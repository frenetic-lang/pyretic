################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################

""" A simpler, cleaner end to end testing script. """

import argparse
import os
import subprocess, shlex
import signal
import time
import importlib

from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from pyretic.evaluations.mininet_setup import (mn_cleanup,
                                               wait_switch_rules_installed,
                                               get_abort_handler,
                                               get_adjust_path)
from pyretic.evaluations.old_eval_scripts.sweep import create_folder_if_not_exists

""" Constant definitions """
TEST_DURATION_SEC=30
TSHARK_SLACK_SEC=10
INSTALL_TIMEOUT_SEC=30
OVS_START_LISTEN_PORT=6634
SUCCESS_FILE="pass-fail.txt"
TEST_MODULE_BASE="pyretic.evaluations.Tests"
PYRETIC_STDOUT="pyretic-stdout.txt"
PYRETIC_STDERR="pyretic-stderr.txt"
OVHEAD_TRAFFIC="overhead-traffic.txt"
OPTIMAL_TRAFFIC="optimal-traffic.txt"
TOTAL_BW_BIT_PS=180000
IPERF_SERVER_PREFIX="server-udp"
IPERF_CLIENT_PREFIX="client-udp"
IPERF_MIN=500 * 8
TSHARK_INTFS_COUNT=5

def parse_args():
    parser = argparse.ArgumentParser(
        description="Run end to end overhead tests with path queries.")
    parser.add_argument("--pyopts", default='',
                        help="Options to pyretic.py")
    parser.add_argument("-r", "--results_folder",
                        default="./pyretic/evaluations/results/",
                        help="Folder to put the raw results data into")
    parser.add_argument("--test", default="e2e_stanford", required=True,
                        help="Name of test module to run")
    parser.add_argument("--polopts", nargs="+", 
                        help="Options for the test module")
    return parser.parse_args()

def get_test_module(test):
    test_module = importlib.import_module("%s.%s.policy" % (TEST_MODULE_BASE,
                                                            test))
    return test_module

def get_testwise_params(polopts):
    params = {}
    if polopts:
        arg_iter = iter(polopts)
        for arg in arg_iter:
            val = next(arg_iter)
            params[arg] = val
    return params

def get_controller(rfolder, pyopts, test, polopts):
    c_outfile = open("%s/%s" % (rfolder, PYRETIC_STDOUT), 'w')
    c_errfile = open("%s/%s" % (rfolder, PYRETIC_STDERR), 'w')
    py_env = os.environ.copy()
    usern = subprocess.call('./pyretic/tests/get_user.sh')
    pypath = "/home/%s/pyretic:/home/%s/mininet:/home/%s/pox" % ((usern,)*3)
    if not "PYTHONPATH" in py_env:
        py_env["PYTHONPATH"] = pypath
    cmd = ("python pyretic.py -m p0 " + pyopts + ' ' +
           "pyretic.evaluations.eval_path " +
           reduce(lambda r, k: r + ("--" + k + "=" + polopts[k] + " "),
                  polopts.keys(), " "))
    print "Running controller command line:\n`%s`" % cmd
    c = subprocess.Popen(shlex.split(cmd), stdout=c_outfile, stderr=c_errfile,
                         env=py_env)
    return (c, c_outfile, c_errfile)

def get_mininet(test_module, polopts):
    net=Mininet(topo=test_module.topo_setup(**polopts),
                host=CPULimitedHost, controller=RemoteController,
                listenPort=OVS_START_LISTEN_PORT)
    net.start()
    return (net, net.hosts, net.switches)

def get_tshark_ovhead(test_module, polopts, rfolder):
    ovhead_filter = test_module.ovhead_filter_setup(**polopts)
    ovhead_file = open("%s/%s" % (rfolder, OVHEAD_TRAFFIC), 'w')
    cmd = ("tshark -q -i lo -z io,stat,0,'%s' "
           "-f 'tcp port 6633' -a duration:%d" % (
               ovhead_filter, TEST_DURATION_SEC+2*TSHARK_SLACK_SEC))
    print "Running tshark command", cmd
    p = subprocess.Popen(shlex.split(cmd), stdout=ovhead_file,
                         stderr=subprocess.STDOUT)
    return (p, ovhead_file)

def get_tshark_optimal(test_module, polopts, rfolder):
    intfs_capfs = test_module.optimal_filter_setup(**polopts)
    cap_strs = []
    cnt = 0
    ''' Group all interface captures into TSHARK_INTFS_COUNT interfaces '''
    for (intf, capf) in intfs_capfs:
        if cnt == 0:
            cap_strs.append('')
        cnt = 0 if cnt == TSHARK_INTFS_COUNT-1 else cnt+1
        cap_strs[-1] += ("-i %s -f '%s' " % (intf, capf))
    cnt = 0
    ''' Instantiate tsharks '''
    procs, opt_files = [], []
    for cap_str in cap_strs:
        opt_file = open("%s/%s-%d.txt" % (rfolder, OPTIMAL_TRAFFIC, cnt), 'w')
        cnt += 1
        cmd = ("tshark -q -z io,stat,0 %s -a duration:%d" % (
            cap_str, TEST_DURATION_SEC+3))
        print "Running tshark command", cmd
        p = subprocess.Popen(shlex.split(cmd), stdout=opt_file,
                             stderr=subprocess.STDOUT)
        procs.append(p)
        opt_files.append(opt_file)
    return (procs, opt_files)

def run_iperf_test(test_module, polopts, rfolder, net):
    (srcs, dsts, bws) = test_module.workload_setup(TOTAL_BW_BIT_PS, net, **polopts)
    ''' start servers '''
    for dst in dsts:
        dst.cmd("iperf -fK -u -s -p 5002 2>&1 > %s/%s-%s.txt &" %
                (rfolder, IPERF_SERVER_PREFIX, dst.name))
    ''' start clients '''
    for i in range(0, len(srcs)):
        if bws[i] >= IPERF_MIN:
            srcs[i].cmd("iperf -fK -t %d -c %s -u -p 5002 -b %s 2>&1 > %s/%s-%s-%s.txt &"
                        % (TEST_DURATION_SEC, dsts[i].IP(), bws[i],
                           rfolder, IPERF_CLIENT_PREFIX, srcs[i].name,
                           dsts[i].name))
        else:
            print ("Avoiding transfer %s ---> %s because target bandwidth is too"
                   " low" % (srcs[i].name, dsts[i].name))

def kill_processes(plist):
    for p in plist:
        p.send_signal(signal.SIGINT)

def close_fds(fds):
    for fd in fds:
        fd.close()

def query_test():
    """ A simpler, cleaner, end to end testing script. """
    args = parse_args()
    rfolder = args.results_folder
    create_folder_if_not_exists(rfolder)
    pyopts = args.pyopts
    test = args.test
    test_module = get_test_module(test)
    polopts = get_testwise_params(args.polopts)
    polopts['test'] = test
    polopts['pyopts'] = pyopts

    mn_cleanup()
    (ctlr, c_out, c_err) = get_controller(rfolder, pyopts, test, polopts)
    test_module.init_setup(**polopts)
    (net, hosts, switches) = get_mininet(test_module, polopts)
    (rules_installed) = wait_switch_rules_installed(switches, INSTALL_TIMEOUT_SEC)
    # net.pingAll()
    (ovhp, ovhf) = get_tshark_ovhead(test_module, polopts, rfolder)
    time.sleep(TSHARK_SLACK_SEC)
    (optps, optfs) = get_tshark_optimal(test_module, polopts, rfolder)
    # optps, optfs = [], []
    time.sleep(TSHARK_SLACK_SEC)
    run_iperf_test(test_module, polopts, rfolder, net)
    time.sleep(TEST_DURATION_SEC + 2*TSHARK_SLACK_SEC)
    kill_processes([ctlr, ovhp] + optps)
    close_fds([c_out, c_err, ovhf] + optfs)

    net.stop()

    print "Done!"

if __name__ == "__main__":
    query_test()
