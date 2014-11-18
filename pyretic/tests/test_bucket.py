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

import argparse
import os
import subprocess, shlex
import signal
import time
from pyretic.tests.tshark_filter import *
from mininet.log import setLogLevel
from mininet.topo import *
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from pyretic.evaluations.mininet_setup import mn_cleanup, wait_switch_rules_installed, get_abort_handler, get_adjust_path

def pyretic_controller(ctlr_params, c_out, c_err, pythonpath):
    c_outfile = open(c_out, 'w')
    c_errfile = open(c_err, 'w')
    # Hackety hack. I don't know of any other way to supply the PYTHONPATH
    # variable for the pyretic controller!
    py_env = os.environ.copy()
    if not "PYTHONPATH" in py_env:
        py_env["PYTHONPATH"] = pythonpath

    cmd = ("pyretic.py -m p0 pyretic.examples.bucket " +
           reduce(lambda r, k: r + ("--" + k + "=" + ctlr_params[k] + " "),
                  ctlr_params.keys(), " "))
    c = subprocess.Popen(shlex.split(cmd), stdout=c_outfile, stderr=c_errfile,
                         env=py_env)
    return (c, c_outfile, c_errfile)

def get_mininet(topo_args, listen_port):
    """ Get a mininet network from topology arguments. """
    class_args = map(int, topo_args['class_args'].split(','))
    class_name = topo_args['class_name']
    topo = globals()[class_name](*class_args)
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=listen_port)
    net.start()
    return (net, net.hosts, net.switches)

def capture_packets(t_out, t_err):
    t_outfile = open(t_out, 'w')
    t_errfile = open(t_err, 'w')
    """ tshark command below prints the following specific fields only for
    mininet packets:
    - frame length
    - ip src for IP packets
    - ip dst for IP packets
    - ip src for ARP packets
    - ip dst for ARP packets
    If more fields are needed, the command needs to be modified accordingly.
    """
    cmd = ("tshark -i any -f 'inbound and net 10.0.0/24' -T fields " +
           "-e frame.len -e ip.src " +
           "-e ip.dst -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 " +
           "-E separator=,")
    t = subprocess.Popen(shlex.split(cmd), stdout=t_outfile, stderr=t_errfile)
    return (t, t_outfile, t_errfile)

def workload(net, hosts):
    net.pingAll()

def tshark_filter_count(t_outfile, tshark_filter_fun):
    t_out = open(t_outfile, 'r')
    pkt_count = 0
    byte_count = 0
    filter_fun = globals()[tshark_filter_fun]
    for line in t_out:
        if filter_fun(line):
            pkt_count  += 1
            byte_count += get_bytes_cooked_capture(line)
    return [pkt_count, byte_count]

def test_bucket_single_test():
    """ Main function for a single test case. """
    args = parse_args()
    test_duration_sec = args.test_duration_sec
    tshark_slack_sec  = args.tshark_slack_sec
    adjust_path = get_adjust_path(args)
    mn_cleanup()

    """ Controller """
    print "Setting up controller..."
    c_params = {'query': args.query, 'fwding': args.fwding}
    c_outfile = adjust_path("pyretic-stdout.txt")
    c_errfile = adjust_path("pyretic-stderr.txt")
    pypath = "/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox"
    (ctlr, c_out, c_err) = pyretic_controller(c_params, c_outfile, c_errfile,
                                              pypath)

    """ Network """
    print "Setting up mininet..."
    topo_args = {'class_name': args.topo_name, 'class_args': args.topo_args}
    (net, hosts, switches) = get_mininet(topo_args, args.listen_port)

    """ Wait for switches to be prepped """
    print "Waiting to install switch rules..."
    wait_switch_rules_installed(switches)

    """ Capture """
    print "Starting tshark capture..."
    t_outfile = adjust_path("tshark-stdout.txt")
    t_errfile = adjust_path("tshark-stderr.txt")
    (tshark, t_out, t_err) = capture_packets(t_outfile, t_errfile)
    time.sleep(tshark_slack_sec)

    """ Workload """
    print "Starting workload..."
    workload(net, hosts)
    time.sleep(test_duration_sec)

    """ Finish up """
    print "Actual run done. Cleaning up..."
    kill_process(ctlr, "controller")
    kill_process(tshark, "tshark")
    close_fds([c_out, c_err], "controller")
    close_fds([t_out, t_err], "tshark")
    net.stop()

    """ Verify results """
    [pkts, bytes] = tshark_filter_count(t_outfile, args.tshark_filter_fun)
    print "Got tshark counts:", pkts, "packets,", bytes, "bytes"

#### Helper functions #####

def parse_args():
    parser = argparse.ArgumentParser(description="Run correctness tests for buckets")
    parser.add_argument("-q", "--query", default="test0",
                        help="Query policy to run")
    parser.add_argument("-f", "--fwding", default="mac_learner",
                        help="Forwarding policy to run")
    parser.add_argument("--topo_name", default="SingleSwitchTopo",
                        help="Topology class to use")
    parser.add_argument("--tshark_filter_fun", default="filt_test0",
                        help="Filter function to parse tshark output")
    parser.add_argument("--topo_args", default="3",
                        help="Arguments to the topology class constructor " +
                        "(separated by commas)")
    parser.add_argument("-l", "--listen_port", default=6634, type=int,
                        help="Starting port for OVS switches to listen on")
    parser.add_argument("-r", "--results_folder",
                        default="./pyretic/evaluations/results/",
                        help="Folder to put the raw results data into")
    parser.add_argument("--test_duration_sec", type=int,
                        help="Duration before workload finishes execution",
                        default=30)
    parser.add_argument("--tshark_slack_sec", type=int,
                        help="Duration to wait for tshark capture to start",
                        default=5)
    args = parser.parse_args()
    return args

def kill_process(p, process_str):
    """ Kill a process """
    print "Signaling", process_str, "for completion"
    p.send_signal(signal.SIGINT)

def close_fds(fds, fd_str):
    """ Close a bunch of file descriptors """
    for fd in fds:
        fd.close()
    print "Closed", fd_str, "file descriptors"

### Filter functions to parse tshark output for various test cases ###
ip1 = '10.0.0.1'
ip2 = '10.0.0.2'
ip3 = '10.0.0.3'

def filt_test0(l):
    return True

def filt_test1(l):
    return pkt_srcip(ip1)(l)

def filt_test2_b0(l):
    return ip_pkt_srcip(ip1)(l) or ip_pkt_srcip(ip3)(l)

def filt_test2_b1(l):
    return ip_pkt_srcip(ip2)(l)

def filt_test3_b0(l):
    return pkt_srcip(ip1)(l) or pkt_srcip(ip3)(l)

def filt_test3_b1(l):
    return pkt_srcip(ip2)(l)

def filt_test4_b0(l):
    return pkt_srcip(ip1)(l) and pkt_dstip(ip2)(l)

def filt_test4_b1(l):
    return pkt_srcip(ip1)(l) and pkt_dstip(ip2)(l)

def filt_test4_b2(l):
    return pkt_srcip(ip1)(l) and pkt_dstip(ip3)(l)

def filt_test5(l):
    return (
        ((not pkt_srcip(ip1)(l)) and pkt_dstip(ip2)(l)) or
        ((not pkt_srcip(ip1)(l)) and pkt_dstip(ip3)(l)) or
        ((not pkt_srcip(ip1)(l)) and pkt_dstip(ip1)(l)))

def filt_test6(l):
    return not pkt_srcip(ip1)(l)

def filt_test7(l):
    return pkt_srcip(ip1)(l)

### The main thread.
if __name__ == "__main__":
    setLogLevel('info')
    test_bucket_single_test()

