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
import re
from mininet.log import setLogLevel
from mininet.topo import *
from pyretic.evaluations.extratopos import *
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from pyretic.evaluations.mininet_setup import mn_cleanup, wait_switch_rules_installed, get_abort_handler, get_adjust_path

def pyretic_controller(ctlr_name, ctlr_params, c_out, c_err, pythonpath):
    c_outfile = open(c_out, 'w')
    c_errfile = open(c_err, 'w')
    # Hackety hack. I don't know of any other way to supply the PYTHONPATH
    # variable for the pyretic controller!
    py_env = os.environ.copy()
    if not "PYTHONPATH" in py_env:
        py_env["PYTHONPATH"] = pythonpath

    cmd = ("pyretic.py -m p0 pyretic.examples." + ctlr_name + ' ' +
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

def capture_packets(t_out, t_err, ints_list, capture_dir):
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
    cmd = ("tshark -f '" + capture_dir + " and net 10.0.0/24' -T fields " +
           "-e frame.len -e ip.src " +
           "-e ip.dst -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 " +
           "-e frame.interface_id " +
           "-E separator=, " +
           reduce(lambda a,i: a + '-i ' + i + ' ', ints_list, ''))
    t = subprocess.Popen(shlex.split(cmd), stdout=t_outfile, stderr=t_errfile)
    return (t, t_outfile, t_errfile)

def workload(net, hosts):
    net.pingAll()

def get_tshark_counts(t_outfile, params, ctlr):
    filter_funs = params['filter_funs'].split(',')
    test_nums   = params['test_nums'].split(',')
    assert len(filter_funs) == len(test_nums)
    tshark_counts = {}

    if ctlr == 'bucket':
        counting_fun = bucket_tshark_filter_count
    elif ctlr == 'path_query':
        counting_fun = path_query_tshark_filter_count
    else:
        raise RuntimeError('unknown controller!')

    for i in range(0, len(filter_funs)):
        bucket_ref = test_nums[i]
        f = filter_funs[i]
        tshark_counts.update([(bucket_ref, counting_fun(t_outfile, f))])
    return tshark_counts

def bucket_tshark_filter_count(t_outfile, filter_fun):
    global ints_map
    t_out = open(t_outfile, 'r')
    pkt_count = 0
    byte_count = 0
    filter_fun = globals()[filter_fun]
    if 'any' not in ints_map:
        bytes_fun = get_bytes
    else:
        bytes_fun = get_bytes_cooked_capture
    for line in t_out:
        if filter_fun(line.strip()):
            pkt_count  += 1
            byte_count += bytes_fun(line)
    return (pkt_count, byte_count)

def get_key_str(line):
    """ This function matches closely with the get_key_str() function in
    path_query.py, since they both generate keys to aggregate the same set of
    packets in different ways -- the latter to group packet counts retrieved
    from query-matched packets, and this one to group packets filtered from
    tshark."""
    global rev_ints_map
    ethtype = 'ip' if __get_ip_srcip(line) != '' else 'arp'
    srcip_fun = __get_ip_srcip if ethtype == 'ip' else __get_arp_srcip
    dstip_fun = __get_ip_dstip if ethtype == 'ip' else __get_arp_dstip
    pred = "int:%s,ethtype:%s,srcip:%s,dstip:%s" % (
        rev_ints_map[__get_interface_id(line)],
        ethtype, srcip_fun(line), dstip_fun(line))
    return pred

def path_query_tshark_filter_count(t_outfile, filter_fun):
    global ints_map
    t_out = open(t_outfile, 'r')
    predwise_count = {}
    filter_fun = globals()[filter_fun]
    if 'any' not in ints_map:
        bytes_fun = get_bytes
    else:
        bytes_fun = get_bytes_cooked_capture
    for line in t_out:
        if filter_fun(line.strip()):
            pred = get_key_str(line)
            (pkt_count, byte_count) = predwise_count.get(pred, (0, 0))
            predwise_count[pred] = (pkt_count + 1, byte_count + bytes_fun(line))
            (pkt_count, byte_count) = predwise_count.get('total', (0, 0))
            predwise_count['total'] = (pkt_count + 1, byte_count + bytes_fun(line))
    return predwise_count

def ctlr_counts(c_outfile, c_name):
    c_out = open(c_outfile, 'r')
    if c_name == 'bucket':
        count_dict = bucket_ctlr_counts(c_out)
    elif c_name == 'path_query':
        count_dict = path_query_ctlr_counts(c_out)
    else:
        raise RuntimeError('unknown controller!')
    c_out.close()
    return count_dict

def __parse_ctlr_count_line__(line):
    parts = line.strip().split()
    bucket_id = parts[1]
    pkt_count  = int(parts[-2][1:-1])
    byte_count = int(parts[-1][:-1])
    inter_str = ' '.join(parts[2:-2])
    return (bucket_id, pkt_count, byte_count, inter_str)

def bucket_ctlr_counts(c_out):
    buckets_counts = {}
    bucket_p = re.compile("Bucket [0-9a-zA-Z._]+ \(packet, byte\) counts: \[[0-9]+, [0-9]+\]")
    for line in c_out:
        if bucket_p.match(line.strip()):
            (bucket_id, pkt_count, byte_count, _) = (
                __parse_ctlr_count_line__(line))
            buckets_counts[bucket_id] = (pkt_count, byte_count)
    return buckets_counts

def path_query_ctlr_counts(c_out):
    buckets_preds_counts = {}
    bucket_p = re.compile("Bucket [0-9a-zA-Z._]+ [0-9a-zA-Z,:._\-]+ counts: \[[0-9]+, [0-9]+\]$")
    for line in c_out:
        if bucket_p.match(line.strip()):
            (bucket_id, pkt_count, byte_count, inter_str) = (
                __parse_ctlr_count_line__(line))
            pred = inter_str.split()[0]
            try:
                buckets_preds_counts[bucket_id][pred] = (pkt_count, byte_count)
            except KeyError:
                buckets_preds_counts[bucket_id] = {}
                buckets_preds_counts[bucket_id][pred] = (pkt_count, byte_count)
    return buckets_preds_counts

def test_bucket_single_test():
    """ Main function for a single test case. """
    args = parse_args()
    test_duration_sec = args.test_duration_sec
    tshark_slack_sec  = args.tshark_slack_sec
    adjust_path = get_adjust_path(args)
    mn_cleanup()

    """ Controller """
    print "Setting up controller..."
    c_params = {'query': args.query, 'fwding': args.fwding,
                'only_count_results': 'true'}
    c_name   = args.ctlr
    c_outfile = adjust_path("pyretic-stdout.txt")
    c_errfile = adjust_path("pyretic-stderr.txt")
    pypath = "/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox"
    (ctlr, c_out, c_err) = pyretic_controller(c_name, c_params, c_outfile,
                                              c_errfile, pypath)

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
    ints_list = globals()[args.interface_map]()
    capture_dir = args.capture_dir
    (tshark, t_out, t_err) = capture_packets(t_outfile, t_errfile, ints_list, capture_dir)
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
    print "Verifying correctness..."
    tshark_filter_params = {'filter_funs': args.tshark_filter_funs,
                            'test_nums': args.test_nums }
    tshark_counts = get_tshark_counts(t_outfile, tshark_filter_params, c_name)
    buckets_counts = ctlr_counts(c_outfile, c_name)
    success_file = adjust_path(args.success_file)
    write_passfail_info(success_file, tshark_counts, buckets_counts, c_name)

#### Helper functions #####

def parse_args():
    parser = argparse.ArgumentParser(description="Run correctness tests for buckets")
    parser.add_argument("-c", "--ctlr", default="bucket",
                        choices=['bucket', 'path_query'],
                        help="Controller to test")
    parser.add_argument("-q", "--query", default="test0",
                        help="Query policy to run")
    parser.add_argument("-f", "--fwding", default="mac_learner",
                        help="Forwarding policy to run")
    parser.add_argument("--topo_name", default="SingleSwitchTopo",
                        help="Topology class to use")
    parser.add_argument("--tshark_filter_funs", default="filt_test0",
                        help="Filter functions to parse tshark output " +
                        "(multiple values can be comma separated")
    parser.add_argument("--test_nums", default="0",
                        help="Test numbers to distinguish controller outputs" +
                        " (multiple values can be comma separated)")
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
                        default=15)
    parser.add_argument("--tshark_slack_sec", type=int,
                        help="Duration to wait for tshark capture to start",
                        default=5)
    parser.add_argument("--success_file", help="File to write test pass/fail",
                        default="pass-fail.txt")
    parser.add_argument("--interface_map", default="map_any",
                        help="Map that defines interfaces to run packet capture")
    parser.add_argument("--capture_dir", default="inbound",
                        choices=['inbound', 'outbound'],
                        help="Direction of packet movement to capture")

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

def write_passfail_info(success_file, tshark_counts, buckets_counts, ctlr):
    if ctlr == 'bucket':
        bucket_write_passfail_info(success_file, tshark_counts, buckets_counts)
    elif ctlr == 'path_query':
        path_query_write_passfail_info(success_file, tshark_counts, buckets_counts)
    else:
        raise RuntimeError('unknown controller!')

def bucket_write_passfail_info(success_file, tshark_counts, buckets_counts):
    passfail = open(success_file, 'w')
    output_str = ''
    if set(tshark_counts.keys()) != set(buckets_counts.keys()):
        output_str += "FAIL\n"
        output_str += "Query references mismatch:\n"
        output_str += "TShark: %s\n" % str(tshark_counts.keys())
        output_str += "Bucket: %s\n" % str(buckets_counts.keys())
    elif True:
        for q in tshark_counts.keys():
            tc = tshark_counts[q]
            bc = buckets_counts[q]
            if tc != bc:
                output_str += "FAIL\n"
                output_str += "Query: %s\n" % q
                output_str += "TShark: %s\n" % str(tc)
                output_str += "Bucket: %s\n" % str(bc)
    if output_str == '':
        output_str += "PASS\n"
    print output_str
    passfail.write(output_str)
    passfail.close()

def path_query_write_passfail_info(success_file, tshark_counts, buckets_counts):
    """ Write pass/fail information summary for this test. This function takes
    the following steps to determine if the output of the path query controller
    is acceptable.
    1. ensure the query references obtained from tshark & buckets are the same.
    For each query reference,
    2. is the total packet count the same?
    3. is the difference between total byte counts bounded?*
    4. is the set of keys generated from tshark & buckets the same?
    For each key of each query reference,
    5. is the packet count the same?
    6. is the difference between byte counts bounded?*

    * TODO(ngsrinivas): some packets show a 4 byte increase in payload size when
      they come into the packet interpreter. This needs more investigation.
    """
    passfail = open(success_file, 'w')
    output_str = ''
    if set(tshark_counts.keys()) != set(buckets_counts.keys()):
        """ Test numbers mismatch. """
        output_str += 'FAIL\n'
        output_str += 'Query references mismatch:\n'
        output_str += 'TShark: %s\n' % str(tshark_counts.keys())
        output_str += 'Bucket: %s\n' % str(buckets_counts.keys())
    elif True:
        """ Per-query-test checks. """
        for q in tshark_counts.keys():
            tc = tshark_counts[q]
            bc = buckets_counts[q]
            (tc_total_pkts, tc_total_bytes) = tc['total']
            (bc_total_pkts, bc_total_bytes) = bc['total']
            if tc_total_pkts != bc_total_pkts:
                output_str += 'FAIL\n'
                output_str += 'Query: %s\n' % q
                output_str += 'Total packet counts mismatch:\n'
                output_str += 'TShark: %d\n' % tc_total_pkts
                output_str += 'Bucket: %d\n' % bc_total_pkts
                break
            elif abs(tc_total_bytes-bc_total_bytes) > 4*tc_total_pkts:
                output_str += 'FAIL\n'
                output_str += 'Query: %s\n' % q
                output_str += 'Total byte count mismatch out of bounds:\n'
                output_str += 'TShark: %d\n' % tc_total_bytes
                output_str += 'Bucket: %d\n' % bc_total_bytes
                break
            elif set(tc.keys()) != set(bc.keys()):
                output_str += 'FAIL\n'
                output_str += 'Query: %s\n' % q
                output_str += 'Groups of packets counted differ:\n'
                output_str += 'TShark:\n%s\n' % ('\n'.join(tc.keys()))
                output_str += 'Bucket:\n%s\n' % ('\n'.join(bc.keys()))
                break
            elif True:
                for pred in tc.keys():
                    """ Check each predicate within each query. """
                    (tc_pred_pkts, tc_pred_bytes) = tc[pred]
                    (bc_pred_pkts, bc_pred_bytes) = bc[pred]
                    if tc_pred_pkts != bc_pred_pkts:
                        output_str += 'FAIL\n'
                        output_str += 'Query: %s\n' % q
                        output_str += 'Predicate pkt counts mismatch:\n'
                        output_str += 'Predicate: %s\n' % pred
                        output_str += 'TShark: %d\n' % tc_pred_pkts
                        output_str += 'Bucket: %d\n' % bc_pred_pkts
                        break
                    elif abs(tc_pred_bytes-bc_pred_bytes) > 4*tc_pred_pkts:
                        output_str += 'FAIL\n'
                        output_str += 'Query: %s\n' % q
                        output_str += 'Predicate byte count mismatch out of bounds:\n'
                        output_str += 'Predicate: %s\n' % pred
                        output_str += 'TShark: %d\n' % tc_pred_bytes
                        output_str += 'Bucket: %d\n' % bc_pred_bytes
                        break
    if output_str == '':
        output_str += 'PASS\n'
    print output_str
    passfail.write(output_str)
    passfail.close()

### Helpers to extract specific headers from tshark output ###
ints_map = {}
rev_ints_map = {}

def __get_frame_len(line):
    return line.split(',')[0]

def __get_ip_srcip(line):
    return line.split(',')[1]

def __get_ip_dstip(line):
    return line.split(',')[2]

def __get_arp_srcip(line):
    return line.split(',')[3]

def __get_arp_dstip(line):
    return line.split(',')[4]

def __get_interface_id(line):
    return int(line.split(',')[5])

def get_bytes(l):
    return int(__get_frame_len(l))

def get_bytes_cooked_capture(l):
    return int(__get_frame_len(l))-2

def ip_pkt_srcip(target_ip, l):
    return __get_ip_srcip(l) == target_ip

def ip_pkt_dstip(target_ip, l):
    return __get_ip_dstip(l) == target_ip

def arp_pkt_srcip(target_ip, l):
    return __get_arp_srcip(l) == target_ip

def arp_pkt_dstip(target_ip, l):
    return __get_arp_dstip(l) == target_ip

def pkt_srcip(target_ip, l):
    return ((__get_ip_srcip(l) == target_ip) or
            (__get_arp_srcip(l) == target_ip))

def pkt_dstip(target_ip, l):
    return ((__get_ip_dstip(l) == target_ip) or
            (__get_arp_dstip(l) == target_ip))

def pkt_interface(int_name, l):
    global ints_map
    return __get_interface_id(l) == ints_map[int_name]

### Filter functions to parse tshark output for various test cases ###
ip1 = '10.0.0.1'
ip2 = '10.0.0.2'
ip3 = '10.0.0.3'

## Bucket test cases.
def filt_test0(l):
    return True

def filt_test1(l):
    return pkt_srcip(ip1, l)

def filt_test2_b0(l):
    return ip_pkt_srcip(ip1, l) or ip_pkt_srcip(ip3, l)

def filt_test2_b1(l):
    return ip_pkt_srcip(ip2, l)

def filt_test3_b0(l):
    return pkt_srcip(ip1, l) or pkt_srcip(ip3, l)

def filt_test3_b1(l):
    return pkt_srcip(ip2, l)

def filt_test4_b0(l):
    return pkt_srcip(ip1, l) and pkt_dstip(ip2, l)

def filt_test4_b1(l):
    return pkt_srcip(ip1, l) and pkt_dstip(ip2, l)

def filt_test4_b2(l):
    return pkt_srcip(ip1, l) and pkt_dstip(ip3, l)

def filt_test5(l):
    return (
        ((not pkt_srcip(ip1, l)) and pkt_dstip(ip2, l)) or
        ((not pkt_srcip(ip1, l)) and pkt_dstip(ip3, l)) or
        ((not pkt_srcip(ip1, l)) and pkt_dstip(ip1, l)))

def filt_test6(l):
    return not pkt_srcip(ip1, l)

def filt_test7(l):
    return pkt_srcip(ip1, l)

## Path Query test cases
def filt_path_test_0(l):
    return pkt_interface('s2-eth3', l)

def filt_path_test_0_5(l):
    return (pkt_srcip(ip2, l) or
            (pkt_srcip(ip1, l) and not pkt_interface('s1-eth2', l)) or
            (pkt_srcip(ip3, l) and not pkt_interface('s3-eth2', l)))

### Interfaces map for packet capture ###
def map_any():
    global ints_map, rev_ints_map
    ints_map = {'any': 0}
    rev_ints_map = {0: 'any'}
    return ["any"]

def map_chain_3_3():
    global ints_map, rev_ints_map
    ints_list = ["s1-eth1", "s1-eth2", "s2-eth1", "s2-eth2",
                 "s2-eth3", "s3-eth1", "s3-eth2"]
    ints_map  = {i: ints_list.index(i) for i in ints_list}
    rev_ints_map = {j: ints_list[j] for j in range(0, len(ints_list))}
    return ints_list

### The main thread.
if __name__ == "__main__":
    setLogLevel('info')
    test_bucket_single_test()

