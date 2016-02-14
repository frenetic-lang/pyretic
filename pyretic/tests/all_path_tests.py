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

import subprocess, shlex, os
import sys
import argparse

num_passed = 0
num_failed = 0
num_greyed = 0
failed_tests = []
fails_counts = []
greyed_tests = []
greys_counts = []

def parse_args():
    parser = argparse.ArgumentParser(
        description="Run all path query correctness tests.")
    parser.add_argument('--testrun', action="store_true", dest="testrun",
                        help="Run just one sample test to check")
    return parser.parse_args()

def single_path_test(fwding="static_fwding_chain_3_3",
                     query="path_test_0",
                     pyopts='',
                     tshark_filter_funs="filt_path_test_0",
                     topo_name="ChainTopo",
                     topo_args="3,3",
                     results_folder='./pyretic/evaluations/results',
                     success_file='pass-fail.txt',
                     test_nums="0",
                     interface_map="map_chain_3_3",
                     tshark_slack_sec=10,
                     capture_dir="inbound"):

    global fails_counts
    pyoptstr = "--pyopts='" + pyopts + "' " if pyopts else ''
    cmd = ("sudo python pyretic/tests/test_bucket.py " +
           "--ctlr=path_query " +
           "--fwding=" + fwding + ' ' +
           "--query=" + query + ' ' +
           "--topo_name=" + topo_name + ' ' +
           "--topo_args=" + topo_args + ' ' +
           "--tshark_filter_funs=" + tshark_filter_funs + ' ' +
           "--results_folder=" + results_folder + ' ' +
           "--success_file=" + success_file + ' ' +
           "--test_nums=" + test_nums + ' ' +
           "--interface_map=" + interface_map + ' ' +
           pyoptstr +
           "--tshark_slack_sec=" + str(tshark_slack_sec) + ' ' +
           "--capture_dir=" + capture_dir)
    test = subprocess.call(shlex.split(cmd))
    pf_file = os.path.join(results_folder, success_file)
    f = open(pf_file, 'r')
    success_info = f.read().strip()
    f.close()
    """ Remove pass-fail file, for next test. """
    cmd2 = ("rm -f %s" % pf_file)
    subprocess.call(shlex.split(cmd2))
    if 'PASS' not in success_info:
        print "--- Got failure_info: ---"
        print success_info
        fails_counts.append(success_info)
        return "fail"
    elif 'PASS' in success_info and success_info != 'PASS':
        print "--- Got success_info: ---"
        print success_info
        greys_counts.append(success_info)
        return "grey"
    else:
        return "pass"

results_folder = './pyretic/evaluations/results'
success_file = 'pass-fail.txt'

def path_test_0_static_single_stage(default_pyopts, capture_dir):
    """ Path test 0 with static policy, single-stage """
    query = "path_test_0"
    fwding = "static_fwding_chain_3_3"
    pyopts = default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_0_%s' % capture_dir,
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='0', interface_map="map_chain_3_3",
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def path_test_0_5_static_single_stage(default_pyopts, capture_dir):
    """ Path test 0.5 with static policy, single-stage """
    query = "path_test_0_5"
    fwding = "static_fwding_chain_3_3"
    pyopts = default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_0_5_%s' % capture_dir,
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='0.5', interface_map="map_chain_3_3",
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def path_test_2_mac_learner_single_stage(default_pyopts, capture_dir):
    """ Path test 2 with mac learner, single-stage """
    query = "path_test_2"
    fwding = "mac_learner"
    pyopts = default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_2_%s' % capture_dir,
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='2', interface_map="map_chain_3_3",
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def path_test_3_static_single_stage(default_pyopts, capture_dir):
    """ Path test 3 with static policy, single-stage """
    query = "path_test_3"
    fwding = "static_fwding_chain_3_3"
    pyopts = default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_1_%s,filt_path_test_2_%s' % (
            capture_dir, capture_dir),
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='1,2', interface_map="map_chain_3_3",
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def path_test_3_mac_learner_multistage(default_pyopts, capture_dir):
    """ Path test 3 with mac learner, multistage """
    query = "path_test_3"
    fwding = "mac_learner"
    pyopts = "%s --nx --pipeline=path_query_pipeline" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_1_%s,filt_path_test_2_%s' % (
            capture_dir, capture_dir),
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='1,2', interface_map="map_chain_3_3",
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def path_test_3_static_mt_stage(default_pyopts, capture_dir):
    """ Path test 3 with static policy, single-stage """
    query = "path_test_3"
    fwding = "static_fwding_chain_3_3"
    pyopts = "%s --nx --pipeline=mt -b" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_1_%s,filt_path_test_2_%s' % (
            capture_dir, capture_dir),
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='1,2', interface_map="map_chain_3_3",
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def path_test_5_2_static_single_stage_upstream(default_pyopts):
    """ Path test 5.2 upstream with static policy, single stage. """
    query = "path_test_5_2"
    fwding = "static_fwding_chain_3_3"
    pyopts = default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_5_2_inbound_upstream',
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='5.2', interface_map="map_chain_3_3",
        capture_dir='inbound')
    update_test_stats(query, fwding, pyopts, res)

def path_test_5_2_static_multistage_upstream(default_pyopts):
    """ Path test 5.2 upstream with static policy, multistage. """
    query = "path_test_5_2"
    fwding = "static_fwding_chain_3_3"
    pyopts = "%s --nx --pipeline=path_query_pipeline" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_5_2_inbound_upstream',
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='5.2', interface_map="map_chain_3_3",
        capture_dir='inbound')
    update_test_stats(query, fwding, pyopts, res)

def waypoint_violation_spanning_tree_1_multistage(default_pyopts, capture_dir):
    """ Waypoint violation with spanning tree 1, multistage """
    query = "path_test_waypoint_violation_general"
    fwding = "static_fwding_cycle_4_4_spanning_tree_1"
    pyopts = "%s --nx --pipeline=path_query_pipeline" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_gwpv_st1_%s' % capture_dir,
        topo_name="CycleTopo", topo_args="4,4",
        results_folder=results_folder, success_file=success_file,
        test_nums='generalized_waypoint_violation',
        interface_map="map_cycle_4_4", tshark_slack_sec=20,
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def waypoint_violation_spanning_tree_1_mt_stage(default_pyopts, capture_dir):
    """ Waypoint violation with spanning tree 1, multistage """
    query = "path_test_waypoint_violation_general"
    fwding = "static_fwding_cycle_4_4_spanning_tree_1"
    pyopts = "%s --nx --pipeline=mt -b" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_gwpv_st1_%s' % capture_dir,
        topo_name="CycleTopo", topo_args="4,4",
        results_folder=results_folder, success_file=success_file,
        test_nums='generalized_waypoint_violation',
        interface_map="map_cycle_4_4", tshark_slack_sec=20,
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def waypoint_violation_spanning_tree_1_multistage_upstream(default_pyopts):
    """ Waypoint violation upstream with spanning tree 1, multistage """
    query = "path_test_waypoint_violation_general_upstream"
    fwding = "static_fwding_cycle_4_4_spanning_tree_1"
    pyopts = "%s --nx --pipeline=path_query_pipeline" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_gwpv_st1_inbound_upstream',
        topo_name="CycleTopo", topo_args="4,4",
        results_folder=results_folder, success_file=success_file,
        test_nums='generalized_waypoint_violation',
        interface_map="map_cycle_4_4", tshark_slack_sec=20,
        capture_dir='inbound')
    update_test_stats(query, fwding, pyopts, res)

def waypoint_violation_spanning_tree_2_multistage(default_pyopts, capture_dir):
    """ Waypoint violation with spanning tree 2, multistage """
    query = "path_test_waypoint_violation_general"
    fwding = "static_fwding_cycle_4_4_spanning_tree_2"
    pyopts = "%s --nx --pipeline=path_query_pipeline" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_gwpv_st2_%s' % capture_dir,
        topo_name="CycleTopo", topo_args="4,4",
        results_folder=results_folder, success_file=success_file,
        test_nums='generalized_waypoint_violation',
        interface_map="map_cycle_4_4", tshark_slack_sec=20,
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def waypoint_violation_spanning_tree_2_mt_stage(default_pyopts, capture_dir):
    """ Waypoint violation with spanning tree 2, multistage """
    query = "path_test_waypoint_violation_general"
    fwding = "static_fwding_cycle_4_4_spanning_tree_2"
    pyopts = "%s --nx --pipeline=mt -b" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_gwpv_st2_%s' % capture_dir,
        topo_name="CycleTopo", topo_args="4,4",
        results_folder=results_folder, success_file=success_file,
        test_nums='generalized_waypoint_violation',
        interface_map="map_cycle_4_4", tshark_slack_sec=20,
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def waypoint_violation_spanning_tree_2_multistage_upstream(default_pyopts):
    """ Waypoint violation upstream with spanning tree 2, multistage """
    query = "path_test_waypoint_violation_general_upstream"
    fwding = "static_fwding_cycle_4_4_spanning_tree_2"
    pyopts = "%s --nx --pipeline=path_query_pipeline" % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_gwpv_st2_inbound_upstream',
        topo_name="CycleTopo", topo_args="4,4",
        results_folder=results_folder, success_file=success_file,
        test_nums='generalized_waypoint_violation',
        interface_map="map_cycle_4_4", tshark_slack_sec=20,
        capture_dir='inbound')
    update_test_stats(query, fwding, pyopts, res)

def path_test_23_static_single_stage(default_pyopts, capture_dir):
    """ Path test 23 single-stage, static policy """
    query = "path_test_23"
    fwding = "static_fwding_chain_3_3"
    pyopts = default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_23_p1_static_%s,filt_path_test_23_p2_static_%s'
        % (capture_dir, capture_dir),
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='23.p1,23.p2', interface_map="map_chain_3_3",
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def path_test_23_static_multistage(default_pyopts, capture_dir):
    """ Path test 23 multi-stage, static policy """
    query = "path_test_23"
    fwding = "static_fwding_chain_3_3"
    pyopts = '%s --nx --pipeline=path_query_pipeline' % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_23_p1_static_%s,filt_path_test_23_p2_static_%s'
        % (capture_dir, capture_dir),
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='23.p1,23.p2', interface_map="map_chain_3_3",
        capture_dir=capture_dir)
    update_test_stats(query, fwding, pyopts, res)

def path_test_stanford_firewall_multistage(default_pyopts, capture_dir='outbound'):
    """ Stanford topology with firewall query """
    assert capture_dir == 'outbound'
    query = "stanford_firewall"
    fwding = "stanford_shortest_path"
    pyopts = '%s --nx --pipeline=path_query_pipeline' % default_pyopts
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs="filt_stanford_firewall_outbound",
        topo_name="StanfordTopo", topo_args='',
        results_folder=results_folder, success_file=success_file,
        test_nums='stanford_firewall', interface_map="map_stanford_edges",
        capture_dir='outbound', tshark_slack_sec=120)
    update_test_stats(query, fwding, pyopts, res)

def bunched_path_tests(default_pyopts='', capture_dir='outbound'):
    path_test_5_2_static_multistage_upstream(default_pyopts)
    path_test_5_2_static_single_stage_upstream(default_pyopts)
    waypoint_violation_spanning_tree_1_multistage_upstream(default_pyopts)
    waypoint_violation_spanning_tree_2_multistage_upstream(default_pyopts)
    waypoint_violation_spanning_tree_1_multistage(default_pyopts, capture_dir)
    waypoint_violation_spanning_tree_1_mt_stage(default_pyopts, capture_dir)
    waypoint_violation_spanning_tree_2_multistage(default_pyopts, capture_dir)
    waypoint_violation_spanning_tree_2_mt_stage(default_pyopts, capture_dir)
    path_test_23_static_single_stage(default_pyopts, capture_dir)
    path_test_23_static_multistage(default_pyopts, capture_dir)
    path_test_0_static_single_stage(default_pyopts, capture_dir)
    path_test_0_5_static_single_stage(default_pyopts, capture_dir)
    path_test_2_mac_learner_single_stage(default_pyopts, capture_dir)
    path_test_3_static_single_stage(default_pyopts, capture_dir)
    path_test_3_mac_learner_multistage(default_pyopts, capture_dir)
    path_test_3_static_mt_stage(default_pyopts, capture_dir)

def update_test_stats(query, fwding, pyopts, res):
    global num_passed, num_failed, failed_tests, num_greyed, greyed_tests
    test_name = "%s %s with options '%s'" % (query, fwding, pyopts)
    if res == "pass":
        print "===== TEST %s PASSED =====" % test_name
        num_passed += 1
    elif res == "fail":
        print "===== TEST %s FAILED =====" % test_name
        failed_tests.append(test_name)
        num_failed += 1
    elif res == "grey":
        print "===== TEST %s AMBIGUOUS =====" % test_name
        greyed_tests.append(test_name)
        num_greyed += 1
    else:
        raise RuntimeError("single test result uninterpreted")

def print_failed_tests():
    if len(failed_tests) > 0:
        print "Failed tests:"
        assert len(failed_tests) == len(fails_counts)
        for t in range(0, len(failed_tests)):
            print failed_tests[t]
            print fails_counts[t]
    if len(greyed_tests) > 0:
        print "Ambiguous tests:"
        assert len(greyed_tests) == len(greys_counts)
        for t in range(0, len(greyed_tests)):
            print greyed_tests[t]
            print greys_counts[t]

if __name__ == "__main__":
    opts = parse_args()
    if opts.testrun: # just run one test, to sample
        # path_test_0_static_single_stage('', 'outbound')
        path_test_stanford_firewall_multistage(default_pyopts='-r')
    else: # run full suite of tests
        # bunched_path_tests(default_pyopts='')
        bunched_path_tests(default_pyopts='-r')
        bunched_path_tests(default_pyopts='-r --use_pyretic')
        # bunched_path_tests(default_pyopts='--use_pyretic')

    print "===== TESTS COMPLETE ====="
    print "%d tests passed, %d failed, %d ambiguous" % (
        num_passed, num_failed, num_greyed)
    if failed_tests or greyed_tests:
        print_failed_tests()
