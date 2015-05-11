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

num_passed = 0
num_failed = 0
failed_tests = []
fails_counts = []

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
                     tshark_slack_sec=10):

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
           "--tshark_slack_sec=" + str(tshark_slack_sec))
    test = subprocess.call(shlex.split(cmd))
    pf_file = os.path.join(results_folder, success_file)
    f = open(pf_file, 'r')
    success_info = f.read().strip()
    f.close()
    """ Remove pass-fail file, for next test. """
    cmd2 = ("rm -f %s" % pf_file)
    subprocess.call(shlex.split(cmd2))
    if success_info != 'PASS':
        print "--- Got success_info: ---"
        print success_info
        fails_counts.append(success_info)
    return success_info == 'PASS'

def all_path_tests():
    results_folder = './pyretic/evaluations/results'
    success_file = 'pass-fail.txt'

    """ Path test 0 with static policy, single-stage """
    query = "path_test_0"
    fwding = "static_fwding_chain_3_3"
    pyopts = ''
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_0',
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='0', interface_map="map_chain_3_3")
    update_test_stats(query, fwding, pyopts, res)

    """ Path test 0.5 with static policy, single-stage """
    query = "path_test_0_5"
    fwding = "static_fwding_chain_3_3"
    pyopts = ''
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_0_5',
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='0.5', interface_map="map_chain_3_3")
    update_test_stats(query, fwding, pyopts, res)

    """ Path test 2 with mac learner, single-stage """
    query = "path_test_2"
    fwding = "mac_learner"
    pyopts = ''
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_2',
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='2', interface_map="map_chain_3_3")
    update_test_stats(query, fwding, pyopts, res)
    
    """ Path test 3 with static policy, single-stage """
    query = "path_test_3"
    fwding = "static_fwding_chain_3_3"
    pyopts = ''
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_1,filt_path_test_2',
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='1,2', interface_map="map_chain_3_3")
    update_test_stats(query, fwding, pyopts, res)

    """ Path test 3 with mac learner, multistage """
    query = "path_test_3"
    fwding = "mac_learner"
    pyopts = "--nx --pipeline=path_query_pipeline"
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_1,filt_path_test_2',
        topo_name="ChainTopo", topo_args="3,3",
        results_folder=results_folder, success_file=success_file,
        test_nums='1,2', interface_map="map_chain_3_3")
    update_test_stats(query, fwding, pyopts, res)

    """ Waypoint violation with spanning tree 1, multistage """
    query = "path_test_waypoint_violation_general"
    fwding = "static_fwding_cycle_4_4_spanning_tree_1"
    pyopts = "--nx --pipeline=path_query_pipeline"
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_gwpv_st1',
        topo_name="CycleTopo", topo_args="4,4",
        results_folder=results_folder, success_file=success_file,
        test_nums='generalized_waypoint_violation',
        interface_map="map_cycle_4_4", tshark_slack_sec=20)
    update_test_stats(query, fwding, pyopts, res)

    """ Waypoint violation with spanning tree 2, multistage """
    query = "path_test_waypoint_violation_general"
    fwding = "static_fwding_cycle_4_4_spanning_tree_2"
    pyopts = "--nx --pipeline=path_query_pipeline"
    res = single_path_test(
        query=query, fwding=fwding, pyopts=pyopts,
        tshark_filter_funs='filt_path_test_gwpv_st2',
        topo_name="CycleTopo", topo_args="4,4",
        results_folder=results_folder, success_file=success_file,
        test_nums='generalized_waypoint_violation',
        interface_map="map_cycle_4_4", tshark_slack_sec=20)
    update_test_stats(query, fwding, pyopts, res)

def update_test_stats(query, fwding, pyopts, res):
    global num_passed, num_failed, failed_tests
    test_name = "%s %s with options '%s'" % (query, fwding, pyopts)
    if res:
        print "===== TEST %s PASSED =====" % test_name
        num_passed += 1
    else:
        print "===== TEST %s FAILED =====" % test_name
        failed_tests.append(test_name)
        num_failed += 1

def print_failed_tests():
    print "Failed tests:"
    assert len(failed_tests) == len(fails_counts)
    for t in range(0, len(failed_tests)):
        print failed_tests[t]
        print fails_counts[t]

if __name__ == "__main__":
    all_path_tests()

    print "===== TESTS COMPLETE ====="
    print "%d tests passed, %d failed" % (num_passed, num_failed)
    if failed_tests:
        print_failed_tests()
