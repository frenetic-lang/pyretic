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

def single_bucket_test(fwding, query, filt_funs, topo_name, topo_args,
                       results, pass_fail, test_nums):
    global fails_counts
    cmd = ("sudo python pyretic/tests/test_bucket.py " +
           "--ctlr=bucket " +
           "--fwding=" + fwding + ' ' +
           "--query=" + query + ' ' +
           "--topo_name=" + topo_name + ' ' +
           "--topo_args=" + topo_args + ' ' +
           "--tshark_filter_funs=" + filt_funs + ' ' +
           "--results_folder=" + results + ' ' +
           "--success_file=" + pass_fail + ' ' +
           "--test_nums=" + test_nums)
    test = subprocess.call(shlex.split(cmd))
    pf_file = os.path.join(results, pass_fail)
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

def deprecated_generic_topo_tests(topo_name, topo_args, fwding_pols):
    global num_passed, num_failed, failed_tests
    query_pols  = ['test0', 'test1', 'test2', 'test3', 
                   'test4', 'test5', 'test6', 'test7']
    filt_funs   = ['filt_test0',
                   'filt_test1',
                   'filt_test2_b0,filt_test2_b1',
                   'filt_test3_b0,filt_test3_b1',
                   'filt_test4_b0,filt_test4_b1,filt_test4_b2',
                   'filt_test5',
                   'filt_test6',
                   'filt_test7']
    test_nums   = ['0',
                   '1',
                   '2.b0,2.b1',
                   '3.b0,3.b1',
                   '4.b0,4.b1,4.b2',
                   '5',
                   '6',
                   '7']
    results = './pyretic/evaluations/results'
    pass_fail = 'pass-fail.txt'

    for fwding in fwding_pols:
        for i in range(0, len(query_pols)):
            res = single_bucket_test(fwding, query_pols[i], filt_funs[i],
                                     topo_name, topo_args, results, pass_fail,
                                     test_nums[i])
            test_name = "%s %s on %s" % (query_pols[i], fwding, topo_name)
            if res:
                print "===== TEST %s PASSED =====" % test_name
                num_passed += 1
            else:
                print "===== TEST %s FAILED =====" % test_name
                failed_tests.append(test_name)
                num_failed += 1

def test0(topo_name, topo_args, fwding, results, pass_fail):
    query_pol = 'test0'
    return (query_pol, single_bucket_test(fwding, query_pol, 'filt_test0',
                                          topo_name, topo_args, results,
                                          pass_fail, '0'))

def test1(topo_name, topo_args, fwding, results, pass_fail):
    query_pol = 'test1'
    return (query_pol, single_bucket_test(fwding, query_pol, 'filt_test1',
                                          topo_name, topo_args, results,
                                          pass_fail, '1'))

def test2(topo_name, topo_args, fwding, results, pass_fail):
    query_pol = 'test2'
    return (query_pol, single_bucket_test(fwding, query_pol,
                                          'filt_test2_b0,filt_test2_b1',
                                          topo_name, topo_args, results,
                                          pass_fail, '2.b0,2.b1'))

def test3(topo_name, topo_args, fwding, results, pass_fail):
    query_pol = 'test3'
    return (query_pol, single_bucket_test(fwding, query_pol,
                                          'filt_test3_b0,filt_test3_b1',
                                          topo_name, topo_args, results,
                                          pass_fail, '3.b0,3.b1'))

def test4(topo_name, topo_args, fwding, results, pass_fail):
    query_pol = 'test4'
    return (query_pol, single_bucket_test(fwding, query_pol,
                                          'filt_test4_b0,filt_test4_b1,filt_test4_b2',
                                          topo_name, topo_args, results,
                                          pass_fail, '4.b0,4.b1,4.b2'))

def test5(topo_name, topo_args, fwding, results, pass_fail):
    query_pol = 'test5'
    return (query_pol, single_bucket_test(fwding, query_pol, 'filt_test5',
                                          topo_name, topo_args, results,
                                          pass_fail, '5'))

def test6(topo_name, topo_args, fwding, results, pass_fail):
    query_pol = 'test6'
    return (query_pol, single_bucket_test(fwding, query_pol, 'filt_test6',
                                          topo_name, topo_args, results,
                                          pass_fail, '6'))

def test7(topo_name, topo_args, fwding, results, pass_fail):
    query_pol = 'test7'
    return (query_pol, single_bucket_test(fwding, query_pol, 'filt_test7',
                                          topo_name, topo_args, results,
                                          pass_fail, '7'))

def generic_topo_tests(topo_name, topo_args, fwding_pols):
    global num_passed, num_failed, failed_tests
    results = './pyretic/evaluations/results'
    pass_fail = 'pass-fail.txt'
    test_funs = [test0,
                 test1,
                 test2,
                 test3,
                 test4,
                 test5,
                 test6,
                 test7
    ]

    for fwding in fwding_pols:
        for test_fun in test_funs:
            (query_pol, res) = test_fun(topo_name, topo_args, fwding, results,
                                        pass_fail)
            test_name = "%s %s on %s" % (query_pol, fwding, topo_name)
            if res:
                print "===== TEST %s PASSED =====" % test_name
                num_passed += 1
            else:
                print "===== TEST %s FAILED =====" % test_name
                failed_tests.append(test_name)
                num_failed += 1

def single_switch_topo_tests():
    topo_name   = 'SingleSwitchTopo'
    topo_args   = '3'
    fwding_pols = ['static_fwding_single_3', 'mac_learner']
    generic_topo_tests(topo_name, topo_args, fwding_pols)

def cycle_topo_tests():
    topo_name = 'CycleTopo'
    topo_args = '3,3'
    fwding_pols = ['static_fwding_cycle_3_3', 'mac_learner']
    generic_topo_tests(topo_name, topo_args, fwding_pols)

def print_failed_tests():
    print "Failed tests:"
    assert len(failed_tests) == len(fails_counts)
    for t in range(0, len(failed_tests)):
        print failed_tests[t]
        print fails_counts[t]

if __name__ == "__main__":
    cycle_topo_tests()
    single_switch_topo_tests()

    print "===== TESTS COMPLETE ====="
    print "%d tests passed, %d failed" % (num_passed, num_failed)
    if failed_tests:
        print_failed_tests()
