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

def single_test(fwding, query, filt_funs, topo_name, topo_args,
                       results, pass_fail):
    cmd = ("sudo python pyretic/tests/test_bucket.py " +
           "--fwding=" + fwding + ' ' +
           "--query=" + query + ' ' +
           "--topo_name=" + topo_name + ' ' +
           "--topo_args=" + topo_args + ' ' +
           "--tshark_filter_funs=" + filt_funs + ' ' +
           "--results_folder=" + results + ' ' +
           "--success_file=" + pass_fail)
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
    return success_info == 'PASS'

def all_tests():
    fwding_pols = ['static_fwding', 'mac_learner']
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
    topo_name   = 'SingleSwitchTopo'
    topo_args   = '3'
    results = './pyretic/evaluations/results'
    pass_fail = 'pass-fail.txt'
    num_passed = 0
    num_failed = 0
    
    for fwding in fwding_pols:
        for i in range(0, len(query_pols)):
            res = single_test(fwding, query_pols[i], filt_funs[i],
                              topo_name, topo_args, results, pass_fail)
            test_name = "%s %s" % (query_pols[i], fwding)
            if res:
                print "===== TEST %s PASSED =====" % test_name
                num_passed += 1
            else:
                print "===== TEST %s FAILED =====" % test_name
                num_failed += 1
    print "===== TESTS COMPLETE ====="
    print "%d tests passed, %d failed" % (num_passed, num_failed)

if __name__ == "__main__":
    all_tests()
