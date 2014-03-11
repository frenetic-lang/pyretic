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

################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet: Changes each time. Run evaluation script alongside corresponding    #
# mininet testing script                                                       #
# pyretic: pyretic.py pyretic.evaluations.eval_path -m p0 --test=<test_name>   #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.path import *
from pyretic.lib.query import counts

def query_callback(test_num):
    def actual_callback(pkt):
        print '**************'
        print datetime.now()
        print 'Test', test_num, ' -- got a callback from installed path query!'
        print pkt
        print '**************'
    return actual_callback

## Test: Loop Forwarding
def path_test_loop(**kwargs):
    """Path query that checks for loops in forwarding.
    
    :param n: number of switches in the topology
    :type n: integer
    """
    plist = []
    assert 'n' in kwargs
    n = int(kwargs['n'])
    for s in range(1,n+1):
        p = (atom(match(switch=s)) ^ +(atom(~match(switch=s))) ^
             atom(match(switch=s)))
        p.register_callback(query_callback('loops'))
        plist += [p]
    return plist
    # return []

def loop_fwding(**kwargs):
    """Forwarding policy that creates a loop when packets are sent from h1 to
    hn, and forwards in a single direction around the cycle topology otherwise.
    
    :param n: number of switches and hosts in the (loop) topology
    :type n: integer
    """
    assert 'n' in kwargs
    n = int(kwargs['n'])
    ip_prefix = '10.0.0.'
    h1_ip = IP(ip_prefix + str(1))
    h3_ip = IP(ip_prefix + str(3))
    f = ((match(dstip=h1_ip) >> match(switch=1) >> (~match(srcip=h3_ip)) >>
          fwd(3)) +
         (match(dstip=h1_ip) >> match(switch=1) >> match(srcip=h3_ip) >>
          fwd(2)) + # explicit loop added between h2 --> h1
         (match(dstip=h1_ip) >> (~match(switch=1)) >> fwd(2)))
    for h in range(2,n+1):
        h_ip = IP(ip_prefix + str(h))
        f += (match(dstip=h_ip) >> ((match(switch=h) >> fwd(3)) +
                                    (match(switch=1) >> fwd(1)) +
                                    (((~match(switch=1))&(~match(switch=h))) >>
                                     fwd(2))))
    return f

## Test: Traffic Matrix
def path_test_tm():
    p = []
    n = 5
    for s1 in range(1,n+1):
        for s2 in range(s1+1,n+1):
            p += [atom(ingress_filter() & match(switch=s1)) ^
                  end_path(match(switch=s2))]
    return p

def tm_fwding():
    return mac_learner()

# List of tests, to be used with the --test= parameter.
test_mains = {'loops': loop_fwding,
              'traffic_matrix': tm_fwding }

test_path_mains = {'loops': path_test_loop,
                   'traffic_matrix': path_test_tm }

def test_setup(test_dict, default_test, **kwargs):
    params = dict(**kwargs)
    if 'test' in params:
        testname = params['test']
        return test_dict[testname](**kwargs)
    else:
        return default_test

def path_main(**kwargs):
    return test_setup(test_path_mains, [], **kwargs)

def main(**kwargs):
    return test_setup(test_mains, mac_learner(), **kwargs)

