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
# mininet: mininet.sh --topo=chain,3,3                                         #
# pyretic: pyretic.py pyretic.examples.path_query -m p0                        #
# test:    h1 ping h3 should produce packets at the controller from s3.        #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.path import *
from pyretic.lib.query import counts
import threading

import time
from datetime import datetime

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')

static_fwding_chain_2_2 = (
    (match(dstip=ip1) >> ((match(switch=1) >> fwd(2)) +
                          (match(switch=2) >> fwd(1)))) +
    (match(dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                          (match(switch=2) >> fwd(2))))
    )

static_fwding_chain_3_3 = (
    (match(dstip=ip1) >> ((match(switch=1) >> fwd(2)) +
                          (match(switch=2) >> fwd(1)) +
                          (match(switch=3) >> fwd(1)))) +
    (match(dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                          (match(switch=2) >> fwd(3)) +
                          (match(switch=3) >> fwd(1)))) +
    (match(dstip=ip3) >> ((match(switch=1) >> fwd(1)) +
                          (match(switch=2) >> fwd(2)) +
                          (match(switch=3) >> fwd(2))))
    )

def query_func(bucket, interval):
    while True:
        output = str(datetime.now())
        output += " Pulling stats for bucket " + repr(bucket)
        # output += bucket.get_matches()
        print output
        bucket.pull_stats()
        time.sleep(interval)

def query_callback(test_num):
    def actual_callback(pkt):
        print '**************'
        print datetime.now()
        print 'Test', test_num, ' -- got a callback from installed path query!'
        print pkt
        print '**************'
    return actual_callback

def path_callback(test_num):
    def actual_callback(pkt, paths):
        print '**************'
        print datetime.now()
        print 'Test', test_num, ' -- got a callback from installed path query!'
        print pkt
        print 'Got', len(paths), 'path(s) from the callback.'
        path_index = 1
        for path in paths:
            print '-----'
            print 'Printing path', path_index
            path_index += 1
            for p in path:
                print p
            print '-----'
        print '**************'
    return actual_callback

def path_test_1():
    a1 = atom(match(switch=1,srcip=ip1))
    a2 = atom(match(switch=3,dstip=ip3))
    p = a1 ** a2
    p.register_callback(query_callback(1))
    return [p]

def path_test_2():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=3))
    p = a1 ** a2
    p.register_callback(query_callback(2))
    return [p]

def path_test_3():
    return path_test_2() + path_test_1()

def path_test_4():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=3))
    p = a1 ^ a2
    cb = CountBucket()
    p.set_bucket(cb)
    p.register_callback(query_callback(4))
    query_thread = threading.Thread(target=query_func, args=(cb,2.5))
    query_thread.daemon = True
    query_thread.start()
    return [p]

def path_test_5():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=3))
    p = (a1 ^ a2)  | (a2 ^ a1)
    p.register_callback(query_callback(5))
    return [p]

def path_test_6():
    p = +atom(identity)
    p.register_callback(query_callback(6))
    return [p]

def path_test_7():
    p = atom(match(switch=1)) ^ +atom(identity)
    p.register_callback(query_callback(7))
    return [p]

def path_test_8():
    p = atom(ingress_network())
    p.register_callback(query_callback(8))
    return [p]

def path_test_9():
    p = atom(match(srcip=ip1)) ^ end_path(identity)
    p.register_callback(query_callback(9))
    return [p]

def path_test_10():
    """ TODO(ngsrinivas): Defunct test as of now -- drop atoms are not stitched
    into the main policy.
    """
    p = atom(match(srcip=ip1)) ^ drop_atom(identity)
    p.register_callback(query_callback(10))
    return [p]

def path_test_11():
    p = end_path(identity)
    p.register_callback(query_callback(11))
    return [p]

def path_test_12():
    p = atom(match(switch=1))
    pb = PathBucket()
    p.set_bucket(pb)
    p.register_callback(path_callback(12))
    return [p]

def path_test_13():
    p = (atom(match(switch=1)) ^ atom(match(switch=2)) ^ atom(match(switch=3)))
    p.register_callback(query_callback(13))
    return [p]

def path_test_14():
    p = (atom(match(switch=1)) ^ hook(match(switch=2), ['inport']) ^
         atom(match(switch=3)))
    p.register_callback(query_callback(14))
    return [p]

def path_test_15():
    p = (atom(match(switch=1)) ^ hook(match(switch=2), ['inport']) ^
         hook(match(switch=3), ['srcip','dstip']))
    p.register_callback(query_callback(15))
    return [p]

def path_test_16():
    return path_test_13() + path_test_14() + path_test_15()

# type: unit -> path list
def path_main():
    return path_test_3()

def main():
#    return mac_learner()
    return static_fwding_chain_3_3
