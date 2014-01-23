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

import time
from datetime import datetime

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')

static_fwding_chain_2_2 = (
    (match(srcip=ip1, dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                                     (match(switch=2) >> fwd(2)))) +
    (match(srcip=ip2, dstip=ip1) >> ((match(switch=1) >> fwd(2)) +
                                     (match(switch=2) >> fwd(1)))))

def query_callback(test_num):
    def actual_callback(pkt):
        print '**************'
        print 'Test', test_num, ' -- got a packet satisfying path query!'
        print pkt
        print '**************'
    return actual_callback

def path_test_1():
    a1 = atom(match(switch=1,srcip=ip1))
    a2 = atom(match(switch=3,dstip=ip3))
    p = a1 ^ a2
    p.register_callback(query_callback(1))
    return [p]

def path_test_2():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=3))
    p = a1 ^ a2
    p.register_callback(query_callback(2))
    return [p]

def path_test_3():
    return path_test_1() + path_test_2()

def path_test_4():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=3))
    p = a1 ^ a2
    p.bucket_instance = counts(interval=5)
    p.register_callback(query_callback(4))
    return [p]

# type: unit -> path list
def path_main():
    return path_test_4()

def main():
    return mac_learner()
