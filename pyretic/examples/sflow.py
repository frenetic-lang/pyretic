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
# pyretic: pyretic.py pyretic.examples.sflow                                   #
# test:    netblowbucket returns aggregated counts from traffic on the network.#
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.netflow import NetflowBucket

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')

def static_fwding_chain_3_3():
    return (
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

def sf_callback_fn(results):
    print "****** In callback function: got results:"
    for res in results:
        print res
        print '--'
    print "Got", len(results), "results"

def sf_bucket():
    sfb = NetflowBucket(cap_type="sflow")
    sfb.register_callback(sf_callback_fn)
    return sfb

def test0():
    return sf_bucket()

def test1():
    return match(srcip=ip3) >> sf_bucket()

def main(**kwargs):
    return static_fwding_chain_3_3() + test1()
