
################################################################################
# The Frenetic Project                                                         #
# frenetic@frenetic-lang.org                                                   #
################################################################################
# Licensed to the Frenetic Project by one or more contributors. See the        #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Frenetic Project licenses this        #
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

# Intended to be used with ./mininet.sh --topo square

from frenetic.lib import *

#    |    +---+----+   |  |     +---+----+    |
#  --|----|   s1   |------------|   s4   |----|--
#  1 |  1 |        | 3 |  |   2 |        | 1  | 2               
#    |    +----+---+   |  |     +----+---+    |
#    |         | 2     |  |        3 |        |
#    |         | 2     |  |        3 |        |
#    |     +---|---+ 3 |  |  2  +----+---+    |
#    |     |  s2   |------------|   s3   |    |
#    |     |       |   |  |     |        |    |
#    |     +---+---+   |  |     +----+---+    |
#    | v1      | 1     |  | v2       | 1      |
#    +---------+-------+  +----------+--------+
#              | 2                   | 1


def get_ingress_policy1():
    ingress_policy = ((match(switch=1, inport=1) & modify(vinport = 1) | 
                       match(switch=2, inport=1) & modify(vinport = 2)) 
                      >> modify(vswitch = 1))
    return ingress_policy

def get_ingress_policy2():
    ingress_policy = ((match(switch=3, inport=1) & modify(vinport = 1) | 
                       match(switch=4, inport=1) & modify(vinport = 2)) 
                      >> modify(vswitch = 2))
    return ingress_policy

def get_egress_policy1():
    egress_pred = (match(switch=1, voutport=1) |
                   match(switch=2, voutport=2))
    return if_(egress_pred, pop_vheaders)
    
def get_egress_policy2():
    egress_pred = (match(switch=3, voutport=1) |
                   match(switch=4, voutport=2))
    return if_(egress_pred, pop_vheaders)

def get_physical_policy1():
    physical_policy = (match(switch=1) & (match(voutport=1) & fwd(1)
                                          | match(voutport=2) & fwd(2)) 
                      | match(switch=2) & (match(voutport=1) & fwd(2)
                                           | match(voutport=2) & fwd(1)))

    return physical_policy
    
def get_physical_policy2():
    physical_policy = (match(switch=3) & (match(voutport=1) & fwd(1) | 
                                          match(voutport=2) & fwd(3)) | 
                       match(switch=4) & (match(voutport=1) & fwd(3) | 
                                          match(voutport=2) & fwd(1)))

    return physical_policy
    
def setup_virtual_networks(network):
    vinfo1 = {1: [1, 2]}
    vinfo2 = {2: [1, 2]}

    ingress_policy1 = get_ingress_policy1()
    flood_policy1 = flood_splitter(vinfo1)
    egress_policy1 = get_egress_policy1()
    physical_policy1 = get_physical_policy1()

    ingress_policy2 = get_ingress_policy2()
    flood_policy2 = flood_splitter(vinfo2)
    egress_policy2 = get_egress_policy2()
    physical_policy2 = get_physical_policy2()

    v_network1 = fork_virtual_network(network, [(ingress_policy1, physical_policy1 >> egress_policy1, flood_policy1)])
    v_network2 = fork_virtual_network(network, [(ingress_policy2, physical_policy2 >> egress_policy2, flood_policy2)])
    return (v_network1, v_network2)
