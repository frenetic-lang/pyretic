
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

# Intended to be used with ./mininet.sh --topo triangle

from frenetic.lib import *

# Static virtualization of the following network:
#                     |1
#  +------------------+---------------------+
#  |                  | 1                   |
#  |              +---+----+                |
#  |              |  s101  |                |
#  |  v1          |        |                |
#  |              /--------+-               |
#  |             / 2         \- 3           |
#  |            /              \-           |
#  |           /                 \- 3       |
#  |          /  2            +----\---+    |
#  |     +---/---+ 3       2  |        |    |
#  |     | s102  |------------| s103   |    |
#  |     |       |            |        |    |
#  |     +---+---+            +----+---+    |
#  |         | 1                   | 1      |
#  +---------+---------------------+--------+
#            | 2                    | 3

vinfo = {1: [1, 2, 3]}

def get_ingress_policy():
    ingress_policy = ((match(switch=1, inport=1)[push(vinport = 1)] | 
                       match(switch=2, inport=1)[push(vinport = 2)] | 
                       match(switch=3, inport=1)[push(vinport = 3)])
                      >> push(vswitch=1))
    return ingress_policy

    
def get_physical_policy():
    physical_policy = (match(switch=1)[ match(voutport=1)[fwd(1)]  | 
                                        match(voutport=2)[fwd(2)]  | 
                                        match(voutport=3)[fwd(3)] ]
                       
                       |  match(switch=2)[ match(voutport=1)[fwd(2)] | 
                                           match(voutport=2)[fwd(1)] | 
                                           match(voutport=3)[fwd(3)] ]
                       
                       |  match(switch=3)[ match(voutport=1)[fwd(3)] | 
                                           match(voutport=2)[fwd(2)] | 
                                           match(voutport=3)[fwd(1)] ]
    return physical_policy

    
def get_egress_policy():
    pred = match(outport=1) & or_(match(switch=1, voutport=1), 
                                  match(switch=2, voutport=2), 
                                  match(switch=3, voutport=3))

    return pred
    
def setup_virtual_network(network):
    vn = VNetwork.fork(network)
    vn.ingress_policy = get_ingress_policy()
    vn.physical_policy = get_physical_policy()
    vn.egress_predicate = get_egress_policy()
    vn.topology.add_node(Switch(1), ports=set(Port(1), Port(2), Port(3)))
    vn.topology.signal_mutation()
    return vn

    
