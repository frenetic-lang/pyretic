
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


v_switch = Switch(1)
vinfo = {v_switch: [Port(1), Port(2), Port(3)]}

def get_ingress_policy():
    ingress_policy = (((_.switch == Switch(1)) & (_.inport == 1)  & modify(vinport = 1) | 
                       (_.switch == Switch(2)) & (_.inport == 1)  & modify(vinport = 2) | 
                       (_.switch == Switch(3)) & (_.inport == 1)  & modify(vinport = 3))
                      >> modify(vswitch = Switch(1)))
    return ingress_policy

    
def get_physical_policy():
    physical_policy = ((_.switch == Switch(1)) & ((_.voutport == 1) & fwd(1)  | 
                                                  (_.voutport == 2) & fwd(2)  | 
                                                  (_.voutport == 3) & fwd(3))
                       
                       |  (_.switch == Switch(2)) & ((_.voutport == 1) & fwd(2) | 
                                                     (_.voutport == 2) & fwd(1) | 
                                                     (_.voutport == 3) & fwd(3))
                       
                       |  (_.switch == Switch(3)) &  ((_.voutport == 1) & fwd(3) | 
                                                      (_.voutport == 2) & fwd(2) | 
                                                      (_.voutport == 3) & fwd(1)))
    return if_(is_port_real(_.voutport), physical_policy, copy_vheaders)

    
def get_egress_policy():
    pred = _.outport.is_(1) & or_(
        _.switch == 1, _.voutport == 1, 
        _.switch == 2, _.voutport == 2, 
        _.switch == 3, _.voutport == 3)

    pred |= ~is_port_real(_.outport)
    
    return if_(pred, strip_vheaders, passthrough)
    
def setup_virtual_network(network):
    ingress_policy = get_ingress_policy()
    physical_policy = get_physical_policy()
    egress_policy = get_egress_policy()

    v_network = fork_virtual_network(network, vinfo, ingress_policy, physical_policy >> egress_policy)
    return v_network
