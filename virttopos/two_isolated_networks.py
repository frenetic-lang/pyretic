
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
    ingress_policy = (((_.switch == Switch(1)) & (_.inport == 1)  & modify(vinport = 1) | 
                       (_.switch == Switch(2)) & (_.inport == 1)  & modify(vinport = 2)) 
                      >> modify(vswitch = Switch(1)))
    return ingress_policy

def get_ingress_policy2():
    ingress_policy = (((_.switch == Switch(3)) & (_.inport == 1)  & modify(vinport = 1) | 
                       (_.switch == Switch(4)) & (_.inport == 1)  & modify(vinport = 2)) 
                      >> modify(vswitch = Switch(2)))
    return ingress_policy

def get_egress_policy1():
    egress_pred = (and_(_.switch == Switch(1), _.voutport == 1) |
                   and_(_.switch == Switch(2), _.voutport == 2) |
                   ~is_port_real(_.voutport))
    return if_(egress_pred, strip_vheaders, passthrough)
    
def get_egress_policy2():
    egress_pred = (and_(_.switch == Switch(3), _.voutport == 1) |
                   and_(_.switch == Switch(4), _.voutport == 2) |
                   ~is_port_real(_.voutport))
    return if_(egress_pred, strip_vheaders, passthrough)

def get_physical_policy1():
    physical_policy = ((_.switch == Switch(1)) & ((_.voutport == 1) & fwd(1) | 
                                                  (_.voutport == 2) & fwd(2)) | 
                       (_.switch == Switch(2)) & ((_.voutport == 1) & fwd(2) | 
                                                  (_.voutport == 2) & fwd(1) ))

    return if_(is_port_real(_.voutport), physical_policy, copy_vheaders)
    
def get_physical_policy2():
    physical_policy = ((_.switch == Switch(3)) & ((_.voutport == 1) & fwd(1) | 
                                                  (_.voutport == 2) & fwd(3)) | 
                       (_.switch == Switch(4)) & ((_.voutport == 1) & fwd(3) | 
                                                  (_.voutport == 2) & fwd(1)))

    return if_(is_port_real(_.voutport), physical_policy, copy_vheaders)
    
def setup_virtual_networks(network):
    vinfo1 = {Switch(1): [Port(1), Port(2)]}
    vinfo2 = {Switch(2): [Port(1), Port(2)]}

    ingress_policy1 = get_ingress_policy1()
    egress_policy1 = get_egress_policy1()
    physical_policy1 = get_physical_policy1()

    ingress_policy2 = get_ingress_policy2()
    egress_policy2 = get_egress_policy2()
    physical_policy2 = get_physical_policy2()

    v_network1 = fork_virtual_network(network, vinfo1, ingress_policy1, physical_policy1 >> egress_policy1)
    v_network2 = fork_virtual_network(network, vinfo2, ingress_policy2, physical_policy2 >> egress_policy2)
    return (v_network1, v_network2)
