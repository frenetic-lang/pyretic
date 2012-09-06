
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

from frenetic.lib import *
from examples.monitor import monitor
    

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
#  |           /                 \- 2       |
#  |          /  3            +----\---+    |
#  |     +---/---+ 2       3  |        |    |
#  |     | s102  |------------| s103   |    |
#  |     |       |            |        |    |
#  |     +---+---+            +----+---+    |
#  |         | 1                   | 1      |
#  +---------+---------------------+--------+
#            | 2                    | 3
                      
def virtual_monitor(network):

    # SIGNATURE
    v_signature = {v1:[1, 2, 3]}

    # IMPLEMENTATION
    ingress_policy = ((_.switch == 's101' & _.inport == 1 ) & modify(vsrcport = 1) | \
                          (_.switch == 's102' & _.inport == 1) & modify(vsrcport = 2) | \
                          (_.switch == 's103' & _.inport == 1) & modify(vsrcport = 3)) \
                          >> modify(vswitch = 'v1')
    internal_policy = (_.switch == 's101' & (_.vdstport == 1 & fwd(1)  | \
                                            _.vdstport == 2 & fwd(2)  | \
                                            _.vdstport == 3 & fwd(3)) | \
                      _.switch == 's102' & (_.vdstport == 1 & fwd(3) | \
                                            _.vdstport == 2 & fwd(1) | \
                                            _.vdstport == 3 & fwd(2)) | \
                      _.switch == 's103' & (_.vdstport == 1 & fwd(2) | \
                                            _.vdstport == 2 & fwd(3) | \
                                            _.vdstport == 3 & fwd(1)))
    
    run(monitor, fork_virtual_network(network, v_signature, ingress_policy, internal_policy)

    ## ALTERNATE, MORE EXPLICIT VERSION
    # v_n = Network()
    # run(monitor, v_n)
    # network.install_sub_policies(
    #    virtualize_policy(v_signature, ingress_policy, internal_policy, pol) 
    #    for pol in v_n.policy_changes())

start(virtual_monitor)
