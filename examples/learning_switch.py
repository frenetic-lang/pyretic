
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

############################################################################################################################
# TO TEST EXAMPLE                                                                                                          #
# -------------------------------------------------------------------                                                      #
# start mininet:  sudo mn --switch ovsk --controller remote --mac --topo linear,3                                          #
# run controller: pox.py --no-cli pyretic/examples/hub.py                                                                  #
# start xterms:   xterm h1 h2 h3                                                                                           #
# start tcpdump:  in each xterm,                                                                                           #
# > IFACE=`ifconfig | head -n 1 | awk '{print $1}'`; tcpdump -XX -vvv -t -n -i $IFACE not ether proto 0x88cc > $IFACE.dump #
# test:           run h1 ping -c 2 h3, examine tcpdumps and confirm that h2 does not see packets on second go around       #
############################################################################################################################

from frenetic.lib import *

@policy_decorator             # policy_decorater will be applied to learning_switch
def learning_switch(self):    # self : DecoratedPolicy  
    self.policy |= flood      # self.policy initial value is drop
    host_to_outport = {}

    @self.query(all_packets)  # self.query(all_packets) will be applied to f
    def f(pkt):
        outport = host_to_outport.get((pkt['switch'], pkt['srcmac']))
        if outport != pkt['inport']:
            host_to_outport[(pkt['switch'], pkt['srcmac'])] = pkt['inport']
            host_p = match(switch=pkt['switch'], dstmac=pkt['srcmac'])
            
            self.policy -= host_p # Don't do our old action.
            self.policy |= host_p[ fwd(pkt['inport']) ] # Do this instead.
        
main = learning_switch()  # this learning_switch() is NOT the function defined above
                          # it is the name of the DecoratedPolicy produced by applying policy_decorator
                          # to the learning_switch function defined above!   
                          # specifically learning_switch is the DecoratedPolicy and () is the constructor call
                          # on the learning_switch DecoratedPolicy



