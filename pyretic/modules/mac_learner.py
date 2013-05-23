
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
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
# mininet:  mininet.sh --topo linear,3 (or other single subnet)                #
# test:     start xterms - e.g., 'xterm h1 h2 h3' in mininet console           #
#           start tcpdump:  in each xterm,                                     #
#           IF=`ifconfig | head -n 1 | awk '{print $1}'`;                      #
#           tcpdump -XX -vvv -t -n -i $IF not ether proto 0x88cc > $IF.dump    #
#           h1 ping -c 2 h3                                                    #
#           examine dumps, confirm that h2 does not see packets on second ping #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *

def learn(self):
    """Standard MAC-learning logic"""

    def update_policy():
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + self.query
    self.update_policy = update_policy

    def learn_new_MAC(pkt):
        """Update forward policy based on newly seen (mac,port)"""
        self.forward = if_(match(dstmac=pkt['srcmac'],
                                switch=pkt['switch']),
                          fwd(pkt['inport']),
                          self.forward) 
        self.update_policy()

    def set_initial_state():
        self.query = packets(1,['srcmac','switch'])
        self.query.register_callback(learn_new_MAC)
        self.forward = flood()
        self.update_policy()

    def set_network(network):
        set_initial_state()
        super(MutablePolicy,self).set_network(network)
       
    self.set_network = set_network
    set_initial_state()


def mac_learner():
    """Create a dynamic policy object from learn()"""
    return dynamic(learn)()

def main():
    return mac_learner()
