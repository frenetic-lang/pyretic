################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Michael Greenberg (mg19@cs.princeton.edu)                            #
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
# mininet:  mininet.sh                                                         #
# test: pingall # everything should work                                       #
#       h2 python -m SimpleHTTPServer 80 &                                     #
#       h2 wget -O - h2 # should work                                          #
#       h1 wget -O - -t 1 --timeout=2 h2 # should timeout                      #
#       h1 echo open sesame | nc -w 1 -u h2 1234                               #
#       h1 wget -O - h2 # should work                                          #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

class port_knocking(DynamicPolicy):
    def __init__(self,knock_port,open_port):
        super(port_knocking,self).__init__()
        self.knock_port = knock_port
        self.open_port = open_port
        self.set_initial_state()

    def set_initial_state(self):
        # the basic switching behavior
        self.switch = (match(port=1)>>fwd(2)) + (match(port=2)>>fwd(1))

        # always forward ARP and ICMP
        forwardARP = match(ethtype=0x0806) >> self.switch
        forwardICMP = match(ethtype=0x0800,protocol=1) >> self.switch
        self.forward = forwardARP + forwardICMP

        # but capture packets on the knocking port
        knock_knock = packets(1,['srcmac'])
        knock_knock.register_callback(self.whos_there)
        self.query = match(dstport=self.knock_port) >> knock_knock

        # combine the forwarding and the knock query
        self.update_policy()

    def update_policy(self):
        self.policy = self.forward + self.query

    def set_network(self,network):
        self.set_initial_state()

    def whos_there(self,pkt):
        mac = pkt['srcmac']
        self.forward = if_(match(srcmac=mac,dstport=self.open_port),
                           self.switch, # open up port for incoming...
                           if_(match(dstmac=mac,srcport=self.open_port),
                               self.switch, # and allow return traffic
                               self.forward))
        self.update_policy()
                              

def main():
    return port_knocking(1234,80)
