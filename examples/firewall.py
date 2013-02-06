
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

##############################################################################################################################
# TO TEST EXAMPLE                                                                                                            #
# -------------------------------------------------------------------                                                        #
# start mininet:  /pyretic/mininet.sh --switch ovsk --clique,5,5                                                             #
# run controller: pox.py --no-cli pyretic/examples/firewall_dyn.py                                                           #
# test:           pingall. odd nodes should reach odd nodes w/ higher IP, likewise for even ones                             #
#                 controller prints one message "punching hole for reverse traffic [IP1]:[IP2]" for each pair where IP1<IP2  #
#                 timeout seconds after last time punched hole used, it will close w/ corresponding print statement          #
##############################################################################################################################

from frenetic.lib import *
from examples.hub import hub
from examples.learning_switch import learning_switch


def simple_firewall(pairs):
    pol = drop
    for (ip1,ip2) in pairs:     
        pred = match(srcip=ip1,dstip=ip2) | match(srcip=ip2,dstip=ip1) 
        pol -= pred
        pol |= pred[passthrough]
    return pol

def simple_firewall_example():
    """traffic allowed between sets {10.0.0.1-10.0.0.3} and {10.0.0.4}, all other traffic dropped"""
    client_ips =  [ '10.0.0.' + str(i) for i in range(1,4) ]
    service_ip  = '10.0.0.4'
    allowed = set([])
    for client_ip in client_ips:
        allowed.add((client_ip,service_ip))
    return simple_firewall(allowed) >> learning_switch()


def simple_ingress_firewall(pairs):
    pol = drop_ingress
    print pol
    for (ip1,ip2) in pairs:     
        pred = match(srcip=ip1,dstip=ip2) | match(srcip=ip2,dstip=ip1) 
        pol -= pred
        pol |= pred[passthrough]
    print pol
    return pol

def simple_ingress_firewall_example():
    """traffic allowed between sets {10.0.0.1-10.0.0.3} and {10.0.0.4}, all other traffic dropped"""
    client_ips =  [ '10.0.0.' + str(i) for i in range(1,4) ]
    service_ip  = '10.0.0.4'
    allowed = set([])
    for client_ip in client_ips:
        allowed.add((client_ip,service_ip))
    return simple_ingress_firewall(allowed) >> hub


@policy_decorator
def directional_hole_puncher(self,**kwargs):
    allowed = self.kwargs['allowed']
    for (ip1,ip2) in allowed:     
        pred = match(srcip=ip1,dstip=ip2) 
        self.policy -= pred
        self.policy |= pred[passthrough]

    @self.query(all_packets)
    def f(pkt):
        srcip_str = str(pkt['srcip'])
        dstip_str = str(pkt['dstip'])
        if (srcip_str,dstip_str) in allowed:
            pred = match(srcip=dstip_str,dstip=srcip_str) 
            print "punching hole for reverse traffic %s:%s\n%s" % (srcip_str,dstip_str,pred)
            import ipdb
            ipdb.set_trace()
            self.policy -= pred
            self.policy |= pred[passthrough]
            


#def authentication_firewall_example():
client_ips =  [ '10.0.0.' + str(i) for i in range(1,10) ]
i = 0
whitelist = set([])
for client_ip in client_ips:
    i += 1
    for client_ip2 in client_ips[i+1::2]:
        whitelist.add((client_ip,client_ip2))

print whitelist

main =  directional_hole_puncher(allowed=whitelist) >> hub
