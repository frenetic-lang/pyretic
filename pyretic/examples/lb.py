################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Omid Alipourfard (omida@cs.princeton.edu)                            #
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
# input:    --clients=NUM_CLIENTS --servers=NUM_SERVERS                        #
# mininet:  mininet.sh --topo=clique,1,NUM_CLIENTS+NUM_SERVERS                 #
#           e.g., if load balancing 4 clients across two servers:              #
#              mininet.sh --topo=clique,1,6                                    #
# test:     hX ping -c 1 10.0.0.100 will work for clients                      #
#           Clients are h1 through hNUM_CLIENTS                                #
#           They will be load balanced across hNUM_CLIENTS+1 to                #
#                                             hNUM_CLIENTS+NUM_SERVERS         #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

################################################
# Translate from 
#   client -> public address : client -> server
#   server -> client : public address -> client
################################################
def translate(c, s, p):
    cp = match(srcip=c, dstip=p)
    sc = match(srcip=s, dstip=c)

    return ((cp >> modify(dstip=s)) +
            (sc >> modify(srcip=p)) +
            (~cp & ~sc))

##################################################################
# Simple round-robin load balancing policy                       #
#                                                                #
# This implementation will drop the first packet of each flow.   #
# An easy fix would be to use network.inject_packet to send the  #
# packet to its final destination.                               #
##################################################################
class rrlb(DynamicPolicy):
    def __init__(self, clients, servers, public_ip):
        super(rrlb,self).__init__()

        print("Server addresses", servers)

        self.clients   = clients
        self.servers   = servers
        self.public_ip = public_ip
        self.index     = 0

        self.query     = packets(1,['srcip'])
        self.query.register_callback(self.update_policy)
        self.public_to_controller = (match(dstip=self.public_ip) >> self.query)
        self.lb_policy = None
        self.policy = self.public_to_controller


    def update_policy(self, pkt):
        client = pkt['srcip']

        # Becareful not to redirect servers on themselves
        if client in self.servers: return

        server = self.next_server()
        p = translate(client, server, self.public_ip)

        print("Mapping c:%s to s:%s" % (client, server))

        if self.lb_policy:
            self.lb_policy = self.lb_policy >> p
        else:
            self.lb_policy = p
        self.policy = self.lb_policy + self.public_to_controller

    def next_server(self):
        server = self.servers[self.index % len(self.servers)]
        self.index += 1
        return server

def main(clients, servers):
    from pyretic.modules.mac_learner import mac_learner

    clients   = int(clients)
    servers   = int(servers)

    ip_prefix = "10.0.0."
    public_ip = IP(ip_prefix + "100")
    print("public ip address is %s." % public_ip)
    
    client_ips = [IP(ip_prefix+str(i)) for i in range(1, clients+1)]
    server_ips = [IP(ip_prefix+str(i)) for i in range(1+clients, clients+servers+1)]
    
    return rrlb(client_ips, server_ips, public_ip) >> mac_learner()
