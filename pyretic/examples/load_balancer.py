
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
# input:    --clients=NUM_CLIENTS --servers=NUM_SERVERS                        #
# mininet:  mininet.sh --topo=bump_clique,3,NUM_CLIENTS,NUM_SERVERS            #
# test:     hX ping -c 1 10.0.0.100 will work from each host                   #
#           all nodes will be able to ping each other,                         #
#           except hosts to their load-balanced instance                       #
#           pingall will output                                                #
#                 h1 -> h2 h3 h4 h5 X hs2 hs3                                  #
#                 h2 -> h1 h3 h4 h5 hs1 X hs3                                  #
#                 h3 -> h1 h2 h4 h5 hs1 hs2 X                                  #
#                 h4 -> h1 h2 h3 h5 X hs2 hs3                                  #
#                 h5 -> h1 h2 h3 h4 hs1 X hs3                                  #
#                 hs1 -> h1 h2 h3 h4 h5 hs2 hs3                                #
#                 hs2 -> h1 h2 h3 h4 h5 hs1 hs3                                #
#                 hs3 -> h1 h2 h3 h4 h5 hs1 hs2                                #
################################################################################

import math
from pyretic.lib.corelib import *
from pyretic.lib.std import *

def subs(c,r,p):
    """from client, substitute replica address for the public address 
    from server, substitute public address for replica address"""
    c_to_p = match(srcip=c,dstip=p)
    r_to_c = match(srcip=r,dstip=c)
    return ((c_to_p & modify(dstip=r)) + 
            (r_to_c & modify(srcip=p)) + 
            (~r_to_c & ~c_to_p))

def rewrite(d,p):
    "substitute for all client/replica mappings in d"
    return sequential([subs(c,r,p) for c,r in d])

def balance(R,H):
    """A simple balancing function the ignores history"""
    client_ips = H.keys()
    extension_factor = int(math.ceil(float(len(client_ips)) / len(R)))
    repeating_R = []
    for i in range(0, extension_factor):
        repeating_R += R
    import random
    random.shuffle(repeating_R)
    return zip(client_ips, repeating_R)

## DO-NOTHING UPDATE, TODO - MAKE INTERESTING
def update(H,stats):
    # for cli,cnt in stats.items():
    #     try:    H[cli] = cnt - H[cli]
    #     except: H[cli] = cnt
    # print H
    return H

def static_lb(p,R,H):
    return rewrite(balance(R,H),p) 

def lb(self,p,R,H):

    def update_policy():
        """Update the policy based on current modify and query policies"""
        self.policy = self.modify + (match(dstip=p) & self.query)
    self.update_policy = update_policy

    def rebalance(stats):
        self.H = update(H,stats)
        b = balance(R,self.H)
        print "rebalance %s" % b
        self.modify = rewrite(b,p)
        self.update_policy()

    self.H = H
    self.query = counts(5,['srcip'])
    self.query.register_callback(rebalance)
    self.modify = static_lb(p,R,H) 
    self.update_policy()


def main(clients, servers):
    from pyretic.modules.mac_learner import learn
    
    num_clients = int(clients)
    num_servers = int(servers)

    print "clients %d" % num_clients
    print "servers %d" % num_servers

    # CALCULATE IPS
    ip_prefix = '10.0.0.'
    public_ip = IP(ip_prefix + str(100))
    print "public_ip = %s" % public_ip
    
    client_ips = [IP(ip_prefix + str(i)) for i in range(1, 1+num_clients)]
    H = {c : 0 for c in client_ips}
    R = [IP(ip_prefix + str(i)) for i in range(1+num_clients, 1+num_clients+num_servers)]

    return static_lb(public_ip,R,H) >> dynamic(learn)()     ## TEST ABOVE WORKS
#    return dynamic(lb)(public_ip,R,H) >> dynamic(learn)()  

