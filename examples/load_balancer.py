
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

###############################################################################################################################
# TO TEST EXAMPLE                                                                                                             #
# -------------------------------------------------------------------                                                         #
# start mininet:  pyretic/mininet.sh --topo=bump_clique,1,5,3                                                                 #
# run controller: pox.py --no-cli pyretic/examples/load_balancer.py --clients=5 --servers=3                                   #
# test:           hX ping -c 1 10.0.0.100 will work from each host                                                            #
#                 all nodes will be able to ping each other, except hosts to their load-balanced instance                     #
#                 pingall will output                                                                                         #
#                 h1 -> h2 h3 h4 h5 X hs2 hs3                                                                                 #
#                 h2 -> h1 h3 h4 h5 hs1 X hs3                                                                                 #
#                 h3 -> h1 h2 h4 h5 hs1 hs2 X                                                                                 #
#                 h4 -> h1 h2 h3 h5 X hs2 hs3                                                                                 #
#                 h5 -> h1 h2 h3 h4 hs1 X hs3                                                                                 #
#                 hs1 -> h1 h2 h3 h4 h5 hs2 hs3                                                                               #
#                 hs2 -> h1 h2 h3 h4 h5 hs1 hs3                                                                               #
#                 hs3 -> h1 h2 h3 h4 h5 hs1 hs2                                                                               #
###############################################################################################################################


import math
from frenetic.lib import *

def subs(c,r,p):
  c_to_p = match(srcip=c,dstip=p)
  r_to_c = match(srcip=r,dstip=c)
  return c_to_p[modify(dstip=r)] | r_to_c[modify(srcip=p)] | (~r_to_c & ~c_to_p)[passthrough]

# # RENAMES PACKETS TO/FROM 10.0.0.2/10.0.0.100 
# def main(public_ip='10.0.0.100', client_ip='10.0.0.1', replica_ip='10.0.0.2'):
#     from examples.hub import hub
#     return subs(client_ip, replica_ip, public_ip) >> hub

def rewrite(d,p):
    return sequential([subs(c,r,p) for c,r in d])


def balance(R,H):
    """ A simple balancing function the ignores history"""
    client_ips = H.keys()
    extension_factor = int(math.ceil(float(len(client_ips)) / len(R)))
    repeating_R = []
    for i in range(0, extension_factor):
        repeating_R += R
    import random
    random.shuffle(repeating_R)
    return zip(client_ips, repeating_R)

def update(H,stats):
    # for cli,cnt in stats.items():
    #     try:    H[cli] = cnt - H[cli]
    #     except: H[cli] = cnt
    # print H
    return H

def lb(self,p,R,H):
 
    def rebalance(stats):
        self.H = update(H,stats)
        b = balance(R,self.H)
        print "rebalance %s" % b
        self.policy = rewrite(b,p)

    self.H = H
    q = counts(5,['srcip'])
    q.when(rebalance)
#    self.policy = rewrite(balance(R,H),p) 
#    self.queries.append(match(dstip=p)[q])
    self.policy = rewrite(balance(R,H),p) | match(dstip=p)[q]


def main(clients, servers):
    from examples.learning_switch import learn
    
    num_clients = int(clients)
    num_servers = int(servers)

    print "clients %d" % num_clients
    print "servers %d" % num_servers

    # CALCULATE IPS
    ip_prefix = '10.0.0.'
    public_ip = ip_prefix + str(100)
    print "public_ip = %s" % public_ip
    
    client_ips = [ip_prefix + str(i) for i in range(1, 1+num_clients)]
    H = {c : 0 for c in client_ips}
    R = [ip_prefix + str(i) for i in range(1+num_clients, 1+num_clients+num_servers)]

#    return rewrite(balance(R,H),public_ip) >> dynamic(learn)()
    return dynamic(lb)(public_ip,R,H) >> dynamic(learn)()
