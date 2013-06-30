
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
# mininet: mininet.sh --topo=clique,5,5 (or other single subnet network)       #
# test:    pingall. odd nodes should reach odd nodes w/ higher IP,             #
#          likewise for even ones                                              #
#          controller prints one message                                       #
#          e.g., "punching hole for reverse traffic [IP1]:[IP2]"               #
#          for each pair where IP1<IP2.                                        #
#          Timeout seconds after last time punched hole used,                  #
#          it will close w/ corresponding print statement                      #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.hub import hub
from pyretic.modules.mac_learner import learn

### FIREWALLS ###

drop_ingress = if_(ingress_network(),drop)

def poke(W,P):
    p = parallel([match(srcip=s,dstip=d) for (s,d) in W])
    return if_(p,passthrough,P)

def static_fw(W):
    W_rev = [(d,s) for (s,d) in W]
    return poke(W_rev, poke(W, drop_ingress))

def fw0(self,W):
    """A dynamic firewall that opens holes but doesn't close them"""

    wp = parallel([match(srcip=s,dstip=d) for (s,d) in W])
    def update_policy():
        """Update the policy based on current forward and query policies"""
        self.policy = self.forward + (wp & self.query)
    self.update_policy = update_policy

    def allow_reverse(p):
        """Open reverse hole for ongoing traffic"""
        print "poking hole for %s,%s" % (p['dstip'],p['srcip'])
        self.forward = poke({(p['dstip'],p['srcip'])},self.forward)
        self.update_policy()

    def refresh_query():
        """(Re)set the query checking for allowed traffic"""
        self.query = packets(1,['dstip','srcip'])
        self.query.register_callback(allow_reverse)

    def refresh():
        """Refresh the policy"""
        refresh_query()
        update_policy()
    self.refresh = refresh

    self.forward = poke(W,drop_ingress) 
    self.refresh()

def patch(p,P):
    return if_(p,drop_ingress,P)

def fw(self,W):
    """A dynamic firewall that closes holes that it opens"""

    def update_policy():
        """Update policy based on current inner and query policies"""
        self.policy = self.inner + (parallel(rps) & self.query)
    self.update_policy = update_policy
    
    def check_reverse(stats):
        """Close unused holes"""
        for (p,cnt) in stats.items():
            (pcnt,missed) = self.H[p]
            if pcnt < cnt: missed = 0   
            else:          missed += 1
            if missed == self.T:
                print "%d seconds w/o traffic, closing hole" % self.T,
                print p
                self.inner.forward = patch(p,self.inner.forward)
                self.inner.refresh()
            self.H[p] = (cnt,missed)

    self.query = counts(1,['srcip','dstip'])
    self.query.register_callback(check_reverse)
    rps = [match(srcip=d,dstip=s) for (s,d) in W]
    self.H = { rp : (0,0) for rp in rps }
    self.T = 3
    self.inner = dynamic(fw0)(W)
    self.update_policy()
    

### EXAMPLES ###

def static_firewall_example():
    """traffic allowed between sets {10.0.0.1-10.0.0.3} and {10.0.0.4}, all other traffic dropped"""
    client_ips =  [ '10.0.0.' + str(i) for i in range(1,4) ]
    service_ip  = '10.0.0.4'
    allowed = set([])
    for client_ip in client_ips:
        allowed.add((client_ip,service_ip))

    return static_fw(allowed) >> hub
 

def authentication_firewall_example():
    """odd nodes should reach odd nodes w/ higher IP, likewise for even ones
       after a higher IP node is pinged, it can contact the lower IP anytime """
    client_ips =  [ '10.0.0.' + str(i) for i in range(1,10) ]
    i = 0
    whitelist = set([])
    for client_ip in client_ips:
        i += 1
        for client_ip2 in client_ips[i+1::2]:
            whitelist.add((client_ip,client_ip2))

    print whitelist
    return dynamic(fw0)(whitelist) >> hub



def statefull_firewall_example():
    """odd nodes should reach odd nodes w/ higher IP, likewise for even ones
       after a higher IP node is pinged, it can contact the lower IP for a short while """
    client_ips =  [ '10.0.0.' + str(i) for i in range(1,10) ]
    i = 0
    whitelist = set([])
    for client_ip in client_ips:
        i += 1
        for client_ip2 in client_ips[i+1::2]:
            whitelist.add((client_ip,client_ip2))

    print whitelist
    return dynamic(fw)(whitelist) >> hub


### Main ###

def main(): 
#    return static_firewall_example()
#    return authentication_firewall_example()
    return statefull_firewall_example()

