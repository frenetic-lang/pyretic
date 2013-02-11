
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
# start mininet:  pyretic/mininet.sh --topo=clique,5,5                                                                       #
# run controller: pox.py --no-cli pyretic/examples/firewall.py                                                               #
# test:           pingall. odd nodes should reach odd nodes w/ higher IP, likewise for even ones                             #
#                 controller prints one message "punching hole for reverse traffic [IP1]:[IP2]" for each pair where IP1<IP2  #
#                 timeout seconds after last time punched hole used, it will close w/ corresponding print statement          #
##############################################################################################################################

from frenetic.lib import *
from examples.hub import hub
from examples.learning_switch import learn
from virttopos.bfs import BFS

### FIREWALLS ###

drop_ingress = if_(ingress,drop,passthrough)

def poke(W,P):
  p = union([match(srcip=s,dstip=d) for (s,d) in W])
  return if_(p,passthrough,P)

def static_fw(W):
  W_rev = [(d,s) for (s,d) in W]
  return poke(W_rev, poke(W, drop_ingress))

def fw0(self,W):

  def allow_reverse(p):
      print "poking hole for %s,%s" % (p['dstip'],p['srcip'])
      self.policy = poke({(p['dstip'],p['srcip'])},self.policy)

  q = packets(None,[])
  q.when(allow_reverse)

  wp = union([match(srcip=s,dstip=d) for (s,d) in W])
  self.policy = poke(W,drop_ingress) | wp[q]

def patch(p,P):
    return if_(p,drop_ingress,P)

def fw(self,W):

    def check_reverse(stats):
        for (p,cnt) in stats.items():
            (pcnt,missed) = self.H[p]
            if pcnt < cnt: missed = 0   
            else:          missed += 1
            if missed == self.T:
                print "%d seconds w/o traffic, closing hole" % self.T,
                print p
                self.inner.policy = patch(p,self.inner.policy)
            self.H[p] = (cnt,missed)

    q = counts(1,['srcip','dstip'])
    q.when(check_reverse)

    rps = [match(srcip=d,dstip=s) for (s,d) in W]
    self.H = { rp : (0,0) for rp in rps }
    self.T = 3
    self.inner = dynamic(fw0)(W)
    self.policy = self.inner | union(rps)[q]


# # HOW TO CHECK A REVERSE PATH
# reverse_packet = overwrite(srcip='dstip',
#                            dstip='srcip',
#                            srcmac='dstmac',
#                            dstmac='srcmac')
# test_reverse = (reverse_packet >> self.policy).attach(self.network)
    


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

