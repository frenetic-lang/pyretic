
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
# start mininet:  pyretic/mininet.sh --topo=gateway                                                                          #
# run controller: pox.py --no-cli pyretic/examples/kitchen_sink.py                                                           #
# test:           pingall should work only between hosts (h1,h2,h3), all traffic between other hosts should be blocked       #
#                 all hosts should also be able to ping 10.0.1.100, which will be handled by changing server (hs1,hs2,hs3)   #
##############################################################################################################################

from frenetic.lib import *

from examples.mac_learner import mac_learner
from examples.arp import arp, translate, ARP
from examples.monitor import dpi
from virttopos.gateway_vdef import gateway_vdef


ethernet = [2,3,4,1000]
ip_core  = [5,6,7,1002]
gateway  = [1001]

num_clients = 3
num_servers = 3

gw_mac = MAC('AA:AA:AA:AA:AA:AA')
fake_mac = MAC('BB:BB:BB:BB:BB:BB')

public_ip = '10.0.1.100'
eth_prefix = '10.0.0.'
ip_prefix  = '10.0.1.'

eth_macs = { IP(eth_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i)) \
                 for i in range(1,1+num_clients) }
ip_macs = { IP(ip_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i+num_clients)) \
                for i in range(1,1+num_servers) }
host_macs = dict(eth_macs.items() + ip_macs.items())
host_macs.update({IP(public_ip) : fake_mac})
gw_macs = {IP(eth_prefix +'1') : gw_mac, IP(ip_prefix+'1') : gw_mac}

to_eth = match(dstip='10.0.0.0/24')
to_ip  = match(dstip='10.0.1.0/24')
eth_to_ip = match(inport=1) & (to_ip | match(dstip=public_ip) )
ip_to_eth = match(inport=2) & (to_eth)

eth_pol          = mac_learner() 
eth_pol_dbg      = pkt_print('->eth') >> eth_pol >> pkt_print('eth->')
ip_pol           = mac_learner() 
ip_pol_dbg       = pkt_print('->ip') >> ip_pol >> pkt_print('ip->')
subnet_forwarder = (match(inport=1) & to_ip)[fwd(2)] | (match(inport=2) & to_eth)[fwd(1)]
gw_pol           = if_(ARP,
                       arp(gw_macs),
                       translate(host_macs) >> subnet_forwarder)
gw_pol_dbg       = pkt_print('->gw') >> gw_pol >> pkt_print('gw->')

pol = switch_in(ethernet)[ eth_pol ] | \
    switch_in(gateway)[ gw_pol ] | \
    switch_in(ip_core)[ ip_pol ]    
pol_dbg = pkt_print('->pol') >> trace(pol) >> pkt_print('->pol') >> if_(egress,clear_trace()) >> pkt_print('outgoing')


@dynamic
def vgateway(self,pol):
    self.policy = virtualize_part(pol, gateway_vdef(self))

def main():
#    return pol
    return vgateway(pol)


