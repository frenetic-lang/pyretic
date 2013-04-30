
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
# start mininet:  pyretic/mininet.sh --topo=pgateway                                                                         #
# run controller: pox.py --no-cli pyretic/examples/basic_gateway.py                                                          #
# test:           pingall                                                                                                    #
##############################################################################################################################

from frenetic.lib import *

from examples.mac_learner import mac_learner
from examples.arp import arp, translate, ARP


def gateway_pol():
    num_clients = 3
    num_servers = 3

    gw_mac = MAC('AA:AA:AA:AA:AA:AA')
    fake_mac = MAC('BB:BB:BB:BB:BB:BB')
    public_ip = '10.0.1.100'
    eth_prefix = '10.0.0.'
    ip_prefix  = '10.0.1.'
    prefix_len = 24
    eth_cidr = eth_prefix + '0/' + str(prefix_len)
    ip_cidr = ip_prefix + '0/' + str(prefix_len)

    eth_macs = { IP(eth_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i)) \
                     for i in range(1,1+num_clients) }
    ip_macs = { IP(ip_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i+num_clients)) \
                    for i in range(1,1+num_servers) }
    host_macs = dict(eth_macs.items() + ip_macs.items())
    host_macs.update({IP(public_ip) : fake_mac})
    gw_macs = {IP(eth_prefix +'1') : gw_mac, IP(ip_prefix+'1') : gw_mac}

    to_eth = match(dstip=eth_cidr)
    to_ip  = match(dstip=ip_cidr)
    eth_to_ip = match(inport=1) & (to_ip | match(dstip=public_ip) )
    ip_to_eth = match(inport=2) & (to_eth)
    subnet_forwarder = eth_to_ip[fwd(2)] | ip_to_eth[fwd(1)]
    return if_(ARP,
               arp(gw_macs),
               translate(host_macs) >> subnet_forwarder)


def policy_from(eth_pol,ip_pol,gw_pol):
    ethernet = [2,3,4,1000]
    ip_core  = [5,6,7,1002]
    gateway  = [1001]

    eth_pol_dbg = pkt_print('->eth') >> eth_pol >> pkt_print('eth->')
    ip_pol_dbg  = pkt_print('->ip') >> ip_pol >> pkt_print('ip->')
    gw_pol_dbg  = pkt_print('->gw') >> gw_pol >> pkt_print('gw->')

    pol = switch_in(ethernet)[ eth_pol ] | \
        switch_in(gateway)[ gw_pol ] | \
        switch_in(ip_core)[ ip_pol ]    
    pol_dbg = pkt_print('->pol') >> trace(pol) >> pkt_print('->pol') >> \
        if_(egress_network(),clear_trace()) >> pkt_print('outgoing')
    
    return pol

def basic_gateway_setup():
    eth_pol     = mac_learner() 
    ip_pol      = mac_learner() 
    gw_pol      = gateway_pol()
    return policy_from(eth_pol,ip_pol,gw_pol)

def main():
    return basic_gateway_setup()


