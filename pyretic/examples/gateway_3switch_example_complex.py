
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
# mininet:  mininet.sh --topo=gateway3                                         #
# test:     all hosts in 10.0.0.0/24 can ping one another and 10.0.1.100,      #
#           all other non-ARP packets blocked                                  #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.virt import *

from pyretic.modules.gateway_forwarder import gateway_forwarder
from pyretic.modules.mac_learner import mac_learner
from pyretic.modules.arp import ARP
from pyretic.vdef.bfs_vdef import BFS_vdef
from pyretic.examples.load_balancer import lb
from pyretic.examples.firewall import fw


def fix_dstmac(ip_to_mac):
    change = (parallel(
            [match(dstip=k) & ~match(dstmac=v) & 
             pop('dstmac') >> push(dstmac=v)
             for k,v in ip_to_mac.items()]))
              
    leave = (sequential(
            [~(match(dstip=k) & ~match(dstmac=v)) 
              for k,v in ip_to_mac.items()]))
    return change + leave

def example_setup(num_clients=3, num_servers=3):
    ### EXAMPLE PARAMETERS
    # NETWORK BREAKDOWN
    ethernet = [2,3,4,1000]
    ip_core  = [5,6,7,1002]
    gateway  = [1001]

    # SUBNET ADDRESSING
    eth_prefix = '10.0.0.'
    ip_prefix  = '10.0.1.'
    prefix_len = 24
    eth_cidr = eth_prefix + '0/' + str(prefix_len)
    ip_cidr = ip_prefix + '0/' + str(prefix_len)

    # END HOST ADDRESSES
    public_ip = IP('10.0.1.100')
    fake_mac = MAC('BB:BB:BB:BB:BB:BB')
    eth_macs = { IP(eth_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i)) \
                     for i in range(1,1+num_clients) }
    ip_macs = { IP(ip_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i+num_clients)) \
                    for i in range(1,1+num_servers) }
    host_macs = dict(eth_macs.items() + ip_macs.items())
    host_macs.update({IP(public_ip) : fake_mac})

    # PARAMETERS FOR FIREWALL/LOAD BALANCER
    R = [IP(ip_prefix + str(i)) for i in range(2, 2+num_servers)]
    H = {IP(eth_prefix + str(i)) : 0 for i in range(2,2+num_clients)}
    W = {(c,public_ip) for c in H.keys()}

    ### POLICIES FOR THIS EXAMPLE
    eth_pol = mac_learner()
    alb = dynamic(lb)(public_ip,R,H) >> fix_dstmac(ip_macs) 
    afw = if_(ARP,passthrough,dynamic(fw)(W))
    ip_pol = if_(match(srcip=eth_cidr), 
                 afw >> alb, 
                 alb >> afw) >> mac_learner() 
    ip_pol = virtualize(ip_pol,BFS_vdef(name=5,from_switches=ip_core))
    gw_pol = gateway_forwarder(eth_cidr,ip_cidr,host_macs)

    return ((switch_in(ethernet) & eth_pol) + 
            (switch_in(gateway)  & gw_pol ) +
            (switch_in(ip_core)  & ip_pol ))    


def main():
    return example_setup()


