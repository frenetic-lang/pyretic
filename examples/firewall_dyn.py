
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
from examples.learning_switch_dyn import learning_switch

def simple_firewall(pairs):
    pol = drop
    for (ip1,ip2) in pairs:     
        pred = match(srcip=ip1,dstip=ip2) | match(srcip=ip2,dstip=ip1) 
        pol -= pred
        pol |= pred & passthrough
    return pol

def simple_ingress_firewall(pairs,network):
    pol = drop_ingress(network)
    for (ip1,ip2) in pairs:     
        pred = match(srcip=ip1,dstip=ip2) | match(srcip=ip2,dstip=ip1) 
        pol -= pred
        pol |= pred & passthrough
    return pol

def directional_hole_punching_logic(pairs,network,ls):
    for pkt in query_unique(network, all_packets, fields=['srcip', 'dstip']):
        srcip_str = str(pkt['srcip'])
        dstip_str = str(pkt['dstip'])
        if (srcip_str,dstip_str) in pairs:
            print "punching hole for reverse traffic %s:%s" % (srcip_str,dstip_str)
            pred = match(srcip=dstip_str,dstip=srcip_str) 
            pol = ls.get()
            pol -= pred
            pol |= pred & passthrough
            ls.set(pol)


def authentication_firewall(pairs,network):
    pol = drop
    for (ip1,ip2) in pairs:     
        pred = match(srcip=ip1,dstip=ip2) 
        pol -= pred
        pol |= pred & passthrough
    return DynamicPolicy(network,[lambda n,l: directional_hole_punching_logic(pairs,n,l)],pol)


def hole_expiry_logic(timeout,pairs,network,ls):
    poll_freq = 1  # poll every second - if changed need to change timeout logic

    potential_holes = no_packets
    for (srcip_str,dstip_str) in pairs:
        potential_holes |= match(srcip=dstip_str,dstip=srcip_str) 

    count_stats = {}
    for qcount in query_count(network, potential_holes, poll_freq, ['srcip','dstip']):
        for (pred,count) in qcount.items():
            polls_missed = 0
            try:
                (prev_count,polls_missed) = count_stats[pred]
                if prev_count >= count:
                    polls_missed += 1
            except KeyError:
                pass
            
            count_stats[pred] = (count,polls_missed)
                
            if polls_missed == timeout:
                print "%d seconds w/o traffic, closing hole" % timeout,
                print pred
                pol = ls.get()
                pol -= pred 
                ls.set(pol)



def directional_firewall(timeout,pairs,network):
    pol = drop
    for (ip1,ip2) in pairs:     
        pred = match(srcip=ip1,dstip=ip2) 
        pol -= pred
        pol |= pred & passthrough
    return DynamicPolicy(network,[lambda n,l: directional_hole_punching_logic(pairs,n,l),
                                  lambda n,l: hole_expiry_logic(timeout,pairs,n,l)]
                         ,pol)


def simple_firewall_example(network):
    client_ips =  [ '10.0.0.' + str(i) for i in range(1,3) ]
    service_ip  = '10.0.0.4'
    allowed = set([])
    for client_ip in client_ips:
        allowed.add((client_ip,service_ip))
    policy = simple_firewall(allowed) >> learning_switch(network)
    network.install_policy(policy)


def authentication_firewall_example(network):
    client_ips =  [ '10.0.0.' + str(i) for i in range(1,10) ]
    i = 0
    allowed = set([])
    for client_ip in client_ips:
        i += 1
        for client_ip2 in client_ips[i+1::2]:
            allowed.add((client_ip,client_ip2))

    policy = authentication_firewall(allowed,network) >> learning_switch(network)
    network.install_policy(policy)


def directional_firewall_example(network):
    client_ips =  [ '10.0.0.' + str(i) for i in range(1,10) ]
    i = 0
    allowed = set([])
    for client_ip in client_ips:
        i += 1
        for client_ip2 in client_ips[i+1::2]:
            allowed.add((client_ip,client_ip2))

    timeout = 10
            
    policy = directional_firewall(timeout,allowed,network) >> learning_switch(network)
    network.install_policy(policy)

        
main = directional_firewall_example
