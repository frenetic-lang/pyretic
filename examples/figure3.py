
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

# Intended to be used with ./mininet.sh --topo figure3

from frenetic.lib import *
from examples import learning_switch as ls
from examples import simple_arp as sa
from examples import simple_firewall as fw

lswitch_vmap = {
    (101, 1): [(1, 1)],
    (101, 2): [(1, 2)],
    (101, 3): [(1, 3)],    
    (102, 1): [(2, 1)],
    (102, 2): [(2, 2)]
}

arp_vmap = {
    (103, 1): [(1, 1)],
    (103, 2): [(1, 2)],
    (103, 3): [(2, 1)]
}

firewall_vmap = {
    (201, 1): [(101, 1),(103,1)],
    (201, 2): [(101, 2),(102,1),(103,2),(103,3)]
}

def figure_3_views(network):
    lswitch_vn = VNetwork.fork(network)
    lswitch_vn.from_vmap(lswitch_vmap)
    lswitch_vtopo = nx.Graph()
    lswitch_vtopo.add_node(Switch(101),ports={Port(1),Port(2),Port(3)})
    lswitch_vtopo.add_node(Switch(102),ports={Port(1),Port(2)})
    lswitch_vn.topology = lswitch_vtopo
    lswitch_vn.physical_policy = network.flood
    isolated_lswitch_vn = INetwork(lswitch_vn)
    isolated_lswitch_vn.synch_w_topology()
    isolated_lswitch_vn.ingress_predicate -= match(protocol ='ARP')    

    arp_vn = VNetwork.fork(network)
    arp_vn.from_vmap(arp_vmap)
    arp_vtopo = nx.Graph()
    arp_vtopo.add_node(Switch(103),ports={Port(1),Port(2),Port(3)})
    arp_vn.topology = arp_vtopo
    arp_vn.physical_policy = network.flood
    isolated_arp_vn = INetwork(arp_vn)
    isolated_arp_vn.synch_w_topology()
    isolated_arp_vn.ingress_predicate &= match(protocol = 'ARP')
    
    firewall_vn = VNetwork()
    firewall_vn.connect(isolated_lswitch_vn)
    firewall_vn.connect(isolated_arp_vn)
    firewall_vn.from_vmap(firewall_vmap)
    firewall_vtopo = nx.Graph()
    firewall_vtopo.add_node(Switch(201),ports={Port(1),Port(2)})
    firewall_vn.topology = firewall_vtopo
    firewall_vn.physical_policy = network.flood
    
    return (isolated_lswitch_vn, isolated_arp_vn, firewall_vn)

def run_figure3(network):
    lswitch_view,arp_view,firewall_view = figure_3_views(network)
    run(ls.learning_switch, lswitch_view)
    run(sa.arp, arp_view)
    run(fw.firewall, firewall_view)
