
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

#    -------
#  -/       \-                                                        ---------
# /           \                                                     -/         \-
# |     h10   |                                                    /             \
# \           --     +--------------+      2                 /-----       h11     )
#  -\       /-  \-   |              |              /---------      \             /
#    -------      \- |              |    /---------                 -\         /-
#                   \+              +----                             ---------
#                1   |       s1     |
#                    |              |
#                    |              |
#                    +--------------+
#                               \-   3     +---------------------+
#                                 \-       |                     |               -------
#                                   \-     |                     |            --/       \--
#                                     \- 2 |                     |           /             \
#                                       \- |                     |  1       /               \
#                                         \+       s2            +-----     |               |
#                                          |                     |     \-----      h12      /
#                                          |                     |           \             /
#                                          |                     |            --\       /--
#                                          +---------------------+               -------
#
#
#
#

from frenetic.lib import *
from examples import learning_switch as ls
from examples import simple_arp as sa
from examples import simple_firewall as fw

lswitch_vmap = {
    (101, 1): [(1, 1)], # h10
    (101, 2): [(1, 2)], # h11
    (101, 3): [(1, 3)], # v102
    
    (102, 1): [(2, 1)], # h12  
    (102, 2): [(2, 2)], # v101
}

arp_vmap = {
    (103, 1): [(1, 1)], # h10
    (103, 2): [(1, 2)], # h11
    (103, 3): [(2, 1)]  # h12
}

def figure_3_views(network):
    isolated_lswitch_vn = INetwork.fork(network)
    isolated_lswitch_vn.sync_with_topology()
    isolated_lswitch_vn.ingress_predicate -= match(type = 0x806)
    
    lswitch_vn = VNetwork.fork(isolated_lswitch_vn)
    lswitch_vn.from_vmap(lswitch_vmap)
    lswitch_vtopo = nx.Graph()
    add_nodes_from_vmap(lswitch_vmap, lswitch_vtopo)
    lswitch_vtopo.add_edge(Switch(101), Switch(102), {Switch(101): Port(3), Switch(102): Port(2)})
    lswitch_vn.topology = lswitch_vtopo
    lswitch_vn.physical_policy = isolated_lswitch_vn.flood

    #
    
    isolated_arp_vn = INetwork.fork(network)
    isolated_arp_vn.sync_with_topology()
    isolated_arp_vn.ingress_predicate &= match(type = 0x806)

    arp_vn = VNetwork.fork(isolated_arp_vn)
    arp_vn.from_vmap(arp_vmap)
    arp_vtopo = nx.Graph()
    add_nodes_from_vmap(arp_vmap, arp_vtopo)
    arp_vn.topology = arp_vtopo
    arp_vn.physical_policy = isolated_arp_vn.flood

    return lswitch_vn, arp_vn

def run_figure3(network):
    lswitch_view, arp_view = figure_3_views(network)
    run(ls.learning_switch, lswitch_view)
    run(sa.arp, arp_view)
    
main = run_figure3
