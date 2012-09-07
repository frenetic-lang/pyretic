
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

from frenetic.lib import *
import networkx as nx

def track_switch_joins(network, topology, topology_changed):
    for switch in network.switch_joins:
        if switch not in topology:
            print "Add switch: %s" % switch
            topology.add_node(switch)
            topology_changed.signal()

def track_switch_parts(network, topology, topology_changed):
    for switch in network.switch_parts:
        if switch in topology:
            print "Lose switch: %s" % switch
            topology.remove_node(switch)
            topology_changed.signal()

def track_link_ups(network, topology, topology_changed):
    for s1,p1,s2,p2 in network.link_ups:
        if not topology.has_edge(s1,s2):
            print "linkup: %s %s -> %s %s" % (s1,p1,s2,p2) 
            topology.add_edge(s1,s2,{'p1': p1, 'p2': p2})
            topology_changed.signal()

def track_link_downs(network, topology, topology_changed):
    for s1,p1,s2,p2 in network.link_downs:
        if topology.has_edge(s1,s2):
            print "linkdown: %s %s -> %s %s" % (s1,p1,s2,p2) 
            topology.remove_edge(s1,s2)
            topology_changed.signal()

def monitor(network):
    topology = nx.DiGraph()
    topology_changed = gs.Event()

    run(track_switch_joins, network, topology, topology_changed)
    run(track_switch_parts, network, topology, topology_changed)
    run(track_link_ups, network, topology, topology_changed)
    run(track_link_downs, network, topology, topology_changed)

    for t in topology_changed:
        print "topology_change!"
        for switch in topology.nodes():
            switch_edges = ', '.join([ "%s => %s[%s]" % (ports['p1'],s2,ports['p2']) for (s1,s2,ports) in topology.edges(data=True) if s1 == switch ])
            print "%s\t%s" % (switch,switch_edges)


main = monitor
