
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

def egress_ports(topo, sw):
    attrs = topo.node[sw]
    all_ports = attrs["ports"]
    non_egress_ports = set()
    for attrs in topo[sw].itervalues():
        non_egress_ports.add(attrs["p1"])
    egress_ports = all_ports - non_egress_ports
    return egress_ports

def topo_to_vmap_dict(topo, mst):
    d = {}
    for sw, attrs in mst.nodes(data=True):
        eports = egress_ports(topo, sw)
        mstports = set()
        for attrs in mst[sw].itervalues():
            mstports.add(attrs["p1"])
        ports = eports | mstports
        for port in ports:
            d[(sw, port)] = [(sw, port)]
    return d

def setup_virtual_network(network):
    def vmap_gen():
        for topo in network.topology_changes:
            mst = nx.minimum_spanning_tree(topo)
            vmap = topo_to_vmap_dict(topo, mst)
            physical_policy = copy(outport="voutport")
            yield (vmap, physical_policy)
    return fork_virtual_network(network, make_vnetwork_gen(vmap_gen()))
        
    

    

