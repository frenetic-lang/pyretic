
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

def topo_to_vmap_dict(topo, mst):
    d = {}
    for sw, attrs in mst.nodes(data=True):
        eports = egress_ports(topo, sw)
        mstports = set()
        for attrs in mst[sw].itervalues():
            mstports.add(attrs[sw])
        ports = eports | mstports
        for port in ports:
            d[(sw, port)] = [(sw, port)]
    return d

def setup_virtual_network(network):
    vn = VNetwork.fork(network)
    @run
    def vmap_gen():
        for topo in network.topology_changes:
            mst = nx.minimum_spanning_tree(topo)
            vn.physical_policy = copy(outport="voutport") >> pop("vtag", "vswitch", "vinport")
            vn.from_maps(topo_to_vmap_dict(topo, mst))
            vn.topology = mst
    return vn
    
        
    

    

