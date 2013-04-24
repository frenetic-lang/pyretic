
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

############################################################################################################################
# TO TEST EXAMPLE                                                                                                          #
# -------------------------------------------------------------------                                                      #
# start mininet:  ./pyretic/mininet.sh --switch ovsk --topo=clique,4,4                                                     #
# run controller: pox.py --no-cli pyretic/examples/virtualize.py --program=pyretic/examples/mac_learner.py --virttopo=pyretic/virttopos/bfs.py
############################################################################################################################


from frenetic.lib import *


def topo_to_bfs_vmap(topo):
    vmap = {}
    port_no = 1
    for loc in topo.egress_locations():
        vmap[1, port_no] = [(loc.switch, loc.port_no)]
        port_no += 1
    return vmap

    
def shortest_path_policy(topo,vmap):
    fabric_policy = drop
    paths = Topology.all_pairs_shortest_path(topo)
    # ITERATE THROUGH ALL PAIRS OF VIRTUAL PORTS
    for (vswitch1,vport_no1),[(pswitch1,pport_no1)] in vmap.items():
        for (vswitch2,vport_no2),[(pswitch2,pport_no2)] in vmap.items():
            # FABRIC POLICY ONLY EXISTS WITHIN EACH VIRTUAL SWITCH
            if vswitch1 != vswitch2:
                continue
            # IF IDENTICAL VIRTUAL LOCATIONS, THEN WE KNOW FABRIC POLICY IS JUST TO FORWARD OUT MATCHING PHYSICAL PORT
            if vport_no1 == vport_no2:
                fabric_policy |= match(vswitch=vswitch1,vinport=vport_no1,voutport=vport_no2,switch=pswitch2)[fwd(pport_no2)]
            # OTHERWISE, GET THE PATH BETWEEN EACH PHYSICAL PAIR OF SWITCHES CORRESPONDING TO THE VIRTUAL LOCATION PAIR
            # THE FOR EACH PHYSICAL HOP ON THE PATH, CREATE THE APPROPRIATE FORWARDING RULE FOR THAT SWITCH
            # FINALLY ADD A RULE THAT FORWARDS OUT THE CORRECT PHYSICAL PORT AT THE LAST PHYSICAL SWITCH ON THE PATH
            else:
                try:
                    for loc in paths[pswitch1][pswitch2]:
                        fabric_policy |= match(vswitch=vswitch1,vinport=vport_no1,voutport=vport_no2,switch=loc.switch)[fwd(loc.port_no)]
                    fabric_policy |= match(vswitch=vswitch1,vinport=vport_no1,voutport=vport_no2,switch=pswitch2)[fwd(pport_no2)]
                except KeyError:
                    pass
    return fabric_policy

from frenetic import netcore

class BFS(object):
    def __init__(self,keep=[]):
        self.keep = keep
        self.vmap = None
        self.underlying_topology = None

    def network_transform(self,network):
        """produces a new network object w/ transformed topology, also updates underlying_topology and vmap for use by ingress, fabric and egress"""
        self.underlying_topology = network.topology
        if self.keep:
            tmp = network.topology.filter_nodes(self.keep)
            if tmp:
                self.underlying_topology = tmp
        self.vmap = topo_to_bfs_vmap(self.underlying_topology)
        
        vtopo = Topology()
        add_nodes_from_vmap(self.vmap, vtopo)
        vnetwork = Network(None)
        vnetwork.init_events()
        vnetwork.topology = vtopo
        vnetwork.backend = network.backend  # UNSURE IF THIS IS PRINCIPLED OR A HACK

        print "------- Underlying BFS Topology ---------"
        print self.underlying_topology
        print "------- Derived BFS Topology ---------"
        print vnetwork.topology

        return vnetwork
                
    @NetworkDerivedPolicyPropertyFrom
    def ingress_policy(self, network):
        return vmap_to_ingress_policy(self.vmap)

    @NetworkDerivedPolicyPropertyFrom
    def fabric_policy(self, network): 
        return shortest_path_policy(self.underlying_topology, self.vmap)

    @NetworkDerivedPolicyPropertyFrom
    def egress_policy(self, network):
        return vmap_to_egress_policy(self.vmap)

        
transform = BFS()
