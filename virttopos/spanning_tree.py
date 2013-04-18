
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
# run controller: pox.py --no-cli pyretic/examples/virtualize.py --program=pyretic/examples/mac_learner.py --virttopo=pyretic/virttopos/spanning_tree.py
############################################################################################################################


from frenetic.lib import *

def topo_to_st_vmap(topo, mst):
    d = {}
    for sw, attrs in mst.nodes(data=True):
        elocs = topo.egress_locations(sw)
        mstlocs = set()
        for attrs in mst[sw].itervalues():
            mstlocs.add(attrs[sw])
        locs = elocs | {Location(sw,p) for p in mstlocs}
        for loc in locs:
            d[(loc.switch,loc.port_no)] = [(loc.switch, loc.port_no)]
    return d


def one_to_one_fabric_policy(vmap):
    fabric_policy = drop
    # ITERATE THROUGH ALL PAIRS OF VIRTUAL PORTS
    for (vswitch1,vport1),[(pswitch1,pport1)] in vmap.items():
        for (vswitch2,vport2),[(pswitch2,pport2)] in vmap.items():
            # FABRIC POLICY ONLY EXISTS WITHIN EACH VIRTUAL SWITCH
            if vswitch1 != vswitch2:
                continue
            # FORWARD OUT THE CORRECT PHYSICAL PORT
            fabric_policy |= match(vswitch=vswitch1,vinport=vport1,voutport=vport2)[fwd(pport2)]
    return fabric_policy



class SpanningTree(object):
    def __init__(self):
        self.vmap = None
        
    from frenetic import netcore
    def network_transform(self,network):
        vtopo = Topology.minimum_spanning_tree(network.topology)
        self.vmap = topo_to_st_vmap(network.topology, vtopo)
        vnetwork = Network(None)
        vnetwork.init_events()
        vnetwork.topology = vtopo
        vnetwork.backend = network.backend  # UNSURE IF THIS IS PRINCIPLED OR A HACK

        print "------- Underlying ---------"
        print network.topology
        print "------- Derived ---------"
        print vnetwork.topology

        return vnetwork
        
    @NetworkDerivedPolicyPropertyFrom
    def ingress_policy(self, network):
        return vmap_to_ingress_policy(self.vmap)

    @NetworkDerivedPolicyPropertyFrom
    def fabric_policy(self, network):
        return one_to_one_fabric_policy(self.vmap)

    @NetworkDerivedPolicyPropertyFrom
    def egress_policy(self, network):
        return vmap_to_egress_policy(self.vmap)

transform = SpanningTree()

        
    

    

