
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

from pyretic.lib.corelib import *
from pyretic.lib.virt import *

class spanning_tree_vdef(vdef):
    def make_vmap(self):
        mapping = vmap()
        for sw, attrs in self.derived.topology.nodes(data=True):
            elocs = self.underlying.topology.egress_locations(sw)
            mstlocs = set()
            for attrs in self.derived.topology[sw].itervalues():
                mstlocs.add(attrs[sw])
            locs = elocs | {Location(sw,p) for p in mstlocs}
            for loc in locs:
                mapping.d2u[Location(loc.switch,loc.port_no)] = \
                    [Location(loc.switch, loc.port_no)]
        return mapping

    def set_network(self,network):
        if network == self.underlying:
            return
        self.underlying = network
        self.derived = DerivedNetwork(self.underlying)
        self.derived.topology = Topology.minimum_spanning_tree(network.topology)
        self.derived.inherited.clear()
        self.vmap = self.make_vmap()

        print "------- Underlying Spanning Tree Topology ---------"
        print self.underlying.topology
        print "------- Derived Spanning Tree Topology ---------"
        print self.derived.topology

        
    @NetworkDerivedPolicyPropertyFrom
    def ingress_policy(self, network):
        return self.vmap.ingress_policy()

    @NetworkDerivedPolicyPropertyFrom
    def fabric_policy(self, network):
        return self.vmap.one_to_one_fabric_policy() 

    @NetworkDerivedPolicyPropertyFrom
    def egress_policy(self, network):
        return self.vmap.egress_policy()

transform = spanning_tree_vdef()

        
    

    

