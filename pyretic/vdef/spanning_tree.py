
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

class spanning_tree(vdef):
    def __init__(self):
        super(spanning_tree,self).__init__()

        @singleton
        class ingress_policy(DynamicPolicy):
            def set_network(self,network):
                self.policy = self.vmap.ingress_policy()
                DynamicPolicy.set_network(self,network)            
        self.ingress_policy = ingress_policy

        @singleton
        class fabric_policy(DynamicPolicy):
            def set_network(self,network):
                self.policy = self.vmap.one_to_one_fabric_policy() 
                DynamicPolicy.set_network(self,network)            
        self.fabric_policy = fabric_policy

        @singleton
        class egress_policy(DynamicPolicy):
            def set_network(self,network):
                self.policy = self.vmap.egress_policy()
                DynamicPolicy.set_network(self,network)            
        self.egress_policy = egress_policy
    
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
        self.underlying = network
        self.derived = self.DerivedNetwork(self.underlying)
        self.derived.topology = Topology.minimum_spanning_tree(network.topology)
        self.derived.inherited.clear()
        super(spanning_tree,self).set_network(network)
        print "------- Underlying Spanning Tree Topology ---------"
        print self.underlying.topology
        print "------- Derived Spanning Tree Topology ---------"
        print self.derived.topology


transform = spanning_tree()

        
    

    

