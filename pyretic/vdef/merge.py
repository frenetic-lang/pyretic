
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
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

class merge(vdef):
    def __init__(self,name=1,from_switches=[]):
        self.name = name
        self.from_switches = from_switches
        self.kept_topology = None
        super(merge,self).__init__()

        @singleton
        class ingress_policy(DynamicPolicy):
            def set_network(self,network):
                if not self.vmap is None:
                    self.policy = self.vmap.ingress_policy()
                    DynamicPolicy.set_network(self,network)            
        self.ingress_policy = ingress_policy

        @singleton
        class fabric_policy(DynamicPolicy):
            def set_network(self,network):
                if not self.vmap is None:
                    self.policy = self.vmap.shortest_path_fabric_policy(network.topology)
                    DynamicPolicy.set_network(self,network)            
        self.fabric_policy = fabric_policy

        @singleton
        class egress_policy(DynamicPolicy):
            def set_network(self,network):
                if not self.vmap is None:
                    self.policy = self.vmap.egress_policy()
                    DynamicPolicy.set_network(self,network)            
        self.egress_policy = egress_policy
   
    def make_vmap(self):
        mapping = vmap()
        port_no = 1
        for loc in self.kept_topology.egress_locations():
            mapping.d2u[Location(self.name, port_no)] = \
                [Location(loc.switch, loc.port_no)]
            mapping.u2d[Location(loc.switch, loc.port_no)] = \
                Location(self.name, port_no)
            port_no += 1
        return mapping

    def set_network(self,network):
        self.underlying = network
        self.derived = self.DerivedNetwork(self.underlying)
        self.kept_topology = self.underlying.topology
        if self.from_switches:
            tmp = network.topology.filter_nodes(self.from_switches)
            if tmp:
                self.kept_topology = tmp
        self.derived.topology = self.underlying.topology.copy()
        super(merge,self).set_network(network)
        relink = {}
        if len(self.from_switches) == 0:
            self.derived.topology = Topology()
            self.derived.inherited.clear()
        else:
            for switch in self.from_switches:
                try:
                    ports = self.derived.topology.node[switch]['ports']
                    for port_no,port in ports.items():
                        if not (port is None or port.linked_to.switch in self.from_switches):
                            relink[self.vmap.u2d[Location(switch,port_no)]] = port.linked_to
                except:
                    pass
                try:
                    self.derived.topology.remove_node(switch)
                    self.derived.inherited.remove(switch)
                except:
                    pass

        # ADD THE DERIVED SWITCH
        for u in self.vmap.d2u:
            port = Port(u.port_no)
            try:
                self.derived.topology.node[u.switch]['ports'][u.port_no] = port 
            except KeyError:
                self.derived.topology.add_node(u.switch, ports={u.port_no: port})
        
        # SET UP LINKS BETWEEN DERIVED SWITCH AND REMAINING UNDERLYING SWITCHES
        for u,v in relink.items():
            self.derived.topology.add_link(u,v)

        print "------- Underlying (to Merge) Topology ---------"
        print self.underlying.topology
        print "------- Derived (Merged) Topology ---------"
        print self.derived.topology

                        
transform = merge()
