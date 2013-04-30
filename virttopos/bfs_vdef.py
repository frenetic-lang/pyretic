
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


class BFS_vdef(object):
    def __init__(self,name=1,from_switches=[]):
        self.from_switches = from_switches
        self.vmap = None
        self.derived_topology = None
        self.underlying_topology = None
        self.kept_topology = None

    def make_vmap(self):
        mapping = vmap()
        port_no = 1
        for loc in self.kept_topology.egress_locations():
            mapping.d2u[Location(1, port_no)] = \
                [Location(loc.switch, loc.port_no)]
            mapping.u2d[Location(loc.switch, loc.port_no)] = \
                Location(1, port_no)
            port_no += 1
        return mapping

    def set_network(self,network):
        self.underlying_topology = network.topology
        self.kept_topology = self.underlying_topology
        if self.from_switches:
            tmp = network.topology.filter_nodes(self.from_switches)
            if tmp:
                self.kept_topology = tmp
        self.vmap = self.make_vmap()
        self.derived_topology = self.underlying_topology.copy()
        relink = {}
        if len(self.from_switches) == 0:
            self.derived_topology = Topology()
        else:
            for switch in self.from_switches:
                try:
                    ports = self.derived_topology.node[switch]['ports']
                    for port_no,port in ports.items():
                        if not (port is None or port.linked_to.switch in self.from_switches):
                            relink[self.vmap.u2d[Location(switch,port_no)]] = port.linked_to
                except:
                    pass
                try:
                    self.derived_topology.remove_node(switch)
                except:
                    pass

        # ADD THE DERIVED SWITCH
        for u in self.vmap.d2u:
            port = Port(u.port_no)
            try:
                self.derived_topology.node[u.switch]['ports'][u.port_no] = port 
            except KeyError:
                self.derived_topology.add_node(u.switch, ports={u.port_no: port})
        
        # SET UP LINKS BETWEEN DERIVED SWITCH AND REMAINING UNDERLYING SWITCHES
        for u,v in relink.items():
            self.derived_topology.add_link(u,v)

    def derive_network(self):
        """produces a new network object w/ transformed topology, also updates underlying_topology and vmap for use by ingress, fabric and egress"""
        vnetwork = Network()
        vnetwork.topology = self.derived_topology

        print "------- Underlying BFS Topology ---------"
        print self.underlying_topology
        print "------- Derived BFS Topology ---------"
        print self.derived_topology

        return vnetwork
                
    @NetworkDerivedPolicyPropertyFrom
    def ingress_policy(self, network):
        return self.vmap.ingress_policy()

    @NetworkDerivedPolicyPropertyFrom
    def fabric_policy(self, network): 
        return self.vmap.shortest_path_fabric_policy(self.underlying_topology)

    @NetworkDerivedPolicyPropertyFrom
    def egress_policy(self, network):
        return self.vmap.egress_policy()

        
transform = BFS_vdef()
