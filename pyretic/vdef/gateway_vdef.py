
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

class gateway_vdef(vdef):
    def __init__(self, redo):
        super(gateway_vdef,self).__init__()

        def push_vloc(switch,inport):
            return push(vswitch=switch,vinport=inport,voutport=-1)

        self.ingress_policy = if_(match(switch=1),
               push(vtag='ingress') >> (                                
               # At physical gateway, ethernet side. Pretend we are switch 1000.
               match(at=None, inport=1)[push_vloc(1000,1)] +
               match(at=None, inport=2)[push_vloc(1000,2)] +
               # At physical gateway, imaginary side close to ethernet.
               match(at="vswitch 1000, vinport 3")[push_vloc(1000,3) >> pop("at")] +
               # At physical gateway, imaginary gateway.
               match(at="vswitch 1001, vinport 1")[push_vloc(1001,1) >> pop("at")] +
               match(at="vswitch 1001, vinport 2")[push_vloc(1001,2) >> pop("at")] +
               # At physical gateway, imaginary side close to ip.
               match(at="vswitch 1002, vinport 3")[push_vloc(1002,3) >> pop("at")] +
               # At physical gateway, ip side. Pretend we are switch 1002.
               match(at=None, inport=3)[push_vloc(1002,1)] +
               match(at=None, inport=4)[push_vloc(1002,2)] ),
               passthrough)

        self.fabric_policy = (
            # Destined to ethernet side
            match(vswitch=1000, voutport=1)[fwd(1)] +
            match(vswitch=1000, voutport=2)[fwd(2)] +
            # If we are destined to a fake switch, 
            # push another header that says which fake switch we are at.
            match(vswitch=1000, voutport=3)[push(at="vswitch 1001, vinport 1")] +
            match(vswitch=1001, voutport=1)[push(at="vswitch 1000, vinport 3")] +
            match(vswitch=1001, voutport=2)[push(at="vswitch 1002, vinport 3")] +
            match(vswitch=1002, voutport=3)[push(at="vswitch 1001, vinport 2")] +
            # Destined to ip side
            match(vswitch=1002, voutport=1)[fwd(3)] +
            match(vswitch=1002, voutport=2)[fwd(4)] )
            
        self.egress_policy = pop_vheaders >> \
            if_(match(at=None), passthrough, recurse(redo))

    def make_vmap(self):
        mapping = vmap()
        topo = self.underlying.topology.copy()
        try:
            topo.remove_node(1)

            for u, attrs in topo.nodes(data=True):
                ports = attrs['ports']
                for port in ports:
                    l = Location(u,port)
                    mapping.d2u[l] = [l]
        except:
            pass
        mapping.d2u[Location(1000,1)] = [Location(2,1)]
        mapping.d2u[Location(1000,2)] = [Location(3,1)]
        mapping.d2u[Location(1000,3)] = [Location(1,None)]
        mapping.d2u[Location(1001,1)] = [Location(1,None)]
        mapping.d2u[Location(1001,2)] = [Location(1,None)]
        mapping.d2u[Location(1002,1)] = [Location(1,None)]
        mapping.d2u[Location(1002,2)] = [Location(5,1)]
        mapping.d2u[Location(1002,3)] = [Location(6,1)]
        return mapping

    def set_network(self,network):
        self.underlying = network
        self.derived = self.DerivedNetwork(self.underlying)
        self.derived.topology = self.underlying.topology.copy()
        try:
            # REMOVE PHYSICAL SWITCHES ONTO WHICH VIRTUAL SWITCHES WILL BE MAPPED
            self.derived.topology.remove_node(1)
            self.derived.inherited.remove(1)
            
            # ADD VIRTUAL SWITCHES
            self.derived.topology.add_node(1000, ports={i: Port(i) for i in range(1,3+1)})
            self.derived.topology.add_node(1001, ports={i: Port(1) for i in range(1,2+1)})
            self.derived.topology.add_node(1002, ports={i: Port(i) for i in range(1,3+1)})

            # WIRE UP VIRTUAL SWITCHES
            # compare to notations in mininet/extra-topos.py GatewayTopo / PGatewayTopo
            self.derived.topology.add_link(Location(2,1),Location(1000,1))    # {link(s2[1])} == {s1[1]} == s1000[1] 
            self.derived.topology.add_link(Location(3,1),Location(1000,2))    # {link(s3[1])} == {s1[2]} == s1000[2] 
            self.derived.topology.add_link(Location(1001,1),Location(1000,3)) # internal  s1001[1] -- s1000[3]
            self.derived.topology.add_link(Location(5,1),Location(1002,1))    # {link(s5[1])} == {s1[3]} == s1002[1] 
            self.derived.topology.add_link(Location(6,1),Location(1002,2))    # {link(s6[1])} == {s1[4]} == s1002[2] 
            self.derived.topology.add_link(Location(1001,2),Location(1002,3)) # internal  s1001[2] -- s1002[3] 
        except:
            self.derived.topology = Topology()
        super(gateway_vdef,self).set_network(network)
        print "--- Underlying Gateway Topology ------"
        print self.underlying.topology
        print "--- Derived Gateway Topology ------"
        print self.derived.topology
