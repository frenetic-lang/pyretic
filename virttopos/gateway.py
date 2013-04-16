
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

##############################################################################################################################
# TO TEST EXAMPLE                                                                                                            #
# -------------------------------------------------------------------                                                        #
# start mininet:  pyretic/mininet.sh --topo=gateway                                                                          #
# run controller: pox.py --no-cli pyretic/examples/gateway.py                                                                #
# test:           pingall                                                                                                    #
##############################################################################################################################

from frenetic.lib import *

class GatewayVirt(Virtualizer):
    def __init__(self, redo):
        self.ingress_policy = if_(match(switch=1),
               # At physical gateway, ethernet side. Pretend we are switch 1000.
               match(at=None, inport=1)[push(vswitch=1000, vinport=1)] |
               match(at=None, inport=2)[push(vswitch=1000, vinport=2)] |
                
               # At physical gateway, imaginary side close to ethernet.
               match(at="vswitch 1000, vinport 3")[push(vswitch=1000, vinport=3) >> pop("at")] |
               
               # At physical gateway, imaginary gateway.
               match(at="vswitch 1001, vinport 1")[push(vswitch=1001, vinport=1) >> pop("at")] |
               match(at="vswitch 1001, vinport 2")[push(vswitch=1001, vinport=2) >> pop("at")] |
                
               # At physical gateway, imaginary side close to ip.
               match(at="vswitch 1002, vinport 3")[push(vswitch=1002, vinport=3) >> pop("at")] |
                
               # At physical gateway, ip side. Pretend we are switch 1002.
               match(at=None, inport=3)[push(vswitch=1002, vinport=1)] |
               match(at=None, inport=4)[push(vswitch=1002, vinport=2)],
            
               copy(vswitch="switch", vinport="inport"))

        self.fabric_policy = parallel([
            # Destined to ethernet side
            match(vswitch=1000, voutport=1)[pop_vheaders >> fwd(1)],
            match(vswitch=1000, voutport=2)[pop_vheaders >> fwd(2)],
            # If we are destined to a fake switch, lets push another header that
            # says which fake switch we are at.
            match(vswitch=1000, voutport=3)[push(at="vswitch 1001, vinport 1") >> pop_vheaders >> recurse(redo)],
            match(vswitch=1001, voutport=1)[push(at="vswitch 1000, vinport 3") >> pop_vheaders >> recurse(redo)],
            match(vswitch=1001, voutport=2)[push(at="vswitch 1002, vinport 3") >> pop_vheaders >> recurse(redo)],
            match(vswitch=1002, voutport=3)[push(at="vswitch 1001, vinport 2") >> pop_vheaders >> recurse(redo)],
            # Destined to ip side
            match(vswitch=1002, voutport=1)[pop_vheaders >> fwd(3)],
            match(vswitch=1002, voutport=2)[pop_vheaders >> fwd(4)],
            (~(match(vswitch=1000) | match(vswitch=1001) | match(vswitch=1002)))[virtual_to_physical]
        ])

        self.egress_policy = passthrough

        def transformer(network):
            vtopo = network.topology.copy()
            n = Network(None)
            n.init_events()
            n.topology = vtopo
            n.backend = network.backend  # UNSURE IF THIS IS PRINCIPLED OR A HACK

            try:
                # REMOVE PHYSICAL SWITCHES ONTO WHICH VIRTUAL SWITCHES WILL BE MAPPED
                vtopo.remove_node(1)

                # ADD VIRTUAL SWITCHES
                vtopo.add_node(1000, ports={i: Port(i) for i in range(1,3+1)})
                vtopo.add_node(1001, ports={i: Port(1) for i in range(1,2+1)})
                vtopo.add_node(1002, ports={i: Port(i) for i in range(1,3+1)})

                # WIRE UP VIRTUAL SWITCHES
                # compare to notations in mininet/extra-topos.py GatewayTopo / PGatewayTopo
                vtopo.add_link(Location(2,1),Location(1000,1))    # {link(s2[1])} == {s1[1]} == s1000[1] 
                vtopo.add_link(Location(3,1),Location(1000,2))    # {link(s3[1])} == {s1[2]} == s1000[2] 
                vtopo.add_link(Location(1001,1),Location(1000,3)) # internal  s1001[1] -- s1000[3]
                vtopo.add_link(Location(5,1),Location(1002,1))    # {link(s5[1])} == {s1[3]} == s1002[1] 
                vtopo.add_link(Location(6,1),Location(1002,2))    # {link(s6[1])} == {s1[4]} == s1002[2] 
                vtopo.add_link(Location(1001,2),Location(1002,3)) # internal  s1001[2] -- s1002[3] 
            except:
                pass
            
            print "--- Underlying Topology ------"
            print network.topology
            print "----Abstracted Topology ------"
            print vtopo

            return n

        self.transform_network = functools.partial(transform_network, transformer)

