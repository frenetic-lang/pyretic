
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

from examples.learning_switch import learning_switch
from examples.repeater import repeater
from examples.hub import hub


class GatewayVirt(Virtualizer):
    def __init__(self, redo):
        self.ingress_policy = if_(match(switch=1),
               # At physical gateway, ethernet side. Pretend we are switch 1000.
               match(at=None, inport=1)[push(vswitch=1000, vinport=1)] |
               match(at=None, inport=2)[push(vswitch=1000, vinport=2)] |
                
               # At physical gateway, imaginary side close to ethernet.
               match(at="vswitch 1000, vinport 3")[push(vswitch=1000, vinport=3) >> pop(["at"])] |
               
               # At physical gateway, imaginary gateway.
               match(at="vswitch 1001, vinport 1")[push(vswitch=1001, vinport=1) >> pop(["at"])] |
               match(at="vswitch 1001, vinport 2")[push(vswitch=1001, vinport=2) >> pop(["at"])] |
                
               # At physical gateway, imaginary side close to ip.
               match(at="vswitch 1002, vinport 3")[push(vswitch=1002, vinport=3) >> pop(["at"])] |
                
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
            match(vswitch=1000, voutport=3)[push(at="vswitch 1001, vinport 1") >> pop_vheaders >> redo],
            match(vswitch=1001, voutport=1)[push(at="vswitch 1000, vinport 3") >> pop_vheaders >> redo],
            match(vswitch=1001, voutport=2)[push(at="vswitch 1002, vinport 3") >> pop_vheaders >> redo],
            match(vswitch=1002, voutport=3)[push(at="vswitch 1001, vinport 2") >> pop_vheaders >> redo],
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

            try:
                vtopo.remove_node(1)

                vtopo.add_node(1000, ports={1: Port(1),
                                            2: Port(2),
                                            3: Port(3)})
                vtopo.add_node(1001, ports={1: Port(1),
                                            2: Port(2)})
                vtopo.add_node(1002, ports={1: Port(1),
                                            2: Port(2),
                                            3: Port(3)})

                del vtopo.node[6]["ports"][2]
                
                vtopo.add_edge(3, 1000, {3: 3, 1000: 1})

                vtopo.node[3]['ports'][3].linked_to = vtopo.node[1000]['ports'][1]
                vtopo.node[1000]['ports'][1].linked_to = vtopo.node[3]['ports'][3]
                
                vtopo.add_edge(4, 1000, {4: 2, 1000: 2})

                vtopo.node[4]['ports'][2].linked_to = vtopo.node[1000]['ports'][2]
                vtopo.node[1000]['ports'][2].linked_to = vtopo.node[4]['ports'][2]
                
                vtopo.add_edge(1000, 1001, {1000: 3, 1001: 1})
                
                vtopo.node[1000]['ports'][3].linked_to = vtopo.node[1001]['ports'][1]
                vtopo.node[1001]['ports'][1].linked_to = vtopo.node[1000]['ports'][3]
                
                vtopo.add_edge(1001, 1002, {1001: 2, 1002: 3})
                
                vtopo.node[1001]['ports'][2].linked_to = vtopo.node[1002]['ports'][3]
                vtopo.node[1002]['ports'][3].linked_to = vtopo.node[1001]['ports'][2]
                
                vtopo.add_edge(5, 1002, {5: 2, 1002: 1})

                vtopo.node[5]['ports'][2].linked_to = vtopo.node[1002]['ports'][1]
                vtopo.node[1002]['ports'][1].linked_to = vtopo.node[5]['ports'][2]
                
                vtopo.add_edge(7, 1002, {7: 3, 1002: 2})

                vtopo.node[7]['ports'][3].linked_to = vtopo.node[1002]['ports'][2]
                vtopo.node[1002]['ports'][2].linked_to = vtopo.node[7]['ports'][3]
            except:
                pass
            
            return n

        self.transform_network = functools.partial(transform_network, transformer)

    def attach(self, network):
        pass

    def update_network(self, network):
        pass

    def detach(self, network):
        pass


def gateway_example():
    return ((match(switch=2) | match(switch=3) | match(switch=4) | match(switch=1000))[ hub ] |
            match(switch=1001)[ repeater  ] |
            (match(switch=5) | match(switch=6) | match(switch=7) | match(switch=1002))[ hub ])


@dynamic
def vgateway_example(self):
    ge = gateway_example()
    self.policy = virtualize(ge, GatewayVirt(Recurse(self)))


def main():
    return vgateway_example()

