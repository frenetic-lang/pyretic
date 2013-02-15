
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
from examples.hub import hub
from examples.arp import arp, ARP
from examples.load_balancer import static_lb, lb
from examples.firewall import fw
from virttopos.bfs import BFS

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
            n.backend = network.backend  # UNSURE IF THIS IS PRINCIPLED OR A HACK

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

                
                vtopo.add_edge(3, 1000, {3: 3, 1000: 1})

                vtopo.node[3]['ports'][3].linked_to = Location(1000,1)
                vtopo.node[1000]['ports'][1].linked_to = Location(3,3)
                
                vtopo.add_edge(4, 1000, {4: 2, 1000: 2})

                vtopo.node[4]['ports'][2].linked_to = Location(1000,2)
                vtopo.node[1000]['ports'][2].linked_to = Location(4,2)
                
                vtopo.add_edge(1000, 1001, {1000: 3, 1001: 1})
                
                vtopo.node[1000]['ports'][3].linked_to = Location(1001,1)
                vtopo.node[1001]['ports'][1].linked_to = Location(1000,3)
                
                vtopo.add_edge(1001, 1002, {1001: 2, 1002: 3})
                
                vtopo.node[1001]['ports'][2].linked_to = Location(1002,3)
                vtopo.node[1002]['ports'][3].linked_to = Location(1001,2)
                
                vtopo.add_edge(5, 1002, {5: 2, 1002: 1})

                vtopo.node[5]['ports'][2].linked_to = Location(1002,1)
                vtopo.node[1002]['ports'][1].linked_to = Location(5,2)
                
                vtopo.add_edge(7, 1002, {7: 3, 1002: 2})

                vtopo.node[7]['ports'][3].linked_to = Location(2002,2)
                vtopo.node[1002]['ports'][2].linked_to = Location(7,3)
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



def in_(l):
    return union([match(switch=s) for s in l])

def gateway_example(num_clients,num_servers):

    ethernet = [2,3,4,1000]
    ip_core  = [5,6,7,1002]
    gateway  = [1001]

    gw_mac = MAC('AA:AA:AA:AA:AA:AA')

    eth_prefix = '10.0.0.'
    ip_prefix  = '10.0.1.'

    eth_macs = { IP(eth_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i)) \
                      for i in range(1,1+num_clients) }
    eth_macs.update({IP(eth_prefix+'1') : gw_mac})

    ip_macs = { IP(ip_prefix+str(i+1)) : MAC('00:00:00:00:00:0'+str(i+num_clients)) \
                        for i in range(1,1+num_servers) }
    ip_macs.update({IP(ip_prefix +'1') : gw_mac})
    
    all_macs = dict(eth_macs.items() + ip_macs.items())

    def rewrite_dstmac(tm):
        return parallel([match(dstip=k)[pop('dstmac') >> push(dstmac=v)] for k,v in tm.items()])

    def rewrite_srcmac():
        return pop('srcmac') >> push(srcmac=gw_mac)
    
    def rewrite_macs(tm):
        return rewrite_dstmac(tm) >> rewrite_srcmac()

    def fix_dstmac():
        fix = parallel([(match(dstip=k) & ~match(dstmac=v))[pop('dstmac') >> push(dstmac=v)] for k,v in ip_macs.items()])
        pas = intersect([~(match(dstip=k) & ~match(dstmac=v)) for k,v in ip_macs.items()])[passthrough]
        return fix | pas

    public_ip = '10.0.1.100'
    fake_mac = 'BB:BB:BB:BB:BB:BB'

    all_macs.update({public_ip : fake_mac})

    R = [ip_prefix + str(i) for i in range(2, 2+num_servers)]
    H = {eth_prefix + str(i) : 0 for i in range(2,2+num_clients)}
    W = {(c,public_ip) for c in H.keys()}
    from_client = union([match(srcip=c) for c in H.keys()])

    eth_pol = if_(ARP,arp(eth_macs),learning_switch())
    alb =     dynamic(lb)(public_ip,R,H) >> fix_dstmac() 
    afw =     dynamic(fw)(W) 
    ip_pol =  if_(from_client, afw >> alb, alb >> afw) >> learning_switch() 
    ip_pol =  virtualize(ip_pol,BFS(ip_core))
   
##   CIDR MATCHING CURRENTLY NOT WORKING
#    eth_to_ip = match(inport=1,dstip='10.0.0.0/24')
#    ip_to_eth = match(inport=2,dstip='10.0.1.0/24')

    to_eth = union([ match(dstip='10.0.0.'+str(i)) for i in range(2,2+num_clients) ])
    to_ip  = union([ match(dstip='10.0.1.'+str(i)) for i in range(2,2+num_servers) ])

    eth_to_ip = match(inport=1) & (to_ip | match(dstip=public_ip) )
    ip_to_eth = match(inport=2) & (to_eth)

    gw = if_(ARP,arp(eth_macs), 
             rewrite_macs(all_macs) >> 
             ( eth_to_ip[fwd(2)] | ip_to_eth[fwd(1)] ))

    return in_(ethernet)[ pprint('->eth') >> eth_pol >> pprint('eth->') ]  | \
        in_(gateway)[ pprint('->gw') >> gw >> pprint('gw->') ] | \
        in_(ip_core)[ pprint('->ip') >> ip_pol >> pprint('ip->') ]
            
@dynamic
def vgateway_example(self,num_clients,num_servers):
    ge = gateway_example(num_clients,num_servers)
    self.policy = virtualize(ge, GatewayVirt(Recurse(self)))


def main(clients='3',servers='3'):
    clients = int(clients)
    servers = int(servers)
    #return gateway_example(clients,servers)
    return vgateway_example(clients,servers)

