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

# This module is designed for import *.
from frenetic import generators as gs
from frenetic.network import *
from frenetic.netcore import *
from frenetic import util
from frenetic.util import singleton, Data

from networkx import nx

import itertools
from collections import Counter

################################################################################
# Network
################################################################################

def egress_points(topo):
    for sw in topo.nodes():
        ports = egress_ports(topo, sw)
        if ports:
            yield sw, ports
    
def egress_ports(topo, sw):
    attrs = topo.node[sw]
    all_ports = attrs["ports"]
    non_egress_ports = set()
    for attrs in topo[sw].itervalues():
        non_egress_ports.add(attrs[sw])
    return all_ports - non_egress_ports

class flood(Policy):
    def __init__(self, network):
        self.network = network
        @network._topology.notify
        def handle(topo):
            self.mst = nx.minimum_spanning_tree(topo)
    
    def __repr__(self):
        return "flood %s" % self.network
    
    def eval(self, packet):
        if packet.switch in self.network.topology.nodes():
            ports = set()
            ports.update(egress_ports(self.network.topology, packet.switch))
            for sw in self.mst.neighbors(packet.switch):
                port = self.mst[packet.switch][sw][packet.switch]
                ports.add(port)
            packets = [packet._push(outport=port)
                       for port in ports if port != packet.inport]
            return Counter(packets)
        else:
            return Counter()

class Network(object):
    def __init__(self):
        self._policy = gs.Behavior(drop)
        self._sub_policies = {}

    @classmethod
    def clone(cls, network):
        self = cls()
        self.inherit_events(network)
        return self
        
    @classmethod
    def fork(cls, network):
        self = cls.clone(network)
        self.connect(network)
        return self

    def connect(self, network):
        @self._policy.notify
        def change(policy):
            network.install_sub_policy(self, policy)
        
    #
    
    def init_events(self):
        self._topology = gs.Behavior(nx.Graph())                
        self.events = ["switch_joins", "switch_parts",
                       "port_ups", "port_downs",
                       "link_ups", "link_downs"]
        for event in self.events:
            e = gs.Event()
            setattr(self, event, e)
            e.notify(getattr(self, "_handle_%s" % event))

    def inherit_events(self, network):
        self._topology = network._topology
        self.events = network.events
        for event in network.events:
            setattr(self, event, getattr(network, event))

    #

    topology = gs.Behavior.property("_topology")
    
    @property
    def topology_changes(self):
        return iter(self._topology)

    #
        
    def install_policy(self, policy):
        self.install_sub_policy(self, policy)
        
    def install_sub_policy(self, id, policy):
        self._sub_policies[id] = policy
        self._policy.set(self._aggregate_policy())

    @property
    @util.cached
    def flood(self):
        return flood(self)

    def install_flood(self):
        self.install_policy(self.flood)
        
    @property
    def policy(self):
        return self._policy.get()
        
    @property
    def policy_changes(self):
        return iter(self._policy)
    
    def _aggregate_policy(self):
        pol = drop
        for policy in self._sub_policies.itervalues():
            pol |= policy
        return pol

    #
    # Events
    #
           
    def _handle_switch_joins(self, switch):
        self.topology.add_node(switch, ports=set())
        self._topology.signal_mutation()
        
    def _handle_switch_parts(self, switch):
        self.topology.remove_node(switch)
        self._topology.signal_mutation()
        
    def _handle_port_ups(self, (switch, port)):
        self.topology.node[switch]["ports"].add(port)
        self._topology.signal_mutation()

    def _handle_port_downs(self, (switch, port)):
        self.topology.node[switch]["ports"].remove(port)
        self._topology.signal_mutation()
        
    def _handle_link_ups(self, (s1, p1, s2, p2)):
        self.topology.add_edge(s1, s2, {s1: p1, s2: p2})
        self._topology.signal_mutation()
        
    def _handle_link_downs(self, (s1, p1, s2, p2)):
        self.topology.remove_edge(s1, s2)
        self._topology.signal_mutation()

    #
    # Policies
    #

    def __ior__(self, policy):
        self.install_policy(self._sub_policies[self] | policy)
        return self
        
    def __iand__(self, policy):
        self.install_policy(self._sub_policies[self] & policy)
        return self

    def __isub__(self, policy):
        self.install_policy(self._sub_policies[self] - policy)
        return self

    def __irshift__(self, policy):
        self.install_policy(self._sub_policies[self] >> policy)
        return self

################################################################################
# Helpers
################################################################################

def query(network, pred=all_packets, fields=(), time=None):
    b = Bucket(fields, time)
    sub_net = Network.fork(network)
    sub_net.install_policy(pred & fwd(b))
    return b

################################################################################
# Isolation
################################################################################

class isolate_policy(Policy, Data("itag policy ingress_predicate egress_predicate")):
    def __repr__(self):
        return "isolate_policy %s\n%s" % (self.itag, util.repr_plus(["POLICY",
                                                                     self.policy,
                                                                     "INGRESS PREDICATE",
                                                                     self.ingress_predicate,
                                                                     "EGRESS PREDICATE",
                                                                     self.egress_predicate]))
    
    def eval(self, packet):
        pol = (if_(match(itag=None) & self.ingress_predicate,
                   push(itag=self.itag)) >>
               (match(itag=self.itag) &
                (self.policy >>
                 if_(is_bucket("outport") | self.egress_predicate, pop("itag")))))
        return pol.eval(packet)
    
class INetwork(Network):
    def __init__(self):
        super(INetwork, self).__init__()
        
        self._ipolicy = gs.Behavior(drop)
        self._ingress_predicate = gs.Behavior(all_packets)
        self._egress_predicate = gs.Behavior(no_packets)
        
        for b in [self._policy, self._ingress_predicate, self._egress_predicate]:
            b.notify(self._handle_changes)
        
    ingress_predicate = gs.Behavior.property("_ingress_predicate")
    egress_predicate = gs.Behavior.property("_egress_predicate")
    
    def connect(self, network):
        """different than base"""
        @self._ipolicy.notify
        def change(policy):
            network.install_sub_policy(self, policy)

    def sync_with_topology(self):
        @self._topology.notify
        def handle(topology):
            self.egress_predicate = union(match(switch=sw) &
                                            union(match(outport=port) for port in ports)
                                            for sw, ports in egress_points(topology))
            
    def _handle_changes(self, item):
        self._ipolicy.set(self._aggregate_ipolicy())

    def _aggregate_ipolicy(self):
        return isolate_policy(id(self),
                              self.policy,
                              self.ingress_predicate,
                              self.egress_predicate)

    @property
    def ipolicy(self):
        return self._ipolicy.get()
        
    @property
    def ipolicy_changes(self):
        return iter(self._ipolicy)

################################################################################
# Virtualization policies 
################################################################################

class physical_to_virtual(Policy, Data("vtag")):
    def __repr__(self):
        return "physical_to_virtual %s" % self.vtag
        
    def eval(self, packet):
        pol = (push(vtag=self.vtag) >> copy(voutport="outport",
                                            vswitch="switch",
                                            vinport="inport"))
        return pol.eval(packet)

@singleton
class virtual_to_physical(Policy):
    def __repr__(self):
        return "virtual_to_physical"
        
    def eval(self, packet):
         pol = (pop("switch", "inport", "outport", "vtag") >>
                copy(outport="voutport", switch="vswitch", inport="vinport"))
         return pol.eval(packet)

@singleton
class pop_vheaders(Policy):
    def __repr__(self):
        return "pop_vheaders"
        
    def eval(self, packet):
        pol = pop("vswitch", "vinport", "voutport", "vtag")
        return pol.eval(packet)

        
class virtualize_policy(Policy, Data("vtag policy ingress_policy physical_policy_fn query_policy_fn")):
    def __repr__(self):
        return "virtualize_policy %s\n%s" % (self.vtag, util.repr_plus(["POLICY",
                                                                        self.policy,
                                                                        "INGRESS POLICY", 
                                                                        self.ingress_policy,
                                                                        "PHYSICAL POLICY", 
                                                                        self.physical_policy_fn(self),
                                                                        "QUERY POLICY",
                                                                        self.query_policy_fn(self)]))

    def eval(self, packet):
        # if the vlan isnt set, then we need to find out the v* headers.
        pol = (if_(~match(vtag=self.vtag), 
                    (self.ingress_policy >> # set vswitch and vinport
                     # now make the virtualization transparent to the tenant's policy to get the outport
                     copy(switch="vswitch", inport="vinport") >>
                     self.policy >>
                     physical_to_virtual(self.vtag)))
                # Pipe the packet with appropriate v* headers to the physical policy for processing
                >> if_(is_bucket("voutport"),
                       self.query_policy_fn(self),
                       self.physical_policy_fn(self)))
        return pol.eval(packet)
        
def add_nodes_from_vmap(vmap, graph):
    d = {}
    for sw, port in vmap:
        sw = lift_fixedwidth("switch", sw)
        port = lift_fixedwidth("inport", port)
        d.setdefault(sw, set()).add(port)
    for sw, ports in d.iteritems():
        graph.add_node(sw, ports=ports)
    
def vmap_to_ingress_policy(vmap):
    ingress_policy = parallel(push(vswitch=vsw, vinport=vp) &
                            union(match(switch=sw, inport=p) for (sw, p) in switches)
                            for ((vsw, vp), switches) in vmap.iteritems())
    return ingress_policy

def vmap_to_egress_policy(vmap):
    matches_egress = []
    valid_match_egress = []
    for ((vsw, vp), switches) in vmap.iteritems():
        switch_pred = union(match(switch=sw, outport=p) for (sw, p) in switches)
        matches_egress.append(switch_pred)
        valid_match_egress.append(match(vswitch=vsw, voutport=vp) & switch_pred)
    return if_(union(matches_egress), union(valid_match_egress) & pop_vheaders, passthrough)
        
class VNetwork(Network):
    def __init__(self):
        super(VNetwork, self).__init__()
        
        self._vpolicy = gs.Behavior(drop)
        self._ingress_policy = gs.Behavior(drop)
        self._physical_policy = gs.Behavior(drop)
        self._egress_policy = gs.Behavior(no_packets)
        
        for b in [self._policy, self._ingress_policy,
                  self._physical_policy, self._egress_policy]:
            b.notify(self._handle_changes)

    @property
    def vpolicy(self):
        return self._vpolicy.get()
    
    ingress_policy = gs.Behavior.property("_ingress_policy")
    physical_policy = gs.Behavior.property("_physical_policy")
    egress_policy = gs.Behavior.property("_egress_policy")

    @classmethod
    def fork(cls, network):
        """different than base"""
        self = cls()
        self.init_events()
        self.connect(network)
        return self

    def connect(self, network):
        """different than base"""
        @self._vpolicy.notify
        def change(policy):
            network.install_sub_policy(self, policy)

    def from_vmap(self, vmap):
        self.ingress_policy = vmap_to_ingress_policy(vmap)
        self.egress_policy = vmap_to_egress_policy(vmap)

    def _handle_changes(self, item):
        self._vpolicy.set(self._aggregate_vpolicy())

    def _aggregate_vpolicy(self):
        if isinstance(self.physical_policy, Policy):
            physical_policy = lambda rev: self.physical_policy
        else:
            assert callable(self.physical_policy), "must be a function or policy"
            physical_policy = self.physical_policy
            
        return virtualize_policy(id(self),
                                 self.policy,
                                 self.ingress_policy,
                                 lambda rev: physical_policy(rev) >> self.egress_policy,
                                 lambda rev: virtual_to_physical)
    @property
    def vpolicy_changes(self):
        return iter(self._vpolicy)


################################################################################
# 
################################################################################

class ComposedNetwork(object):
    def __init__(self, *args):
        self._networks = args
        self._sub_policies = {}
        self._cpolicy = gs.Behavior(drop)

        for network in self._networks:
            network.connect(self)
        
        super(ComposedNetwork, self).__init__()

    def connect(self, network):
        """different than base"""
        @self._cpolicy.notify
        def change(policy):
            network.install_sub_policy(self, policy)

    def install_sub_policy(self, id, policy):
        self._sub_policies[id] = policy
        self._cpolicy.set(self._aggregate_policy())

    def _aggregate_policy(self):
        pol = passthrough
        for network in self._networks:
            policy = self._sub_policies.get(network, passthrough)
            pol = pol >> policy
        return pol

    @property
    def cpolicy(self):
        return self._cpolicy.get()
