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

from networkx import nx

import itertools

################################################################################
# Network
################################################################################

class Network(object):
    def __init__(self):
        self.policy_b = gs.Behavior(drop)
        self.sub_policies = {}

    #
        
    def init_events(self):
        self.topology_b = gs.Behavior(nx.Graph())                
        self.events = ["switch_joins", "switch_parts",
                       "port_ups", "port_downs",
                       "link_ups", "link_downs"]
        for event in self.events:
            e = gs.Event()
            setattr(self, event, e)
            e.notify(getattr(self, "_handle_%s" % event))

    def inherit_events(self, network):
        self.topology_b = network.topology_b
        self.events = network.events
        for event in network.events:
            setattr(self, event, getattr(network, event))

    @property
    def topology(self):
        return self.topology_b.get()
    
    @property
    def topology_changes(self):
        return itertools.chain([self.topology], iter(self.topology_b))

    #
        
    def install_policy(self, policy):
        self.sub_policies[self] = policy
        self.policy_b.set(self._aggregate_policy())

    @property
    def policy_changes(self):
        return itertools.chain([self.policy], iter(self.policy_b))

    @property
    def policy(self):
        return self.policy_b.get()
        
    def install_sub_policies(self, sub_gen):
        def adder():
            for policy in sub_gen:
                self.sub_policies[sub_gen] = policy
                self.policy_b.set(self._aggregate_policy())
        gs.run(adder)
    
    def _aggregate_policy(self):
        pol = drop
        for policy in self.sub_policies.itervalues():
            pol |= policy
        return pol

    #
    # Events
    #
           
    def _handle_switch_joins(self, switch):
        self.topology.add_node(switch, ports=set())
        self.topology_b.signal_mutation()
        
    def _handle_switch_parts(self, switch):
        self.topology.remove_node(switch)
        self.topology_b.signal_mutation()
        
    def _handle_port_ups(self, (switch, port)):
        self.topology.node[switch]["ports"].add(port)
        self.topology_b.signal_mutation()

    def _handle_port_downs(self, (switch, port)):
        self.topology.node[switch]["ports"].remove(port)
        self.topology_b.signal_mutation()
        
    def _handle_link_ups(self, (s1, p1, s2, p2)):
        self.topology.add_edge(s1, s2, p1=p1, p2=p2)
        self.topology_b.signal_mutation()
        
    def _handle_link_downs(self, (s1, p1, s2, p2)):
        self.topology.remove_edge(s1, s2)
        self.topology_b.signal_mutation()

    #
    # Policies
    #

    def __ior__(self, policy):
        self.install_policy(self.policy | policy)
        return self
        
    def __iand__(self, policy):
        self.install_policy(self.policy & policy)
        return self

    def __isub__(self, policy):
        self.install_policy(self.policy - policy)
        return self

    def __irshift__(self, policy):
        self.install_policy(self.policy >> policy)
        return self

################################################################################
# Network helpers
################################################################################

def flood_splitter(sw_to_ports):
    flood_pol = drop
    for vsw, vports in sw_to_ports.iteritems():
        pol = drop
        for vport in vports:
            vports_ = list(vports)
            vports_.remove(vport)
            vfwds = or_pol(modify(outport=vport_) for vport_ in vports_)
            pol |= match(inport=vport) & vfwds
        flood_pol |= match(switch=vsw) & pol
    return if_(match(outport=Port.flood_port), flood_pol)
        
def fork_sub_network(network):
    sub_net = Network()
    sub_net.inherit_events(network)
    network.install_sub_policies(sub_net.policy_changes)
    return sub_net

################################################################################
# Queries
################################################################################

def query(network, pred=all_packets, fields=(), time=None):
    b = Bucket(fields, time)

    sub_net = fork_sub_network(network)
    sub_net.install_policy(pred & fwd(b))
    
    return b

################################################################################
# Isolation
################################################################################

def isolate_policy(isotag, policy, flood_policy, egress_pred):
    """policy must be flood free"""
    policy = policy >> flood_policy
    return ((match(isotag=None) & policy >> push(isotag=isotag) |
            match(isotag=isotag) & policy) >> 
            if_(is_bucket("outport") | egress_pred, pop("isotag")))

def fork_isolated_network(network, inetwork_gen):
    sub_net = Network()
    sub_net.inherit_events(network)

    def subgen():
        for policy, args in gs.merge_hold(sub_net.policy_changes, inetwork_gen):
            yield isolate_policy(id(sub_net), policy, *args)
    
    network.install_sub_policies(subgen())
    
    return sub_net

################################################################################
# Virtualization policies 
################################################################################

pop_vheaders = pop("vswitch", "vinport", "voutport", "vtag")

virtual_to_physical = (pop("outport", "switch", "inport", "vtag") >>
                       copy(outport="voutport", switch="vswitch", inport="vinport"))

def physical_to_virtual(vtag):
    return (push(vtag=vtag) >>
            copy(voutport="outport", vswitch="switch", vinport="inport"))


def virtualize_policy(vtag,
                      policy,
                      ingress_policy,
                      physical_policy,
                      flood_policy,
                      query_policy=virtual_to_physical):
    """
    - `ingress_policy' is written in terms of the physical network, and tries to
       detect whether a packet is at the ingress of a virtual switch. If the packet
       is at the ingress of a virtual switch, then modify the vswitch and vinport of the
       packet to be the current virtual switch and the inport we are at, respectively .
    - `policy' is written in terms of the virtual network, and modifies the outport field.
       We will modify the voutport of the packet to be the outport returned.
    - `physical_policy' is written in terms of the physical network, and tries to
       forward packets along the fabric of the virtual switch until voutport is reached.
       When the packet leaves vswitch, the v* headers must be removed.

    Returns the virtualization of `policy' with respect to the other parameters.
    """

    # if the vlan isnt set, then we need to find out the v* headers.
    return (if_(~match(vtag=vtag), 
                (ingress_policy >> # set vswitch and vinport
                 # now make the virtualization transparent to the tenant's policy to get the outport
                 copy(switch="vswitch", inport="vinport") >>
                 policy >>
                 flood_policy >>
                 physical_to_virtual(vtag)))
            # Pipe the packet with appropriate v* headers to the physical policy for processing
            >> if_(is_bucket("voutport"), query_policy, physical_policy))
 
def fork_virtual_network(network, vnetwork_gen):
    sub_net = Network()
    sub_net.init_events()
        
    def subgen():
        for policy, args in gs.merge_hold(sub_net.policy_changes, vnetwork_gen):
            yield virtualize_policy(id(sub_net), policy, *args)
    
    network.install_sub_policies(subgen())
    
    return sub_net

################################################################################
# Virtualization helpers
################################################################################

def vmap_to_ingress_policy(vmap):
    return or_pol(or_pred(match(switch=sw, inport=p) for (sw, p) in switches) &
                  push(vswitch=vsw, vinport=vp)
                  for ((vsw, vp), switches) in vmap.iteritems())
    
def vmap_to_egress_policy(vmap):
    pred = or_pred(or_pred(match(switch=sw, outport=p) for (sw, p) in switches) &
                   match(vswitch=vsw, voutport=vp) 
                   for ((vsw, vp), switches) in vmap.iteritems())
               
    return if_(pred, pop_vheaders)
    
def vmap_get_sw_to_ports(vmap):
    sw_to_ports = {}

    for (vsw, vp) in vmap:
        vsw = lift_fixedwidth("vswitch", vsw)
        vp = lift_fixedwidth("vinport", vp)
        sw_to_ports.setdefault(vsw, []).append(vp)

    return sw_to_ports

def make_vnetwork_gen(vmap_phys_gen):
    for args in vmap_phys_gen:
        vmap = args[0]
        physical_policy = args[1]
        args = args[2:]
        flood_policy = flood_splitter(vmap_get_sw_to_ports(vmap))
        ingress_policy = vmap_to_ingress_policy(vmap)
        egress_policy = vmap_to_egress_policy(vmap)
        yield (ingress_policy, physical_policy >> egress_policy, flood_policy) + args

def make_inetwork_gen(vimap_phys_gen):
    for vmap, endpoints in vimap_phys_gen:
        flood_policy = flood_splitter(vmap_get_sw_to_ports(vmap))
        yield flood_policy, or_(match(switch=sw, outport=p) for sw, p in endpoints)
        
