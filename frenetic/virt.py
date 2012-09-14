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


################################################################################
# Network
################################################################################

class Network(object):
    def __init__(self):
        self.switch_joins = gs.Event()
        self.switch_parts = gs.Event()
        self.port_ups = gs.Event()
        self.port_downs = gs.Event()
        self.link_ups = gs.Event()
        self.link_downs = gs.Event()
        
        self.policy_b = gs.Behavior(drop)
        self.policy_changes = self.policy_b # used only for iter method
        self.sub_policies = {}
        
        super(Network, self).__init__()

    def query(self, pred, fields=(), time=None):
        b = Bucket(fields, time)
        b.sub_network = fork_sub_network(self)
        b.sub_network.install_policy(pred & fwd(b))
        return b
        
    def install_policy(self, policy):
        self.sub_policies[self] = policy
        self.policy_b.set(self._aggregate_policy())
        
    def get_policy(self):
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
        
def add_sub_network(super_network, sub_network):
    t = gs.Trigger(sub_network.policy_changes)
    super_network.install_sub_policies(t)
    t.wait()
        
def fork_sub_network(network):
    sub_net = Network()
    sub_net.switch_joins = network.switch_joins
    sub_net.switch_parts = network.switch_parts

    add_sub_network(network, sub_net)
    
    return sub_net

################################################################################
# Databases
################################################################################

class NetworkDatabase(dict):
    def __init__(self, *args, **kwargs):
        self.switch_joins = gs.Event()
        self.switch_parts = gs.Event()
        self.port_ups = gs.Event()
        self.port_downs = gs.Event()
        self.link_ups = gs.Event()
        self.link_downs = gs.Event()
        super(NetworkDatabase, self).__init__(*args, **kwargs)
    
    def activate(self, network):
        @network.switch_joins.notify
        def handler(switch):
            self[switch] = {}
            self.switch_joins.signal(switch)
            
        @network.switch_parts.notify
        def handler(switch):
            if switch in self:
                del self[switch]
                self.switch_parts.signal(switch)
            
        @network.port_ups.notify
        def handler((switch, port)):
            if switch in self:
                self[switch][port] = None
                self.port_ups.signal((switch, port))
            
        @network.port_downs.notify
        def handler((switch, port)):
            if switch in self and port in self[switch]:
                del self[switch][port]
                self.port_downs.signal((switch, port))

        @network.link_ups.notify
        def handler((s1,p1,s2,p2)):
            if s1 in self and p1 in self[s1] and s2 in self and p2 in self[s2]:
                self[s1][p1] = (s2, p2)
                self[s2][p2] = (s1, p1)
                self.link_ups.signal((s1 ,p1, s2, p2))
            
        @network.link_downs.notify
        def handler((s1,p1,s2,p2)):
            if s1 in self and p1 in self[s1] and s2 in self and p2 in self[s2]:
                self[s1][p1] = None
                self[s2][p2] = None
                self.link_downs.signal((s1, p1, s2, p2))
            
################################################################################
# Virtualization policies 
################################################################################
    
def fork_virtual_network(network, vnetwork_gen):
    sub_net = Network()
    t = gs.Trigger(sub_net.policy_changes)

    def subgen():
        for policy, args in gs.merge_hold(t, vnetwork_gen):
            yield virtualize_policy(id(sub_net), policy, *args)
    
    network.install_sub_policies(subgen())
    t.wait()
    
    return sub_net

pop_vheaders = pop("vswitch", "vinport", "voutport", "vtag")
    
virtual_to_physical = (copy(outport="voutport", switch="vswitch", inport="vinport") >> 
                       pop_vheaders)

def physical_to_virtual(vtag):
    return (modify(vtag=vtag) >>
            copy(voutport="outport", vswitch="switch", vinport="inport") >> 
            pop("outport", "switch", "inport"))

def make_flood_policy(vinfo):
    flood_pol = drop
    for vsw, vports in vinfo.iteritems():
        pol = drop
        for vport in vports:
            vports_ = list(vports)
            vports_.remove(vport)
            vfwds = or_(modify(outport=vport_) for vport_ in vports_)
            pol |= match(inport=vport) & vfwds
        flood_pol |= match(switch=vsw) & pol
        
    return if_(match(outport=Port.flood_port), flood_pol)

def isolate_policy(isotag, policy, flood_policy, egress_pred):
    """policy must be flood free"""
    policy = policy >> flood_policy
    return ((match(isotag=None) & policy >> push("isotag") >> modify(isotag=isotag) |
            match(isotag=isotag) & policy >> modify(isotag=isotag)) >> 
            if_(is_bucket("outport") | egress_pred, pop("isotag")))

def fork_isolated_network(network, vnetwork_gen):
    sub_net = Network()
    sub_net.switch_joins = network.switch_joins
    sub_net.switch_parts = network.switch_parts
    sub_net.port_ups = network.port_ups
    sub_net.port_downs = network.port_downs
    sub_net.link_ups = network.link_ups
    sub_net.link_downs = network.link_downs
    
    t = gs.Trigger(sub_net.policy_changes)

    def subgen():
        for policy, args in gs.merge_hold(t, vnetwork_gen):
            yield isolate_policy(id(sub_net), policy, *args)
    
    network.install_sub_policies(subgen())
    t.wait()
    
    return sub_net
    
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

       (Implementation detail: removing vswitch is sufficient).

    Returns the virtualization of `policy' with respect to the other parameters.
    """

    # if the vlan isnt set, then we need to find out the v* headers.
    return (if_(~match(vtag=vtag), 
                (push("vswitch", "vinport") >>
                 ingress_policy >> # set vswitch and vinport
                 # now make the virtualization transparent to the tenant's policy to get the outport
                 push("switch","inport", "outport") >>
                 copy(switch="vswitch", inport="vinport") >>
                 pop("vswitch", "vinport") >>
                 policy >>
                 flood_policy >>
                 push("vtag", "vswitch", "vinport", "voutport") >>
                 physical_to_virtual(vtag)))
            # Pipe the packet with appropriate v* headers to the physical policy for processing
            >> case ((is_bucket("voutport"), query_policy),
                     (all_packets, physical_policy)))

################################################################################
# Virtualization helpers
################################################################################

class VMap(util.frozendict):
    """(phys switch, phys port) -> (virt switch, virt port)"""

    def __init__(self, init):
        d = dict()
        for k, args in init.items():
            if len(args) == 2:
                args += (False,)
            d[k] = args
        super(VMap, self).__init__(d)
    
    def to_vinfo(self):
        vinfo = {}

        for (vsw, vp, endpt) in self.itervalues():
            vsw = lift_fixedwidth("vswitch", vsw)
            vinp = lift_fixedwidth("vinport", vp)
            vinfo.setdefault(vsw, []).append(vinp)

        return vinfo

    def to_flood_policy(self):
        return make_flood_policy(self.to_vinfo())
    
    def to_ingress_policy(self):
        ingress_policy = drop
        for (sw, inp), (vsw, vip, endpt) in self.iteritems():
            ingress_policy |= match(switch=sw, inport=inp) & modify(vswitch=vsw, vinport=vip)

        return ingress_policy
    
    def to_egress_policy(self):
        pred = no_packets
        for (sw, port), (vsw, vport, endpt) in self.iteritems():
            pred |= match(switch=sw, outport=port, vswitch=vsw, voutport=vport)
        
        return if_(pred, pop_vheaders)

    def to_endpts_pred(self):
        pred = no_packets
        for (vsw, vport, endpt) in self.itervalues():
            if endpt:
                pred |= match(switch=vsw, outport=vport)
        return pred

    def fork(self, network, vnetwork_gen, isolate=False):
        ingress_policy = self.to_ingress_policy()
        egress_policy = self.to_egress_policy()
        flood_policy = self.to_flood_policy()

        def gen():
            for args in vnetwork_gen:
                # Query is optional, don't forget
                r = (ingress_policy, args[0] >> egress_policy, flood_policy) + args[1:]
                yield r
        vn = fork_virtual_network(network, gen())
        vn.switch_joins = gs.DelayedEvent(self.to_vinfo())
        vn.switch_parts = gs.DelayedEvent([])
        vn.port_ups = gs.DelayedEvent([])
        vn.port_downs = gs.DelayedEvent([])
        vn.link_ups = gs.DelayedEvent([])
        vn.link_downs = gs.DelayedEvent([])

        if isolate:
            vn = fork_isolated_network(vn, [(flood_policy, self.to_endpts_pred())])
            
        return vn
        
def gen_static_physical_policy(route):
    """(sw, vop) : act"""
    
    policy = drop
    for (sw, vop), act in route.iteritems():
        policy |= match(switch=sw, voutport=vop) & act

    return policy
    
               
