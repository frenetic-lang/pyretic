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
from frenetic.netcore import _
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


class SwitchDatabase(dict):
    def __init__(self, *args, **kwargs):
        self.switch_joins = gs.Event()
        self.switch_parts = gs.Event()
        self.port_ups = gs.Event()
        self.port_downs = gs.Event()
        super(SwitchDatabase, self).__init__(*args, **kwargs)
    
    def activate(self, network):
        @network.switch_joins.notify
        def handler(switch):
            self[switch] = set()
            self.switch_joins.signal(switch)
            
        @network.switch_parts.notify
        def handler(switch):
            if switch in self:
                del self[switch]
                self.switch_parts.signal(switch)
            
        @network.port_ups.notify
        def handler((switch, port)):
            if switch in self:
                self[switch].add(port)
                self.port_ups.signal((switch, port))
            
        @network.port_downs.notify
        def handler((switch, port)):
            if switch in self and port in self[switch]:
                self[switch].remove(port)
                self.port_downs.signal((switch, port))

            
################################################################################
# Virtualization policies 
################################################################################


def fork_virtual_network(network, vinfo, ingress_policy, physical_policy):
    return fork_virtual_network_gen(network, [(vinfo, ingress_policy, physical_policy)])
    
def fork_virtual_network_gen(network, vnetwork_gen):
    sub_net = Network()

    t = gs.Trigger(sub_net.policy_changes)

    def subgen():
        for policy, (vinfo, ingress_policy, physical_policy) in \
            gs.merge_hold(t, vnetwork_gen):
            yield virtualize_policy(generate_vlan_db(1, vinfo),
                                    ingress_policy,
                                    physical_policy,
                                    policy)
    
    network.install_sub_policies(subgen())
    
    t.wait()
    
    return sub_net

def generate_vlan_db(start_vlan, vinfo):
    vlan_to_vheaders = {}
    vheaders_to_vlan = {}

    vlan = start_vlan
    for vswitch in vinfo:
        for vinport in vinfo[vswitch]:
            for voutport in vinfo[vswitch]:
                vlan_to_vheaders[vlan] = (vswitch, vinport, voutport)
                vheaders_to_vlan[(vswitch, vinport, voutport)] = vlan
                vlan += 1

    return (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan)

strip_vheaders = modify(vswitch=None,
                        vinport=None,
                        voutport=None)

def vheaders_to_vlan_policy(vlan_db):
    (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan) = vlan_db
    
    return ((_.vswitch.is_missing() & strip_vlan # if we are no longer virtualized, remove vlan.
            | enum((_.vswitch, vinfo.iterkeys()), # otherwise, encode.
                   lambda s:
                   enum((_.vinport, vinfo[s]),
                        (_.voutport, vinfo[s]),
                        lambda ip, op: modify(vlan=vheaders_to_vlan[(s, ip, op)]))))
            >> strip_vheaders)
    
def vlan_to_vheaders_policy(vlan_db):
    (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan) = vlan_db

    def vlan_dict_helper(vlan):
        (vswitch, vinport, voutport) = vlan_to_vheaders[vlan]
        return modify(vswitch=vswitch, vinport=vinport, voutport=voutport)
    
    return (enum((_.vlan, vlan_to_vheaders.iterkeys()), vlan_dict_helper) >>
            strip_vlan)
    
def pre_vheaders_to_headers_policy():
    return copy_fields(switch=_.vswitch, inport=_.vinport) >> modify(vswitch=None,
                                                                     vinport=None)

def headers_to_post_vheaders(x):
    return copy_fields(voutport=x.outport)

def flood_splitter_policy(vlan_db):
    (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan) = vlan_db

    flood_pol = drop
    for vsw, vports in vinfo.iteritems():
        pol = drop
        for vport in vports:
            vports_ = list(vports)
            vports_.remove(vport)
            vfwds = or_(*(modify(voutport=vport_) for vport_ in vports_))
            pol |= and_(_.vinport == vport, vfwds)
        flood_pol |= and_(_.vswitch == vsw, pol)
        
    return if_(_.voutport == Port.flood_port, flood_pol, passthrough)
    
def virtualize_policy(vlan_db, ingress_policy, physical_policy, policy):
    """
    - `vinfo' is a mapping from switch to set of ports.
    - `start_vlan, ...` - see generate_vlan_db
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
    return (if_(_.vlan.is_missing(), 
                    (ingress_policy >> # set vswitch and vinport
                    # now make the virtualization transparent to the tenant's policy to get the outport
                     let(pre_vheaders_to_headers_policy() >> policy,
                         lambda x: headers_to_post_vheaders(x))),
                  # However, if vlan IS set, re-set the v* headers.
                  vlan_to_vheaders_policy(vlan_db))
            # Pipe the packet with appropriate v* headers to the physical policy for processing
            >> flood_splitter_policy(vlan_db)
            >> physical_policy
            # and translate the v* headers to a vlan value, since the real network
            # doesn't understand our custom headers.
            >> vheaders_to_vlan_policy(vlan_db))


################################################################################
# Virtualization helpers
################################################################################

class VMap(util.frozendict):
    """(phys switch, phys port) -> (virt switch, virt port)"""
    
    @util.cached
    def to_vinfo(self):
        vinfo = {}

        for (vsw, vp) in self.itervalues():
            vsw = lift_fixedwidth_kv("vswitch", vsw)
            vinp = lift_fixedwidth_kv("vinport", vp)
            vinfo.setdefault(vsw, []).append(vinp)

        return vinfo

    @util.cached
    def to_ingress_policy(self):
        ingress_policy = drop

        for (sw, inp), (vsw, vip) in self.iteritems():
            ingress_policy |= and_(_.switch == sw, _.inport == inp, modify(vswitch=vsw, vinport=vip))

        return ingress_policy

    @util.cached
    def to_egress_policy(self):
        pred = no_packets

        for (sw, port), (vsw, vport) in self.iteritems():
            pred |= and_(_.switch == sw, _.outport == port,
                         _.vswitch == vsw, _.voutport == vport)

        pred |= ~is_port_real(_.outport)

        return if_(pred, strip_vheaders, passthrough)

    # XXX unused for now
    def set_network_statuses(self, switch_db, vnetwork):
        @switch_db.port_ups.notify
        def handler((switch, port)):
            (vswitch, vport) = self[(switch, port)]
            vnetwork.port_ups.signal((vswitch, vport))
            
        @switch_db.port_downs.notify
        def handler((switch, port)):
            (vswitch, vport) = self[(switch, port)]
            vnetwork.port_downs.signal((vswitch, vport))

    def make_fork_func_gen(self, program):
        ingress_policy = self.to_ingress_policy()
        egress_policy = self.to_egress_policy()
        vinfo = self.to_vinfo()

        def fork(network):
            def gen():
                for policy in program(network):
                    yield (vinfo, ingress_policy, policy >> egress_policy)
            vn = fork_virtual_network_gen(network, gen())
            vn.switch_joins = gs.DelayedEvent(self.to_vinfo())
            vn.switch_parts = gs.DelayedEvent([])
            vn.port_ups = gs.DelayedEvent([])
            vn.port_downs = gs.DelayedEvent([])
            return vn

        return fork
        
    def make_fork_func(self, policy):
        return self.make_fork_func_gen(lambda network: [policy])
    
def gen_static_physical_policy(route):
    """(sw, vsw, vop) : act"""
    
    policy = drop

    for (sw, vsw, vop), act in route.iteritems():
        policy |= and_(_.switch == sw,
                       _.vswitch == vsw,
                       _.voutport == vop,
                       act)

    return if_(is_port_real(_.voutport),
               policy,
               copy_fields(outport=_.voutport, switch=_.vswitch, inport=_.vinport)) 
