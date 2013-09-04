
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

# This module is designed for import *.
from pyretic.core.network import *
from pyretic.core.language import *
from pyretic.core import util
from pyretic.core.util import singleton
from pyretic.lib.std import pkt_print, str_print

import itertools

################################################################################
# Unique virtual network tags                                                  #
################################################################################

last_vtag = 0
def new_vtag():
    """Returns a new unique tag"""
    global last_vtag 
    last_vtag = last_vtag + 1
    return last_vtag


################################################################################
# Virtualization helper policies                                               #
################################################################################

class lower_packet(DerivedPolicy):
    """Lowers a packet from the derived network to the underlying network"""
    def __init__(self, vtag):
        self.vtag = vtag
        super(lower_packet,self).__init__(push(vtag=self.vtag) >> 
                                          move(voutport="outport",
                                               vswitch="switch",
                                               vinport="inport"))
        
        def __repr__(self):
            return "lower_packet %s" % self.vtag

        
@singleton
class lift_packet(DerivedPolicy):
    """Lifts a packet from the underlying network to the derived network"""
    def __init__(self):
        DerivedPolicy.__init__(self, 
                               pop("vtag") >>
                               move(outport="voutport", 
                                    switch="vswitch", 
                                    inport="vinport"))
        
    def __repr__(self):
        return "lift_packet"

        
@singleton
class pop_vheaders(DerivedPolicy):
    """Removes all headers used by this library"""
    def __init__(self):
        DerivedPolicy.__init__(self,
                               pop("vswitch", 
                                   "vinport", 
                                   "voutport", 
                                   "vtag"))
        
    def __repr__(self):
        return "pop_vheaders"


################################################################################
# VMAP functions
################################################################################

class vmap(object):
    """The mapping between underlying and physical ports.
    Also helper methods to generate various often-used implementation policies."""
    def __init__(self):
        self.d2u = {}
        self.u2d = {}

    def ingress_policy(self):
        non_ingress = ~union(union(match(switch=u.switch,
                                         inport=u.port_no) 
                                   for u in us) for (d, us) 
                             in self.d2u.iteritems())
        ingress = (union(union(match(switch=u.switch,
                                     inport=u.port_no)
                               for u in us) >> 
                         push(vtag='ingress', 
                              vswitch=d.switch, 
                              vinport=d.port_no, 
                              voutport=-1)
                         for (d, us) in self.d2u.iteritems()))
        return ingress + non_ingress

    def egress_policy(self):
        matches_egress = []
        valid_match_egress = []
        for (d, us) in self.d2u.iteritems():
            switch_pred = union(match(switch=u.switch, 
                                      outport=u.port_no) 
                                for u in us)
            matches_egress.append(switch_pred)
            valid_match_egress.append(match(vswitch=d.switch, 
                                            voutport=d.port_no) & switch_pred)
        return if_(union(matches_egress), 
                   union(valid_match_egress) >> pop_vheaders)

    def one_to_one_fabric_policy(self):
        fabric_policy = drop
        # ITERATE THROUGH ALL PAIRS OF VIRTUAL PORTS
        for (d1,[u1]) in self.d2u.items():
            for (d2,[u2]) in self.d2u.items():
                # FABRIC POLICY ONLY EXISTS WITHIN EACH VIRTUAL SWITCH
                if d1.switch != d2.switch:
                    continue
                # FORWARD OUT THE CORRECT PHYSICAL PORT
                fabric_policy += (match(vswitch=d1.switch,
                                        vinport=d1.port_no,
                                        voutport=d2.port_no) >>
                                  fwd(u2.port_no))
        return fabric_policy

    def shortest_path_fabric_policy(self,topo):
        fabric_policy = drop
        paths = Topology.all_pairs_shortest_path(topo)
        # ITERATE THROUGH ALL PAIRS OF VIRTUAL PORTS
        for (d1,[u1]) in self.d2u.items():
            for (d2,[u2]) in self.d2u.items():
                # FABRIC POLICY ONLY EXISTS WITHIN EACH VIRTUAL SWITCH
                if d1.switch != d2.switch:
                    continue
                # IF IDENTICAL VIRTUAL LOCATIONS, THEN WE KNOW FABRIC POLICY IS JUST TO FORWARD OUT MATCHING PHYSICAL PORT
                if d1.port_no == d2.port_no:
                    fabric_policy += (match(vswitch=d1.switch,
                                            vinport=d1.port_no,
                                            voutport=d2.port_no,
                                            switch=u2.switch) >> 
                                      fwd(u2.port_no))
                # OTHERWISE, GET THE PATH BETWEEN EACH PHYSICAL PAIR OF SWITCHES CORRESPONDING TO THE VIRTUAL LOCATION PAIR
                # THE FOR EACH PHYSICAL HOP ON THE PATH, CREATE THE APPROPRIATE FORWARDING RULE FOR THAT SWITCH
                # FINALLY ADD A RULE THAT FORWARDS OUT THE CORRECT PHYSICAL PORT AT THE LAST PHYSICAL SWITCH ON THE PATH
                else:
                    try:
                        for loc in paths[u1.switch][u2.switch]:
                            fabric_policy += (match(vswitch=d1.switch,
                                                    vinport=d1.port_no,
                                                    voutport=d2.port_no,
                                                    switch=loc.switch) >>
                                              fwd(loc.port_no))
                        fabric_policy += (match(vswitch=d1.switch,
                                                vinport=d1.port_no,
                                                voutport=d2.port_no,
                                                switch=u2.switch) >>
                                          fwd(u2.port_no))
                    except KeyError:
                        pass
        return fabric_policy


################################################################################
# Virtualization definition base class                                         #
################################################################################

class vdef(object):
    """Defines/implements a virtual network."""
    class DerivedNetwork(Network):
        def __init__(self,underlying=None,injection_policy=None):
            super(vdef.DerivedNetwork,self).__init__()
            self.underlying = underlying
            self.injection_policy = injection_policy
            self.inherited = set(underlying.topology.nodes())

        def inject_packet(self, pkt):
            if pkt['switch'] in self.inherited:
                self.underlying.inject_packet(pkt)
            else:
                output = self.injection_policy.eval(pkt)
                map(self.underlying.inject_packet,output)

    class locate_packet_in_underlying(Policy):
        def __init__(self):
            self.vmap = None
            super(vdef.locate_packet_in_underlying,self).__init__()

        def eval(self, pkt):
            try:
                switch = pkt['switch']
                inport = pkt['inport']
            except KeyError:
                vswitch = pkt['vswitch']
                voutport = pkt['voutport']
                u = self.vmap.d2u[Location(vswitch,voutport)][0]
                (switch,outport) = (u.switch,u.port_no)
                pkt = pkt.push(switch=switch)
                pkt = pkt.push(inport=-1)
                if not outport is None:
                    pkt = pkt.push(outport=outport)
                else:
                    pkt = pkt.push(outport=-1)
            return {pkt}

        def __repr__(self):
            return "locate_packet_in_underlying"

    def __init__(self):
        self.vmap = None
        self.underlying = None
        self.derived = None
        self.DEBUG = no_packets
        self.locate_in_underlying = self.locate_packet_in_underlying()

    def make_vmap(self):
        raise NotImplementedError

    def set_network(self,network):
        self.vmap = self.make_vmap()
        self.ingress_policy.vmap = self.vmap
        self.fabric_policy.vmap = self.vmap
        self.egress_policy.vmap = self.vmap
        self.locate_in_underlying.vmap = self.vmap
        self.ingress_policy.set_network(network)
        self.fabric_policy.set_network(network)
        self.egress_policy.set_network(network)

        ### THE INJECTION POLICY
        self.derived.injection_policy = (
            lower_packet(self.vtag) >>
            self.locate_in_underlying >>
            if_(match(outport=-1) | match(outport=None),   # IF NO OUTPORT 
                self.fabric_policy) >>  # THEN WE NEED TO RUN THE FABRIC POLICY
            self.egress_policy)

    
################################################################################
# Virtualize input policies based on virtualization definition                 #
################################################################################

class virtualize(DerivedPolicy):
    """Takes a policy for the unvirtualized components of the network, 
    another for the virtualized components of the network,
    and a virtualization defintion,
    and outputs a single policy for the underlying network."""
    def __init__(self, vpolicy, vdef, DEBUG=no_packets):
        self.vpolicy = vpolicy
        self.vnetwork = None
        self.vtag = new_vtag()
        self.vdef = vdef
        self.DEBUG = DEBUG
        self.vdef.DEBUG = self.DEBUG
        self.vdef.vtag = self.vtag

        ### THE VIRTUALIZED POLICY
        super(virtualize,self).__init__(
            if_(match(outport=None),push(outport=-1)) >>
            self.vdef.ingress_policy >> # set vlocation
            ### IF INGRESSING LIFT AND EVALUATE
            if_(match(vtag='ingress'), 
                lift_packet >> self.vpolicy >> lower_packet(self.vtag)) >>
            ### IF IN INTERIOR NETWORK ROUTE ON FABRIC AND IF APPLICABLE EGRESS
            if_(match(vtag=self.vtag), 
                self.vdef.fabric_policy >> self.vdef.egress_policy,
                self.vpolicy))
        
            
    def set_network(self, network):
        Policy.set_network(self,network)            
        self.vdef.set_network(network)
        if ((not self.vnetwork) or 
            self.vdef.derived.topology != self.vnetwork.topology):
            self.vnetwork = self.vdef.derived.copy()
            self.vpolicy.set_network(self.vnetwork) 
        
    def __repr__(self):
        return "virtualize %s\n%s" % (self.vtag, self.vdef)
