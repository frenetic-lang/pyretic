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

import itertools
from collections import Counter

last_vtag = 0
def new_vtag():
    global last_vtag 
    last_vtag = last_vtag + 1
    return last_vtag

################################################################################
# VMAP functions
################################################################################

def add_nodes_from_vmap(vmap, vtopo):
    for switch, port_no in vmap:
        port = Port(port_no)
        try:
            vtopo.node[switch]['ports'][port_no] = port 
        except KeyError:
            vtopo.add_node(switch, ports={port_no: port})

def vmap_to_ingress_policy(vmap):
    non_ingress = ~union(
        union(match(switch=sw, inport=p) for (sw, p) in switches) 
        for ((vsw, vp), switches) in vmap.iteritems() )
    ingress_policy = non_ingress[passthrough] | parallel(union(match(switch=sw, inport=p) for (sw, p) in switches)[push(vtag='ingress', vswitch=vsw, vinport=vp)] for ((vsw, vp), switches) in vmap.iteritems())
    return ingress_policy

def vmap_to_egress_policy(vmap):
    matches_egress = []
    valid_match_egress = []
    for ((vsw, vp), switches) in vmap.iteritems():
        switch_pred = union(match(switch=sw, outport=p) for (sw, p) in switches)
        matches_egress.append(switch_pred)
        valid_match_egress.append(match(vswitch=vsw, voutport=vp) & switch_pred)
    return if_(union(matches_egress), union(valid_match_egress)[pop_vheaders], passthrough)


################################################################################
# Virtualization policies 
################################################################################

class lower_packet(SinglyDerivedPolicy):
    """Lowers a packet from the derived network to the underlying network"""
    def __init__(self, vtag):
        self.vtag = vtag
        self.policy = (push(vtag=self.vtag) >> move(voutport="outport",
                                                    vswitch="switch",
                                                    vinport="inport"))
        
    def __repr__(self):
        return "lower_packet %s" % self.vtag

        
@singleton
class lift_packet(SinglyDerivedPolicy):
    """Lifts a packet from the underlying network to the derived network"""
    def __init__(self):
#        self.policy = (pop("switch", "inport", "outport", "vtag") >>
        self.policy = (pop("vtag") >>
                       move(outport="voutport", switch="vswitch", inport="vinport"))
        
    def __repr__(self):
        return "lift_packet"

        
@singleton
class pop_vheaders(SinglyDerivedPolicy):
    def __init__(self):
        self.policy = pop("vswitch", "vinport", "voutport", "vtag")
        
    def __repr__(self):
        return "pop_vheaders"

class locate_in_underlying(Policy):
    def __init__(self):
        self.vmap = {}

    def set_vmap(self,vmap):
        self.vmap = vmap
        print "self.vmap is ",
        print self.vmap

    ### repr : unit -> String
    def __repr__(self):
        return "locate_in_underlying"

    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        try:
            switch = packet['switch']
            inport = packet['inport']
            packet = packet.push(run_fabric=True)
        except KeyError:
            vswitch = packet['vswitch']
            voutport = packet['voutport']
            (switch,outport) = self.vmap[(vswitch,voutport)][0]
            # STUPID HACK B/C BACKEND WON'T LET US SEND WHEN OUTPORT=INPORT
            packet = packet.push(switch=switch)
            if outport > 1:
                packet = packet.push(inport=1)
            else:
                packet = packet.push(inport=2)    
            packet = packet.push(outport=outport)
        return Counter([packet])

        
class virtualize_base(SinglyDerivedPolicy):
    def __init__(self, upolicy, vpolicy, vdef, DEBUG=False):
        self.vpolicy = vpolicy
        self.vnetwork = None
        self.vdef = vdef
        self.vtag = new_vtag()
        self.DEBUG = DEBUG
        self.ingress_policy = self.vdef.ingress_policy
        self.fabric_policy = self.vdef.fabric_policy
        self.egress_policy = self.vdef.egress_policy
        self.locate_in_underlying = locate_in_underlying()
        self.policy = (
            pkt_print("virtualize:",self.DEBUG) >>
            self.ingress_policy >> # set vswitch and vinport
            pkt_print("after ingress:",self.DEBUG) >>
            ### IF INGRESSING LIFT AND EVALUATE
            if_(match(vtag='ingress'), 
                lift_packet >>
                pkt_print("after lift:",self.DEBUG) >>
                pol_print(self.vpolicy,'derived policy is:',self.DEBUG) >>
                pkt_print("after derived policy:",self.DEBUG) >>
                lower_packet(self.vtag) >>
                pkt_print("after lower:",self.DEBUG),
                passthrough) >>
            ### IF IN INTERIOR NETWORK ROUTE ON FABRIC AND IF APPLICABLE EGRESS
            if_(match(vtag=self.vtag), 
                self.fabric_policy >>
                pkt_print("after fabric:",self.DEBUG) >>
                self.egress_policy >>
                pkt_print("after egress:",self.DEBUG),
                upolicy >>
                pkt_print("after underlying policy",self.DEBUG) )
            )
        self.injection_policy = (
            pkt_print("injected packet",self.DEBUG) >>
            lower_packet(self.vtag) >>
            pkt_print("after lower",self.DEBUG) >>
            self.locate_in_underlying >>
            pkt_print("after locate",self.DEBUG) >>
            if_(match(run_fabric=None),
                passthrough,
                self.fabric_policy >>
                pop('run_fabric') >>
                pkt_print("after fabric",self.DEBUG)) >>
            self.egress_policy >>
            pkt_print("after egress",self.DEBUG) 
            )

    def set_network(self, updated_network):
        self.vdef.set_network(updated_network)
        self.locate_in_underlying.set_vmap(self.vdef.vmap)
        super(virtualize_base,self).set_network(updated_network)
        if not updated_network is None:
            # CREATE THE VNETWORK
            vnetwork = self.vdef.derive_network()
            # SET UP THE VNETWORK'S BACKEND
            vnetwork.backend = \
                DerivedBackend(updated_network.backend,self.injection_policy)
        else:
            vnetwork = None
        
        self.vpolicy.set_network(vnetwork) 
        
    def __repr__(self):
        return "virtualize %s\n%s" % (self.vtag, self.vdef)


class virtualize_full(virtualize_base):
    def __init__(self, vpolicy, vdef, DEBUG=False):
        super(virtualize_full,self).__init__(passthrough, vpolicy, vdef, DEBUG)


class virtualize_part(virtualize_base):
    def __init__(self, policy, vdef, DEBUG=False):
        super(virtualize_part,self).__init__(policy, policy, vdef, DEBUG)
