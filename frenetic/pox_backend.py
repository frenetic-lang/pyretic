
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

from frenetic import generators
from frenetic import netcore as nc
from frenetic import netcore_lib as nl
from frenetic import backend
from frenetic.util import frozendict

from pox.core import core
from pox.lib.addresses import *
from pox.lib.revent import EventMixin
import pox.openflow.libopenflow_01 as of


class POXNetwork(backend.Network):
    def __init__(self, pox_backend):
        class POXPolicyHandle(backend.PolicyHandle):
            def install(self2, pol):
                backend.PolicyHandle.install(self2, pol)
                pox_backend.netcore_policy = self.get_combined_policy()
        self.ph_class = POXPolicyHandle 
        backend.Network.__init__(self)
    
class POXBackend(EventMixin):
    def __init__(self, user_program):
        self.netcore_policy = nc.drop
        self.user_program = user_program
        self.listenTo(core)

    def _handle_GoingUpEvent(self, event):
        self.switch_connections = {}
        self.pyretic_network = POXNetwork(self)
        
        generators.run(self.user_program, self.pyretic_network)

        self.listenTo(core.openflow)

    def _handle_PacketIn(self, event):
        pox_pkt = event.parsed
        packet = pox_to_pyretic_packet(event.dpid, event.ofp.in_port, pox_pkt)
        action = nl.eval(self.netcore_policy, packet)
        n_pkts = nl.mod_packet(action, packet)
        for pkt in n_pkts:
            # if buckety:
            #     buckety.signal(pkt)
            self.send_packet(pkt)
        
    def _handle_ConnectionUp(self, event):
        self.switch_connections[event.dpid] = event.connection
        self.pyretic_network.switch_joins.signal(nc.Switch(event.dpid))
        
    def _handle_ConnectionDown(self, event):
        # Post this to switch_down
        if event.dpid in self.switch_connections:
            del self.switch_connections[event.dpid]

        self.pyretic_network.switch_parts.signal(nc.Switch(event.dpid))
        
    def _handle_LinkEvent(self, event):
        # Post this somewhere
        pass

    def _handle_PortStatus(self, event):
        # Post this somewhere
        pass

    def _handle_BarrierIn(self, event):
        # We'll use this at some point?
        pass

    def send_packet(self, packet):
        switch = packet.header["switch"]
        inport = packet.header["inport"]
        outport = packet.header["outport"]
        
        msg = of.ofp_packet_out()
        msg.in_port = int(inport)
        # TODO Something about buffer ids
        # If we can compile the action, we can be much more efficient here.
        msg.data = packet.payload

        outport = int(outport)
        if outport == 65535:
            outport = of.OFPP_FLOOD
        msg.actions.append(of.ofp_action_output(port = outport))

        self.switch_connections[int(switch)].send(msg)


_hack_program = None
        
def launch():
    POXBackend(_hack_program)
        
def start(f):
    global _hack_program
    _hack_program = f
    
#
# Utils
#


def pyretic_header_to_pox_match(h):
    match = of.ofp_match()
    match.in_port = h["inport"]
    match.dl_src = EthAddr(h["srcmac"].macbytes)
    match.dl_dst = EthAddr(h["dstmac"].macbytes)
    match.dl_type = h["type"]
    match.dl_vlan = h["vlan"]
    match.dl_vlan_pcp = h["vlan_pcp"]
    match.nw_src = IPAddr(repr(h["srcip"]))
    match.nw_dst = IPAddr(repr(h["dstip"]))
    match.nw_proto = h["protocol"]
    match.nw_tos = h["tos"]
    match.tp_src = h["srcport"]
    match.tp_dst = h["dstport"]
    return match

def pox_match_to_pyretic_header(match):
    # XXX convert here using netcore_helper
    h = dict()
    h["inport"] = match.in_port
    h["srcmac"] = match.dl_src.toRaw()
    h["dstmac"] = match.dl_dst.toRaw()
    h["type"] = match.dl_type
    h["vlan"] = match.dl_vlan
    h["vlan_pcp"] = match.dl_vlan_pcp
    h["srcip"] = match.nw_src.toRaw()
    h["dstip"] = match.nw_dst.toRaw()
    h["protocol"] = match.nw_proto
    h["tos"] = match.nw_tos
    h["srcport"] = match.tp_src
    h["dstport"] = match.tp_dst
    return nl.Header(frozendict(nc.lift_dict(h, 0)))

      
def pox_to_pyretic_packet(dpid, inport, packet):
    if not packet.parsed:
        raise ValueError("The packet must already be parsed.")

    h = pox_match_to_pyretic_header(of.ofp_match.from_packet(packet, inport)).update(switch=dpid)
    n_packet = nl.Packet(h, packet.pack())
    
    return n_packet

    
def compile_action(act):
    """Return a list of POX actions."""

    c = act.get_counter()
    actions = []

    for mapping in c.elements():
        outport, mapping = mapping.pop("outport")
        for k, v in mapping.iteritems():
            if k == "switch":
                raise ValueError
            elif k == "inport":
                raise ValueError
            elif k == "vlan":
                a = of.ofp_action_vlan_vid(vlan_vid=int(v))
                actions.append(a)
            elif k == "vlan_pcp":
                a = of.ofp_action_vlan_pcp(vlan_pcp=int(v))
                actions.append(a)
            elif k == "srcip":
                a = of.ofp_action_nw_addr.set_src(v.to_bits().tobytes())
                actions.append(a)
            elif k == "dstip":
                a = of.ofp_action_nw_addr.set_dst(v.to_bits().tobytes())
                actions.append(a)
            elif k == "srcmac":
                a = of.ofp_action_dl_addr.set_src(v.to_bits().tobytes())
                actions.append(a)
            elif k == "dstmac":
                a = of.ofp_action_dl_addr.set_dst(v.to_bits().tobytes())
                actions.append(a)
            elif k == "srcport":
                a = of.ofp_action_tp_port.set_src(int(v))
                actions.append(a)
            elif k == "dstport":
                a = of.ofp_action_tp_port.set_dst(int(v))
                actions.append(a)
            else:
                raise ValueError
        
        outport = int(outport)
        if outport == 65535:
            outport = of.OFPP_FLOOD
        send_action = of.ofp_action_output(port=outport)
        actions.append(send_action)
    return actions 


   
