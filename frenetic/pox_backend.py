
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

from frenetic import generators, netcore, net, backend

from pox.core import core
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
    def __init__(self):
        self.netcore_policy = None
        self.listenTo(core)

    def _handle_GoingUpEvent(self, event):
        self.switch_connections = {}
        self.pyretic_network = POXNetwork(self)

        # XXX get user's policy func
        generators.run(policy_func, self.pyretic_network)

        self.listenTo(core.openflow)

    def _handle_PacketIn(self, event):
        pox_pkt = event.parsed
        packet = pox_to_pyretic_packet(event.dpid, event.in_port, pox_pkt)
        action = netcore.eval(self.netcore_policy, self.packet)

        n_pkts = netcore.mod_packet(action, packet)
        for pkt in n_pkts:
            # if buckety:
            #     buckety.signal(pkt)
            self.send_packet(pkt)
        
    def _handle_ConnectionUp(self, event):
        self.switch_connections[event.dpid] = event.connection
        self.pyretic_network.switch_joins.signal(net.Switch(event.dpid))
        
    def _handle_ConnectionDown(self, event):
        # Post this to switch_down
        if event.dpid in self.switch_connections:
            del self.switch_connections[event.dpid]

        self.pyretic_network.switch_parts.signal(net.Switch(event.dpid))
        
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
        switch, inport, outport, real_hdr = pkt.header.pop("switch", "inport", "outport")
        real_pkt = pkt.replace(header=real_hdr)

        msg = of.ofp_packet_out()
        msg.in_port = int(inport)
            # TODO Something about buffer ids
            # If we can compile the action, we can be much more efficient here.
        msg.data = real_pkt.payload
        msg.actions.append(of.ofp_action_output(port = int(outport)))

        self.switch_connections[int(switch)].send(msg)


def launch():
    core.registerNew(POXBackend)


#
# Utils
#


def pyretic_header_to_pox_match(h):
    match = of.ofp_match()
    match.in_port = h["inport"]
    match.dl_src = h["srcaddr"]
    match.dl_dst = h["dstaddr"]
    match.dl_type = h["type"]
    match.dl_vlan = h["vlan"]
    match.dl_vlan_pcp = h["vlan_pcp"]
    match.nw_src = h["srcip"]
    match.nw_dst = h["dstip"]
    match.nw_proto = h["protocol"]
    match.nw_tos = h["tos"]
    match.tp_src = h["srcport"]
    match.tp_dst = h["dstport"]
    return match

    
def pox_match_to_pyretic_header(match):
    h = dict()
    h["inport"] = match.in_port
    h["srcaddr"] = match.dl_src
    h["dstaddr"] = match.dl_dst
    h["type"] = match.dl_type
    h["vlan"] = match.dl_vlan
    h["vlan_pcp"] = match.dl_vlan_pcp
    h["srcip"] = match.nw_src
    h["dstip"] = match.nw_dst
    h["protocol"] = match.nw_proto
    h["tos"] = match.nw_tos
    h["srcport"] = match.tp_src
    h["dstport"] = match.tp_dst
    return net.Header(h)

      
def pox_to_pyretic_packet(dpid, inport, packet):
    if not packet.parsed:
        raise ValueError("The packet must already be parsed.")

    h = pox_match_to_pyretic_header(of.ofp_match.from_packet(packet, inport)).update(switch=dpid)
    n_packet = net.Packet(h, None, packet.pack())
    
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
        send_action = of.ofp_action_output(port=int(outport))
        actions.append(send_action)
    return actions 


   
