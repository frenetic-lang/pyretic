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

import threading
from collections import Counter

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery as discovery
from pox.core import core
from pox.lib import revent, addresses as packetaddr, packet as packetlib

from frenetic import generators as gs, network as net, virt, util

import ipdb


class POXBackend(revent.EventMixin):
    # NOT **kwargs
    def __init__(self, user_program, show_traces, debug_packet_in, kwargs):
        self.network = virt.Network()
        self.network.init_events()
        
        self.switch_connections = {}
        self.show_traces = show_traces
        self.debug_packet_in = debug_packet_in
        self.vlan_to_diff_db = {}
        self.diff_to_vlan_db = {}
        self.vlan_diff_lock = threading.RLock()
        
        core.registerNew(discovery.Discovery)

        if core.hasComponent("openflow"):
            self.listenTo(core.openflow)
        if core.hasComponent("openflow_discovery"):
            self.listenTo(core.openflow_discovery)
        
        gs.run(user_program, self.network, **kwargs)
    
    def vlan_from_diff(self, diff):
        with self.vlan_diff_lock:
            vlan = self.diff_to_vlan_db.get(diff)
            if vlan is not None:
                return vlan
            r = len(self.diff_to_vlan_db)
            pcp = r & 0b111000000000000
            id = r & 0b000111111111111
            self.diff_to_vlan_db[diff] = (id, pcp)
            self.vlan_to_diff_db[(id, pcp)] = diff
            return (id, pcp)
        
    def diff_from_vlan(self, id, pcp):
        with self.vlan_diff_lock:
            diff = self.vlan_to_diff_db.get((id, pcp))
            assert diff is not None, "use of vlan that pyretic didn't allocate! not allowed."
            return diff

    def create_packet(self, data):
        p = POXPacket(data, self.diff_from_vlan)
        return p

    def get_packet_payload(self, packet):
        return packet._get_payload(self.vlan_from_diff)

    def _handle_PacketIn(self, event):
        recv_packet = self.create_packet(event.data)
        recv_packet = recv_packet._push(switch=event.dpid, inport=event.ofp.in_port)

        if self.debug_packet_in == "1":
            ipdb.set_trace()

        pol = self.network.policy
        
        with ipdb.launch_ipdb_on_exception():
            output = pol.eval(recv_packet)
        
        if self.debug_packet_in == "drop" and not output:
            ipdb.set_trace()
            output = pol.eval(recv_packet) # So we can step through it
        
        if self.show_traces:
            print "Recv"
            print util.repr_plus([recv_packet], sep="\n\n")
            print
            print
            print "Send"
            print util.repr_plus(output.elements(), sep="\n\n")
            print
            print
            print "===================================="
        
        for pkt in output.elements():
            if pkt.outport.is_real():
                self.send_packet(pkt)
            else:
                bucket = pkt.outport.get_bucket()
                # Perform the link's function here and rm outport
                pkt = pkt._pop("outport")
                bucket.signal(pkt)

    def _handle_ConnectionUp(self, event):
        assert event.dpid not in self.switch_connections
        
        self.switch_connections[event.dpid] = event.connection
        self.network.switch_joins.signal(net.Switch(event.dpid))
        for port in event.ofp.ports:
            if port.port_no <= of.OFPP_MAX:
                self.network.port_ups.signal((net.Switch(event.dpid), net.Port(port.port_no)))
        
    def _handle_ConnectionDown(self, event):
        assert event.dpid in self.switch_connections

        del self.switch_connections[event.dpid]
        self.network.switch_parts.signal(net.Switch(event.dpid))
        
    def _handle_PortStatus(self, event):
        if event.port.port_no <= of.OFPP_MAX:
            if event.added:
                self.network.port_ups.signal((net.Switch(event.dpid), net.Port(event.port)))
            elif event.deleted:
                self.network.port_downs.signal((net.Switch(event.dpid), net.Port(event.port)))

    def _handle_LinkEvent(self, event):
        sw1 = event.link.dpid1
        p1 = event.link.port1
        sw2 = event.link.dpid2
        p2 = event.link.port2
        if sw1 is None or sw2 is None:
            return
        if event.added:
            self.network.link_ups.signal((net.Switch(sw1), net.Port(p1), net.Switch(sw2), net.Port(p2)))
        elif event.removed:
            self.network.link_downs.signal((net.Switch(sw1), net.Port(p1), net.Switch(sw2), net.Port(p2)))
        
    def send_packet(self, packet):
        switch = int(packet.switch)
        inport = int(packet.inport)
        outport = int(packet.outport)

        packet = packet._pop("switch", "inport", "outport")
        
        msg = of.ofp_packet_out()
        msg.in_port = inport
        msg.data = self.get_packet_payload(packet)
        msg.actions.append(of.ofp_action_output(port = outport))
        
        self.switch_connections[switch].send(msg)

        
def launch(module_dict, show_traces=False, debug_packet_in=False, **kwargs):
    import pox
    backend = POXBackend(module_dict["main"], bool(show_traces), debug_packet_in, kwargs)
    pox.pyr = backend

################################################################################
# 
################################################################################

pox_valid_headers = ["srcmac", "dstmac", "srcip", "dstip", "tos", "srcport", "dstport"]

class POXPacket(net.Packet, util.Data("internal_header payload")):
    def __new__(cls, data, get_diff_from_vlan):        
        h = {}
        ih = {}
        p = packetlib.ethernet(data)

        h["srcmac"] = p.src.toRaw()
        h["dstmac"] = p.dst.toRaw()
        ih["type"] = p.type

        p = p.next

        if isinstance(p, packetlib.vlan):
            vlan_diff = get_diff_from_vlan(p.id, p.pcp)
            ih["type"] = p.eth_type
            p = p.next
        else:
            vlan_diff = util.frozendict()

        if isinstance(p, packetlib.ipv4):
            h["srcip"] = p.srcip.toRaw()
            h["dstip"] = p.dstip.toRaw()
            ih["protocol"] = p.protocol
            h["tos"] = p.tos
            p = p.next

            if isinstance(p, packetlib.udp) or isinstance(p, packetlib.tcp):
                h["srcport"] = p.srcport
                h["dstport"] = p.dstport
            elif isinstance(p, packetlib.icmp):
                h["srcport"] = p.type
                h["dstport"] = p.code
        elif isinstance(p, packetlib.arp):
            if p.opcode <= 255:
                ih["protocol"] = p.opcode
                h["srcip"] = p.protosrc.toRaw()
                h["dstip"] = p.protodst.toRaw()
        
        packet = super(POXPacket, cls).__new__(cls, vlan_diff, util.frozendict(ih), data)
        return packet._push(h)

    @property
    def protocol(self):
        assert "protocol" in self.internal_header, "not an ip or arp packet"
        return net.lift_fixedwidth("protocol", self.internal_header["protocol"])

    @property
    def type(self):
        type = self.internal_header["type"]
        return net.lift_fixedwidth("type", type)

    @util.cached
    def _make_diff(self):
        diff = {}
        for k, v in self.header.iteritems():
            if k not in pox_valid_headers and v:
                diff[k] = v
            elif len(v) > 1:
                diff[k] = v[1:]
        return util.frozendict(diff)
        
    def _get_payload(self, vlan_from_diff):
        packet = p = packetlib.ethernet(self.payload)

        p.src = packetaddr.EthAddr(self.srcmac.to_bits().tobytes())
        p.dst = packetaddr.EthAddr(self.dstmac.to_bits().tobytes())

        if self._make_diff():
            if isinstance(p.next, packetlib.vlan):
                p = p.next
            else:
                # Make a vlan header
                old_eth_type = p.type
                p.type = 0x8100
                p.next = packetlib.vlan(next = p.next)
                p = p.next
                p.eth_type = old_eth_type

            p.id, p.pcp = vlan_from_diff(self._make_diff())
        else:
            if isinstance(p.next, packetlib.vlan):
                p.type = p.next.eth_type # Restore encapsulated eth type
                p.next = p.next.next # Remove vlan from header

        p = p.next

        if isinstance(p, packetlib.ipv4):
            p.srcip = packetaddr.IPAddr(self.srcip.to_bits().tobytes())
            p.dstip = packetaddr.IPAddr(self.dstip.to_bits().tobytes())
            p.protocol = int(self.protocol)
            p.tos = int(self.tos)
            p = p.next

            if isinstance(p, packetlib.udp) or isinstance(p, packetlib.tcp):
                p.srcport = int(self.srcport)
                p.dstport = int(self.dstport)
            elif isinstance(p, packetlib.icmp):
                p.type = int(self.srcport)
                p.code = int(self.dstport)
        elif isinstance(p, packetlib.arp):
            p.opcode = int(self.protocol)
            p.protosrc = packetaddr.IPAddr(self.srcip.to_bits().tobytes())
            p.protodst = packetaddr.IPAddr(self.dstip.to_bits().tobytes())

        return packet.pack()
        
    def __repr__(self):
        banner = "Packet of type %s:" % hex(self.type) 
        if self._pop("switch", "inport", "outport")._make_diff():
            banner += " (not backendable)"
        s = util.indent_str(super(POXPacket, self).__repr__())
        return banner + "\n" + s
        

    
    
