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
        self.network = virt.Network(self)
        self.network.init_events()
        
        self.switch_connections = {}
        self.show_traces = show_traces
        self.debug_packet_in = debug_packet_in
        self.vlan_to_diff_db = {}
        self.diff_to_vlan_db = {}
        self.vlan_diff_lock = threading.RLock()
        self.packetno = 0
        
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

    def create_packet(self, switch, inport, data):
        h = {}
        h["switch"] = switch
        h["inport"] = inport
        
        p = packetlib.ethernet(data)
        h["srcmac"] = net.MAC(p.src.toRaw())
        h["dstmac"] = net.MAC(p.dst.toRaw())
        h["type"] = p.type

        p = p.next
        if isinstance(p, packetlib.vlan):
            vlan_diff = self.diff_from_vlan(p.id, p.pcp)
            h["type"] = p.eth_type
            p = p.next
        else:
            vlan_diff = util.frozendict()

        if isinstance(p, packetlib.ipv4):
            h["srcip"] = net.IP(p.srcip.toRaw())
            h["dstip"] = net.IP(p.dstip.toRaw())
            h["protocol"] = p.protocol
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
                h["protocol"] = p.opcode
                h["srcip"] = net.IP(p.protosrc.toRaw())
                h["dstip"] = net.IP(p.protodst.toRaw())

        h["payload"] = data
        
        packet = net.Packet(vlan_diff)
        return packet.pushmany(h)

    def get_packet_payload(self, packet):
        p_begin = p = packetlib.ethernet(packet["payload"])

        p.src = packetaddr.EthAddr(packet["srcmac"].fromRaw())
        p.dst = packetaddr.EthAddr(packet["dstmac"].fromRaw())

        diff = get_packet_diff(packet)
        if diff:
            if isinstance(p.next, packetlib.vlan):
                p = p.next
            else:
                # Make a vlan header
                old_eth_type = p.type
                p.type = 0x8100
                p.next = packetlib.vlan(next=p.next)
                p = p.next
                p.eth_type = old_eth_type
            p.id, p.pcp = self.vlan_from_diff(diff)
        else:
            if isinstance(p.next, packetlib.vlan):
                p.type = p.next.eth_type # Restore encapsulated eth type
                p.next = p.next.next # Remove vlan from header

        p = p.next
        if isinstance(p, packetlib.ipv4):
            p.srcip = packetaddr.IPAddr(packet["srcip"].fromRaw())
            p.dstip = packetaddr.IPAddr(packet["dstip"].fromRaw())
            p.protocol = packet["protocol"]
            p.tos = packet["tos"]

            p = p.next
            if isinstance(p, packetlib.udp) or isinstance(p, packetlib.tcp):
                p.srcport = packet["srcport"]
                p.dstport = packet["dstport"]
            elif isinstance(p, packetlib.icmp):
                p.type = packet["srcport"]
                p.code = packet["dstport"]
        elif isinstance(p, packetlib.arp):
            p.opcode = packet["protocol"]
            p.protosrc = packetaddr.IPAddr(packet["srcip"].fromRaw())
            p.protodst = packetaddr.IPAddr(packet["dstip"].fromRaw())

        return p_begin.pack()

    def _handle_PacketIn(self, event):

        if self.show_traces:
            self.packetno += 1
            print "-------- POX/OF RECV %d ---------------" % self.packetno
            print event.connection
            print event.ofp
            print "port\t%s" % event.port
            print "data\t%s" % packetlib.ethernet(event.data)
            print "dpid\t%s" % event.dpid
            print

        recv_packet = self.create_packet(event.dpid, event.ofp.in_port, event.data)
        
        if self.debug_packet_in == "1":
            ipdb.set_trace()

        pol = self.network.policy
        
        with ipdb.launch_ipdb_on_exception():
            output = pol.eval(recv_packet)
        
        if self.debug_packet_in == "drop" and not output:
            ipdb.set_trace()
            output = pol.eval(recv_packet) # So we can step through it
        
        if self.show_traces:
            print "<<<<<<<<< RECV <<<<<<<<<<<<<<<<<<<<<<<<<<"
            print util.repr_plus([recv_packet], sep="\n\n")
            print
            print ">>>>>>>>> SEND >>>>>>>>>>>>>>>>>>>>>>>>>>"
            print util.repr_plus(output.elements(), sep="\n\n")
            print
        
        for pkt in output.elements():
            outport = pkt["outport"]
            if not isinstance(outport, net.Bucket):
                self.send_packet(pkt)
            else:
                bucket = outport
                # Perform the link's function here and rm outport
                pkt = pkt.pop("outport")
                bucket.signal(pkt)

    def _handle_ConnectionUp(self, event):
        assert event.dpid not in self.switch_connections
        
        self.switch_connections[event.dpid] = event.connection
        self.network.switch_joins.signal(event.dpid)
        for port in event.ofp.ports:
            if port.port_no <= of.OFPP_MAX:
                self.network.port_ups.signal((event.dpid, port.port_no))
        
    def _handle_ConnectionDown(self, event):
        assert event.dpid in self.switch_connections

        del self.switch_connections[event.dpid]
        self.network.switch_parts.signal(event.dpid)
        
    def _handle_PortStatus(self, event):
        if event.port <= of.OFPP_MAX:
            if event.added:
                self.network.port_ups.signal((event.dpid, event.port))
            elif event.deleted:
                self.network.port_downs.signal((event.dpid, event.port))

    def _handle_LinkEvent(self, event):
        sw1 = event.link.dpid1
        p1 = event.link.port1
        sw2 = event.link.dpid2
        p2 = event.link.port2
        if sw1 is None or sw2 is None:
            return
        if event.added:
            self.network.link_ups.signal((sw1, p1, sw2, p2))
        elif event.removed:
            self.network.link_downs.signal((sw1, p1, sw2, p2))
        
    def send_packet(self, packet):
        switch = packet["switch"]
        inport = packet["inport"]
        outport = packet["outport"]

        packet = packet.pop("switch", "inport", "outport")
        
        msg = of.ofp_packet_out()
        msg.in_port = inport
        msg.data = self.get_packet_payload(packet)
        msg.actions.append(of.ofp_action_output(port = outport))
        
        if self.show_traces:
            print "========= POX/OF SEND ================"
            print msg
            print packetlib.ethernet(msg._get_data())
            print

        self.switch_connections[switch].send(msg)

        
def launch(module_dict, show_traces=False, debug_packet_in=False, **kwargs):
    import pox
    backend = POXBackend(module_dict["main"], bool(show_traces), debug_packet_in, kwargs)
    pox.pyr = backend

################################################################################
# 
################################################################################

### REICH - ADDED HEADERS W/ SEEM LIKE THEY SHOULD BE "VALID" 
###         NOT CLEAR PRECISELY WHAT get_packet_diff IS SUPPOSED TO BE DOING
pox_valid_headers = ["srcmac", "dstmac", "srcip", "dstip", "tos", "srcport", "dstport", "protocol", "type", "payload"]

@util.cached
def get_packet_diff(packet):
    diff = {}
    for k, v in packet.header.items():
        if k not in pox_valid_headers and v:
            diff[k] = v
        elif len(v) > 1:
            diff[k] = v[1:]
    return util.frozendict(diff)

    
    
