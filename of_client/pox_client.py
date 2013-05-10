
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

import threading
from collections import Counter

import pox.openflow.libopenflow_01 as of
from pox.core import core
from pox.lib import revent, addresses as packetaddr, packet as packetlib
from pox.lib.packet.ethernet      import ethernet
from pox.lib.packet.ethernet      import LLDP_MULTICAST, NDP_MULTICAST
from pox.lib.packet.lldp          import lldp, chassis_id, port_id, end_tlv
from pox.lib.packet.lldp          import ttl, system_description

from pyretic.backend.comm import *


def inport_value_hack(outport):
    if outport > 1:
        return 1
    else:
        return 2


class BackendChannel(asynchat.async_chat):
    """Sends messages to the server and receives responses.
    """
    def __init__(self, host, port, of_client):
        self.of_client = of_client
        self.received_data = []
        asynchat.async_chat.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host, port))
        self.set_terminator(TERM_CHAR)
        return

    def handle_connect(self):
        print "Connected to pyretic frontend."
        
    def collect_incoming_data(self, data):
        """Read an incoming message from the client and put it into our outgoing queue."""
        with self.of_client.channel_lock:
            self.received_data.append(data)

    def found_terminator(self):
        """The end of a command or message has been seen."""
        with self.of_client.channel_lock:
            msg = deserialize(self.received_data)

        # USE DESERIALIZED MSG
        if msg[0] == 'inject_discovery_packet':
            self.of_client.inject_discovery_packet(msg[1], msg[2])
        elif msg[0] == 'packet':
            self.of_client.send_packet_to_network(msg[1])
        else:
            print "ERROR: Unknown msg from frontend %s" % msg


class POXClient(revent.EventMixin):
    # NOT **kwargs
    def __init__(self,show_traces=False,debug_packet_in=False,ip='127.0.0.1',port=BACKEND_PORT):
        self.switches = {}
        self.show_traces = show_traces
        self.debug_packet_in = debug_packet_in
        self.packetno = 0
        self.channel_lock = threading.Lock()

        if core.hasComponent("openflow"):
            self.listenTo(core.openflow)

        self.backend_channel = BackendChannel(ip, port, self)
        self.adjacency = {} # From Link to time.time() stamp

    def packet_from_network(self, switch, inport, data):
        h = {}
        h["switch"] = switch
        h["inport"] = inport
        
        p = packetlib.ethernet(data)
        h["srcmac"] = p.src.toRaw()
        h["dstmac"] = p.dst.toRaw()
        h["ethtype"] = p.type

        p = p.next
        if isinstance(p, packetlib.vlan):
            h['vlan_id'] = p.id
            h['vlan_pcp'] = p.pcp
            h["ethtype"] = p.eth_type
            p = p.next

        if isinstance(p, packetlib.ipv4):
            h["srcip"] = p.srcip.toRaw()
            h["dstip"] = p.dstip.toRaw()
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
                h["ethtype"] = packetlib.ethernet.ARP_TYPE
                h["protocol"] = p.opcode
                h["srcip"] = p.protosrc.toRaw()
                h["dstip"] = p.protodst.toRaw()

        h["payload"] = data 
        return ascii2bytelist(h)


    def make_arp(self, packet):
        p = packetlib.ethernet()
        p.src = packetaddr.EthAddr(packet["srcmac"])
        p.dst = packetaddr.EthAddr(packet["dstmac"])
        
        p.type = packetlib.ethernet.ARP_TYPE
        p.next = packetlib.arp(prev=p)
        
        p.next.hwsrc = packetaddr.EthAddr(packet["srcmac"])
        p.next.hwdst = packetaddr.EthAddr(packet["dstmac"])
        p.next.protosrc = packetaddr.IPAddr(packet["srcip"])
        p.next.protodst = packetaddr.IPAddr(packet["dstip"])
        p.next.opcode = packet['protocol']

        return p


    def packet_to_network(self, packet):
        packet = bytelist2ascii(packet)
        if len(packet["payload"]) == 0:
            if packet["ethtype"] == packetlib.ethernet.ARP_TYPE:
                p_begin = p = self.make_arp(packet)
            else:  # BLANK PACKET FOR NOW - MAY NEED TO SUPPORT OTHER PACKETS LATER
                p_begin = p = packetlib.ethernet()
        else:
            p_begin = p = packetlib.ethernet(packet["payload"])

        # ETHERNET PACKET IS OUTERMOST
        p.src = packetaddr.EthAddr(packet["srcmac"])
        p.dst = packetaddr.EthAddr(packet["dstmac"])

        if 'vlan_id' in packet:
            if isinstance(p.next, packetlib.vlan):
                p = p.next
            else:
                # Make a vlan header
                old_eth_type = p.type
                p.type = 0x8100
                p.next = packetlib.vlan(next=p.next)
                p = p.next
                p.eth_type = old_eth_type
            p.id = packet['vlan_id']
            p.pcp = packet['vlan_pcp']
        else:
            if isinstance(p.next, packetlib.vlan):
                p.type = p.next.eth_type # Restore encapsulated eth type
                p.next = p.next.next # Remove vlan from header

        # GET PACKET INSIDE ETHERNET/VLAN
        p = p.next
        if isinstance(p, packetlib.ipv4):
            p.srcip = packetaddr.IPAddr(packet["srcip"])
            p.dstip = packetaddr.IPAddr(packet["dstip"])
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
            if 'vlan_id' in packet:
                p.opcode = packet["protocol"]
                p.protosrc = packetaddr.IPAddr(packet["srcip"])
                p.protodst = packetaddr.IPAddr(packet["dstip"])
            else:
                p_begin = self.make_arp(packet)
        
        return p_begin.pack()

    def _handle_ComponentRegistered (self, event):
        if event.name == "openflow":
            self.listenTo(core.openflow)
            return EventRemove # We don't need this listener anymore

    def active_ofp_port_config(self,configs):
        active = []
        for (config,bit) in of.ofp_port_config_rev_map.items():
            if configs & bit:
                active.append(config)
        return active

    def active_ofp_port_state(self,states):
        """get active ofp port state values
        NOTE: POX's doesn't match ofp_port_state_rev_map"""
        active = []
        for (state,bit) in of.ofp_port_state_rev_map.items():
            if states & bit:
                active.append(state)
        return active

    def active_ofp_port_features(self,features):
        active = []
        for (feature,bit) in of.ofp_port_features_rev_map.items():
            if features & bit:
                active.append(feature)
        return active

    def inspect_ofp_phy_port(self,port,prefix=""):
        print "%sport_no:     " % prefix, 
        port_id = port.port_no
        for name,port_no in of.ofp_port_rev_map.iteritems():
            if port.port_no == port_no:
                port_id = name
        print port_id
        print "%shw_addr:     " % prefix, 
        print port.hw_addr
        print "%sname:        " % prefix, 
        print port.name
        print "%sconfig:      " % prefix, 
        print self.active_ofp_port_config(port.config)
        print "%sstate:       " % prefix, 
        print self.active_ofp_port_state(port.state)
        print "%scurr:        " % prefix, 
        print self.active_ofp_port_features(port.curr)
        print "%sadvertised:  " % prefix, 
        print self.active_ofp_port_features(port.advertised)
        print "%ssupported:   " % prefix, 
        print self.active_ofp_port_features(port.supported)
        print "%speer:        " % prefix, 
        print self.active_ofp_port_features(port.peer)


    def create_discovery_packet (self, dpid, port_num, port_addr):
        """
        Build discovery packet
        """
        import pox.lib.packet as pkt
        chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.SUB_LOCAL)
        chassis_id.id = bytes('dpid:' + hex(long(dpid))[2:-1])
        
        port_id = pkt.port_id(subtype=pkt.port_id.SUB_PORT, id=str(port_num))

        ttl = pkt.ttl(ttl = 120)

        sysdesc = pkt.system_description()
        sysdesc.payload = bytes('dpid:' + hex(long(dpid))[2:-1])

        discovery_packet = pkt.lldp()
        discovery_packet.tlvs.append(chassis_id)
        discovery_packet.tlvs.append(port_id)
        discovery_packet.tlvs.append(ttl)
        discovery_packet.tlvs.append(sysdesc)
        discovery_packet.tlvs.append(pkt.end_tlv())

        eth = pkt.ethernet(type=pkt.ethernet.LLDP_TYPE)
        eth.src = port_addr
        eth.dst = pkt.ETHERNET.NDP_MULTICAST
        eth.payload = discovery_packet

        po = of.ofp_packet_out(action = of.ofp_action_output(port=port_num))
        po.data = eth.pack()
        return po.pack()


    def inject_discovery_packet(self,dpid, port):
        try:
            hw_addr = self.switches[dpid]['ports'][port]
            packet = self.create_discovery_packet(dpid, port, hw_addr)
            core.openflow.sendToDPID(dpid, packet)
        except KeyError:
            pass

    def send_to_pyretic(self,msg):
        serialized_msg = serialize(msg)
        try:
            with self.channel_lock:
                self.backend_channel.push(serialized_msg)
        except IndexError as e:
            print "ERROR PUSHING MESSAGE %s" % msg
            pass


    def _handle_ConnectionUp(self, event):
        assert event.dpid not in self.switches
        
        self.switches[event.dpid] = {}
        self.switches[event.dpid]['connection'] = event.connection
        self.switches[event.dpid]['ports'] = {}

        msg = of.ofp_flow_mod(match = of.ofp_match())
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        self.switches[event.dpid]['connection'].send(msg)

        self.send_to_pyretic(['switch','join',event.dpid,'BEGIN'])

        # port type is ofp_phy_port
        for port in event.ofp.ports:
            if port.port_no <= of.OFPP_MAX:
                self.switches[event.dpid]['ports'][port.port_no] = port.hw_addr
                CONF_UP = not 'OFPPC_PORT_DOWN' in self.active_ofp_port_config(port.config)
                STAT_UP = not 'OFPPS_LINK_DOWN' in self.active_ofp_port_state(port.state)
                self.send_to_pyretic(['port','join',event.dpid, port.port_no, CONF_UP, STAT_UP])                        
   
        self.send_to_pyretic(['switch','join',event.dpid,'END'])

                        
    def _handle_ConnectionDown(self, event):
        assert event.dpid in self.switches

        del self.switches[event.dpid]
        self.send_to_pyretic(['switch','part',event.dpid])

        
    def _handle_PortStatus(self, event):
        port = event.ofp.desc
        if event.port <= of.OFPP_MAX:
            if event.added:
                self.switches[event.dpid]['ports'][event.port] = event.ofp.desc.hw_addr
                #self.runtime.network.port_joins.signal((event.dpid, event.port))
                CONF_UP = not 'OFPPC_PORT_DOWN' in self.active_ofp_port_config(port.config)
                STAT_UP = not 'OFPPS_LINK_DOWN' in self.active_ofp_port_state(port.state)
                self.send_to_pyretic(['port','join',event.dpid, port.port_no, CONF_UP, STAT_UP])
            elif event.deleted:
                try:
                    del self.switches[event.dpid]['ports'][event.port] 
                except KeyError:
                    pass  # SWITCH ALREADY DELETED
                self.send_to_pyretic(['port','part',event.dpid,event.port])
            elif event.modified:
                CONF_UP = not 'OFPPC_PORT_DOWN' in self.active_ofp_port_config(port.config)
                STAT_UP = not 'OFPPS_LINK_DOWN' in self.active_ofp_port_state(port.state)
                self.send_to_pyretic(['port','mod',event.dpid, event.port, CONF_UP, STAT_UP])
            else:
                raise RuntimeException("Unknown port status event")


    def handle_lldp(self,packet,event):
        import pox.lib.packet as pkt
        from pox.openflow.discovery import Discovery, LinkEvent
        import time

        lldph = packet.find(pkt.lldp)
        if lldph is None or not lldph.parsed:
            return
        if len(lldph.tlvs) < 3:
            return
        if lldph.tlvs[0].tlv_type != pkt.lldp.CHASSIS_ID_TLV:
            return
        if lldph.tlvs[1].tlv_type != pkt.lldp.PORT_ID_TLV:
            return
        if lldph.tlvs[2].tlv_type != pkt.lldp.TTL_TLV:
            return

        def lookInSysDesc ():
            r = None
            for t in lldph.tlvs[3:]:
                if t.tlv_type == pkt.lldp.SYSTEM_DESC_TLV:
                    # This is our favored way...
                    for line in t.payload.split('\n'):
                        if line.startswith('dpid:'):
                            try:
                                return int(line[5:], 16)
                            except:
                                pass
                    if len(t.payload) == 8:
                        # Maybe it's a FlowVisor LLDP...
                        # Do these still exist?
                        try:
                            return struct.unpack("!Q", t.payload)[0]
                        except:
                            pass
                        return None

        originatorDPID = lookInSysDesc()

        if originatorDPID == None:
            # We'll look in the CHASSIS ID
            if lldph.tlvs[0].subtype == pkt.chassis_id.SUB_LOCAL:
                if lldph.tlvs[0].id.startswith('dpid:'):
                    # This is how NOX does it at the time of writing
                    try:
                        originatorDPID = int(lldph.tlvs[0].id[5:], 16)
                    except:
                        pass
            if originatorDPID == None:
                if lldph.tlvs[0].subtype == pkt.chassis_id.SUB_MAC:
                    # Last ditch effort -- we'll hope the DPID was small enough
                    # to fit into an ethernet address
                    if len(lldph.tlvs[0].id) == 6:
                        try:
                            s = lldph.tlvs[0].id
                            originatorDPID = struct.unpack("!Q",'\x00\x00' + s)[0]
                        except:
                            pass

        if originatorDPID == None:
            return

        if originatorDPID not in core.openflow.connections:
            return

        # Get port number from port TLV
        if lldph.tlvs[1].subtype != pkt.port_id.SUB_PORT:
            return
        originatorPort = None
        if lldph.tlvs[1].id.isdigit():
            # We expect it to be a decimal value
            originatorPort = int(lldph.tlvs[1].id)
        elif len(lldph.tlvs[1].id) == 2:
            # Maybe it's a 16 bit port number...
            try:
                originatorPort  =  struct.unpack("!H", lldph.tlvs[1].id)[0]
            except:
                pass
        if originatorPort is None:
            return
        
        if (event.dpid, event.port) == (originatorDPID, originatorPort):
            return

        link = Discovery.Link(originatorDPID, originatorPort, event.dpid,
                              event.port)

        if link not in self.adjacency:
            self.adjacency[link] = time.time()
            self.raiseEventNoErrors(LinkEvent, True, link)
        else:
            # Just update timestamp
            self.adjacency[link] = time.time()

        self.send_to_pyretic(['link',originatorDPID, originatorPort, event.dpid, event.port])            
        return # Probably nobody else needs this event


    def _handle_PacketIn(self, event):
        packet = event.parsed
        if packet.type == ethernet.LLDP_TYPE: 
            self.handle_lldp(packet,event)
            return
        elif packet.type == 0x86dd:  # IGNORE IPV6
            return 

        if self.show_traces:
            self.packetno += 1
            print "-------- POX/OF RECV %d ---------------" % self.packetno
            print event.connection
            print event.ofp
            print "port\t%s" % event.port
            print "data\t%s" % packetlib.ethernet(event.data)
            print "dpid\t%s" % event.dpid
            print

        received = self.packet_from_network(event.dpid, event.ofp.in_port, event.data)
        self.send_to_pyretic(['packet',received])
        

    def send_packet_to_network(self,packet):
        switch = packet["switch"]
        outport = packet["outport"]
        try:
            inport = packet["inport"]
            if inport == -1 or inport == outport:
                inport = inport_value_hack(outport)
        except KeyError:
            inport = inport_value_hack(outport)
        
        msg = of.ofp_packet_out()
        msg.in_port = inport
        msg.data = self.packet_to_network(packet)
        msg.actions.append(of.ofp_action_output(port = outport))
 
        if self.show_traces:
            print "========= POX/OF SEND ================"
            print msg
            print packetlib.ethernet(msg._get_data())
            print

        ## HANDLE PACKETS SEND ON LINKS THAT HAVE TIMED OUT
        try:
            self.switches[switch]['connection'].send(msg)
        except Runtimerror, e:
            print "ERROR:send_packet_to_network: %s to switch %d" % (str(e),switch)
            # TODO - ATTEMPT TO RECONNECT SOCKET
        except KeyError, e:
            print "ERROR:send_packet_to_network: No connection to switch %d available" % switch
            # TODO - IF SOCKET RECONNECTION, THEN WAIT AND RETRY
 
       
def launch():

    class asyncore_loop(threading.Thread):
        def run(self):
            asyncore.loop()

    POXClient()
    al = asyncore_loop()
    al.start()



    
    
