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
#import pox.openflow.discovery as discovery
from pox.core import core
from pox.lib import revent, addresses as packetaddr, packet as packetlib
from pox.lib.packet.ethernet      import ethernet
from pox.lib.packet.ethernet      import LLDP_MULTICAST, NDP_MULTICAST
from pox.lib.packet.lldp          import lldp, chassis_id, port_id, end_tlv
from pox.lib.packet.lldp          import ttl, system_description

from frenetic import generators as gs, network as net, virt, util

import ipdb

            
class POXBackend(revent.EventMixin):
    # NOT **kwargs
    def __init__(self, main, show_traces, debug_packet_in, kwargs):
        self.network = virt.Network(self)
        self.network.init_events()
        
        self.switches = {}
        self.show_traces = show_traces
        self.debug_packet_in = debug_packet_in
        self.vlan_to_diff_db = {}
        self.diff_to_vlan_db = {}
        self.vlan_diff_lock = threading.RLock()
        self.packetno = 0

        if core.hasComponent("openflow"):
            self.listenTo(core.openflow)

        self.policy = main(**kwargs)
        self.policy.attach(self.network)

        
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

    def packet_from_pox(self, switch, inport, data):
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
                h["type"] = 2054
                h["protocol"] = p.opcode
                h["srcip"] = net.IP(p.protosrc.toRaw())
                h["dstip"] = net.IP(p.protodst.toRaw())


        h["payload"] = data
        
        packet = net.Packet(vlan_diff)
        return packet.pushmany(h)


    def make_pox_arp(self, packet):
        p = packetlib.ethernet()
        p.src = packetaddr.EthAddr(packet["srcmac"].to_bytes())
        p.dst = packetaddr.EthAddr(packet["dstmac"].to_bytes())
        
        p.type = 2054
        p.next = packetlib.arp(prev=p)
        
        p.next.hwsrc = packetaddr.EthAddr(packet["srcmac"].to_bytes())
        p.next.hwdst = packetaddr.EthAddr(packet["dstmac"].to_bytes())
        p.next.protosrc = packetaddr.IPAddr(packet["srcip"].to_bytes())
        p.next.protodst = packetaddr.IPAddr(packet["dstip"].to_bytes())
        p.next.opcode = packet['protocol']
        
        print "SCRATCH"
        print p

        return p

    def packet_to_pox(self, packet):
        if len(packet["payload"]) == 0:
            return self.make_pox_arp(packet).pack()

        p_begin = p = packetlib.ethernet(packet["payload"])

        print "---------------------"        
        print "BEGIN"
        print p_begin

        # ETHERNET PACKET IS OUTERMOST
        p.src = packetaddr.EthAddr(packet["srcmac"].to_bytes())
        p.dst = packetaddr.EthAddr(packet["dstmac"].to_bytes())

        # DEAL WITH ETHERNET VLANS
        diff = get_packet_diff(packet)
        print "diff"
        print diff
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

        # GET PACKET INSIDE ETHERNET/VLAN
        p = p.next
        if isinstance(p, packetlib.ipv4):
            p.srcip = packetaddr.IPAddr(packet["srcip"].to_bytes())
            p.dstip = packetaddr.IPAddr(packet["dstip"].to_bytes())
            p.protocol = packet["protocol"]
            p.tos = packet["tos"]

            p = p.next
            if isinstance(p, packetlib.udp) or isinstance(p, packetlib.tcp):
                p.srcport = packet["srcport"]
                p.dstport = packet["dstport"]
            elif isinstance(p, packetlib.icmp):
                p.type = packet["srcport"]
                p.code = packet["dstport"]
            print "AFTER"
            print p_begin

        elif isinstance(p, packetlib.arp):
            if diff:
                p.opcode = packet["protocol"]
                p.protosrc = packetaddr.IPAddr(packet["srcip"].to_bytes())
                p.protodst = packetaddr.IPAddr(packet["dstip"].to_bytes())
                print "AFTER"
                print p_begin
            else:
                print "AFTER"
                print p_begin
                p_begin = self.make_pox_arp(packet)
        

        print "---------------------"

        payload = p_begin.pack()

        return payload

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

    def create_discovery_packet (self, dpid, portNum, portAddr):
        """ Create LLDP packet """
        
        discovery_packet = lldp()
        
        cid = chassis_id()
        # Maybe this should be a MAC.  But a MAC of what?  Local port, maybe?
        cid.fill(cid.SUB_LOCAL, bytes('dpid:' + hex(long(dpid))[2:-1]))
        discovery_packet.add_tlv(cid)
        
        pid = port_id()
        pid.fill(pid.SUB_PORT, str(portNum))
        discovery_packet.add_tlv(pid)
        
        ttlv = ttl()
        ttlv.fill(0)
        discovery_packet.add_tlv(ttlv)
        
        sysdesc = system_description()
        sysdesc.fill(bytes('dpid:' + hex(long(dpid))[2:-1]))
        discovery_packet.add_tlv(sysdesc)
        
        discovery_packet.add_tlv(end_tlv())
        
        eth = ethernet()
        eth.src = portAddr
        eth.dst = NDP_MULTICAST
        eth.set_payload(discovery_packet)
        eth.type = ethernet.LLDP_TYPE
        
        po = of.ofp_packet_out(action = of.ofp_action_output(port=portNum),
                               data = eth.pack())
    #    log.info("discovery_packet_created")    
        return po.pack()

    def inject_discovery_packet(self,dpid, port):
        hw_addr = self.switches[dpid]['ports'][port]
        packet = self.create_discovery_packet(dpid, port, hw_addr)
        core.openflow.sendToDPID(dpid, packet)

    def _handle_ConnectionUp(self, event):
        assert event.dpid not in self.switches
        
        self.switches[event.dpid] = {}
        self.switches[event.dpid]['connection'] = event.connection
        self.switches[event.dpid]['ports'] = {}

        msg = of.ofp_flow_mod(match = of.ofp_match())
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        self.switches[event.dpid]['connection'].send(msg)

        self.network.switch_joins.signal(event.dpid)

        # port type is ofp_phy_port
        for port in event.ofp.ports:
            if port.port_no <= of.OFPP_MAX:
                self.switches[event.dpid]['ports'][port.port_no] = port.hw_addr
                CONF_UP = not 'OFPPC_PORT_DOWN' in self.active_ofp_port_config(port.config)
                STAT_UP = not 'OFPPS_LINK_DOWN' in self.active_ofp_port_state(port.state)
                self.network.port_joins.signal((event.dpid, port.port_no, CONF_UP, STAT_UP))
        
        self.policy.update_network(self.network)
                        
    def _handle_ConnectionDown(self, event):
        assert event.dpid in self.switches

        del self.switches[event.dpid]
        self.network.switch_parts.signal(event.dpid)

        self.policy.update_network(self.network)
        
    def _handle_PortStatus(self, event):
        port = event.ofp.desc
        if event.port <= of.OFPP_MAX:
            if event.added:
                self.switches[event.dpid]['ports'][event.port] = event.ofp.desc.hw_addr
                self.network.port_joins.signal((event.dpid, event.port))
                CONF_UP = not 'OFPPC_PORT_DOWN' in self.active_ofp_port_config(port.config)
                STAT_UP = not 'OFPPS_LINK_DOWN' in self.active_ofp_port_state(port.state)
                self.network.port_joins.signal((event.dpid, port.port_no, CONF_UP, STAT_UP))
            elif event.deleted:
                try:
                    del self.switches[event.dpid]['ports'][event.port] 
                except KeyError:
                    pass  # SWITCH ALREADY DELETED
                self.network.port_parts.signal((event.dpid, event.port))
            elif event.modified:
                CONF_UP = not 'OFPPC_PORT_DOWN' in self.active_ofp_port_config(port.config)
                STAT_UP = not 'OFPPS_LINK_DOWN' in self.active_ofp_port_state(port.state)
                self.network.port_mods.signal((event.dpid, event.port, CONF_UP, STAT_UP))
            else:
                raise RuntimeException("Unknown port status event")

        self.policy.update_network(self.network)

    def handle_lldp(self,packet,event):

        if not packet.next:
            print "lldp packet could not be parsed"
            return

        assert isinstance(packet.next, lldp)

        lldph = packet.next
        if  len(lldph.tlvs) < 3 or \
                (lldph.tlvs[0].tlv_type != lldp.CHASSIS_ID_TLV) or\
                (lldph.tlvs[1].tlv_type != lldp.PORT_ID_TLV) or\
                (lldph.tlvs[2].tlv_type != lldp.TTL_TLV):
            print "lldp_input_handler invalid lldp packet"
            return

        def lookInSysDesc():
            r = None
            for t in lldph.tlvs[3:]:
                if t.tlv_type == lldp.SYSTEM_DESC_TLV:
                    # This is our favored way...
                    for line in t.next.split('\n'):
                        if line.startswith('dpid:'):
                            try:
                                return int(line[5:], 16)
                            except:
                                pass
                    if len(t.next) == 8:
                        # Maybe it's a FlowVisor LLDP...
                        try:
                            return struct.unpack("!Q", t.next)[0]
                        except:
                            pass
                    return None

        originatorDPID = lookInSysDesc()

        if originatorDPID == None:
            # We'll look in the CHASSIS ID
            if lldph.tlvs[0].subtype == chassis_id.SUB_LOCAL:
                if lldph.tlvs[0].id.startswith('dpid:'):
                    # This is how NOX does it at the time of writing
                    try:
                        originatorDPID = int(lldph.tlvs[0].id.tostring()[5:], 16)
                    except:
                        pass
            if originatorDPID == None:
                if lldph.tlvs[0].subtype == chassis_id.SUB_MAC:
                    # Last ditch effort -- we'll hope the DPID was small enough
                    # to fit into an ethernet address
                    if len(lldph.tlvs[0].id) == 6:
                        try:
                            s = lldph.tlvs[0].id
                            originatorDPID = struct.unpack("!Q",'\x00\x00' + s)[0]
                        except:
                            pass

        if originatorDPID == None:
            print "Couldn't find a DPID in the LLDP packet"
            return

#        # if chassid is from a switch we're not connected to, ignore
#        if originatorDPID not in self._dps:
#            log.info('Received LLDP packet from unconnected switch')
#            return

        # grab port ID from port tlv
        if lldph.tlvs[1].subtype != port_id.SUB_PORT:
            print "Thought we found a DPID, but packet didn't have a port"
            return # not one of ours
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
            print "Thought we found a DPID, but port number didn't make sense"
            return

        if (event.dpid, event.port) == (originatorDPID, originatorPort):
            print 'Loop detected; received our own LLDP event'
            return

        self.network.link_updates.signal((originatorDPID, originatorPort, event.dpid, event.port))

        self.policy.update_network(self.network)
        
        return
#    return EventHalt # Probably nobody else needs this event

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

        recv_packet = self.packet_from_pox(event.dpid, event.ofp.in_port, event.data)
        
        if self.debug_packet_in == "1":
            ipdb.set_trace()
        
        with ipdb.launch_ipdb_on_exception():
            output = self.policy.eval(self.network, recv_packet)
            
        if self.debug_packet_in == "drop" and not output:
            ipdb.set_trace()
            output = self.policy.eval(self.network, recv_packet) # So we can step through it
        
        if self.show_traces:
            print "<<<<<<<<< RECV <<<<<<<<<<<<<<<<<<<<<<<<<<"
            print util.repr_plus([recv_packet], sep="\n\n")
            print
            print ">>>>>>>>> SEND >>>>>>>>>>>>>>>>>>>>>>>>>>"
            print util.repr_plus(output.elements(), sep="\n\n")
            print
        
        for pkt in output.elements():
            self.send_packet(pkt)

                
    def send_packet(self, packet):
        switch = packet["switch"]
        inport = packet["inport"]
        outport = packet["outport"]

        packet = packet.pop("switch", "inport", "outport")
        
        msg = of.ofp_packet_out()
        msg.in_port = inport
        msg.data = self.packet_to_pox(packet)
        msg.actions.append(of.ofp_action_output(port = outport))
        
        if self.show_traces:
            print "========= POX/OF SEND ================"
            print msg
            print packetlib.ethernet(msg._get_data())
            print

        ## HANDLE PACKETS SEND ON LINKS THAT HAVE TIMED OUT
        try:
            self.switches[switch]['connection'].send(msg)
        except RuntimeError, e:
            print "ERROR:send_packet: %s to switch %d" % (str(e),switch)
            # TODO - ATTEMPT TO RECONNECT SOCKET
        except KeyError, e:
            print "ERROR:send_packet: No connection to switch %d available" % switch
            # TODO - IF SOCKET RECONNECTION, THEN WAIT AND RETRY

        
def launch(module_dict, show_traces=False, debug_packet_in=False, **kwargs):
    import pox
    backend = POXBackend(module_dict["main"], bool(show_traces), debug_packet_in, kwargs)
    pox.pyr = backend

################################################################################
# 
################################################################################

pox_valid_headers = ["srcmac", "dstmac", "srcip", "dstip", "tos", "srcport", "dstport",
                     "type", "protocol", "payload"]

@util.cached
def get_packet_diff(packet):
    diff = {}
    for k, v in packet.header.items():
        if k not in pox_valid_headers and v:
            diff[k] = v
        elif len(v) > 1:
            diff[k] = v[1:]
    return util.frozendict(diff)

    
    
