
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
        self.ac_in_buffer_size = 4096 * 3
        self.ac_out_buffer_size = 4096 * 3
        self.set_terminator(TERM_CHAR)
        return

    def handle_connect(self):
        print "Connected to pyretic frontend."
        
    def collect_incoming_data(self, data):
        """Read an incoming message from the client and put it into our outgoing queue."""
        with self.of_client.channel_lock:
            self.received_data.append(data)

    def dict2OF(self,d):
        def convert(h,val):
            if h in ['srcmac','dstmac']:
                return packetaddr.EthAddr(val)
            elif h in ['srcip','dstip']:
                try:
                    return packetaddr.IPAddr(val)
                except:
                    return val
            elif h in ['vlan_id','vlan_pcp'] and val == 'None':
                return None
            else:
                return val
        return { h : convert(h,val) for (h, val) in d.items()}

    def found_terminator(self):
        """The end of a command or message has been seen."""
        with self.of_client.channel_lock:
            msg = deserialize(self.received_data)

        # USE DESERIALIZED MSG
        if msg[0] == 'inject_discovery_packet':
            switch = msg[1]
            port = msg[2]
            self.of_client.inject_discovery_packet(switch,port)
        elif msg[0] == 'packet':
            packet = self.dict2OF(msg[1])
            self.of_client.send_to_switch(packet)
        elif msg[0] == 'install':
            pred = self.dict2OF(msg[1])
            priority = int(msg[2])
            actions = map(self.dict2OF,msg[3])
            self.of_client.install_flow(pred,priority,actions)
        elif msg[0] == 'delete':
            pred = self.dict2OF(msg[1])
            priority = int(msg[2])
            self.of_client.delete_flow(pred,priority)
        elif msg[0] == 'clear':
            switch = int(msg[1])
            self.of_client.clear(switch)
        elif msg[0] == 'barrier':
            switch = msg[1]
            self.of_client.barrier(switch)
        elif msg[0] == 'flow_stats_request':
            switch = msg[1]
            self.of_client.flow_stats_request(switch)
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

    def packet_from_network(self, **kwargs):
        return kwargs

    def packet_to_network(self, packet):
        return packet['raw']

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


    def inject_discovery_packet(self,switch, port):
        try:
            hw_addr = self.switches[switch]['ports'][port]
            packet = self.create_discovery_packet(switch, port, hw_addr)
            core.openflow.sendToDPID(switch, packet)
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


    def send_to_switch(self,packet):
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
        except RuntimeError, e:
            print "ERROR:send_to_switch: %s to switch %d" % (str(e),switch)
            # TODO - ATTEMPT TO RECONNECT SOCKET
        except KeyError, e:
            print "ERROR:send_to_switch: No connection to switch %d available" % switch
            # TODO - IF SOCKET RECONNECTION, THEN WAIT AND RETRY

    def build_of_match(self,switch,inport,pred):
        ### BUILD OF MATCH
        match = of.ofp_match()
        match.in_port = inport
        if 'srcmac' in pred:
            match.dl_src = pred['srcmac']
        if 'dstmac' in pred:
            match.dl_dst = pred['dstmac']
        if 'ethtype' in pred:
            match.dl_type = pred['ethtype']
        if 'vlan_id' in pred:
            match.dl_vlan = pred['vlan_id']
        if 'vlan_pcp' in pred:
            match.dl_vlan_pcp = pred['vlan_pcp']
        if 'protocol' in pred:
            match.nw_proto = pred['protocol']
        if 'srcip' in pred:
            match.set_nw_src(pred['srcip'])
        if 'dstip' in pred:
            match.set_nw_dst(pred['dstip'])
        if 'tos' in pred:
            match.nw_tos = pred['tos']
        if 'srcport' in pred:
            match.tp_src = pred['srcport']
        if 'dstport' in pred:
            match.tp_dst = pred['dstport']
        return match

    def build_of_actions(self,inport,action_list):
        ### BUILD OF ACTIONS
        of_actions = []
        for actions in action_list:
            outport = actions['outport']
            del actions['outport']
            if 'srcmac' in actions:
                of_actions.append(of.ofp_action_dl_addr.set_src(actions['srcmac']))
            if 'dstmac' in actions:
                of_actions.append(of.ofp_action_dl_addr.set_dst(actions['dstmac']))
            if 'srcip' in actions:
                of_actions.append(of.ofp_action_nw_addr.set_src(actions['srcip']))
            if 'dstip' in actions:
                of_actions.append(of.ofp_action_nw_addr.set_dst(actions['dstip']))
            if 'srcport' in actions:
                of_actions.append(of.ofp_action_tp_port.set_src(actions['srcport']))
            if 'dstport' in actions:
                of_actions.append(of.ofp_action_tp_port.set_dst(actions['dstport']))
            if 'vlan_id' in actions:
                if actions['vlan_id'] is None:
                    of_actions.append(of.ofp_action_strip_vlan())
                else:
                    of_actions.append(of.ofp_action_vlan_vid(vlan_vid=actions['vlan_id']))
            if 'vlan_pcp' in actions:
                if actions['vlan_pcp'] is None:
                    if not actions['vlan_id'] is None:
                        raise RuntimeError("vlan_id and vlan_pcp must be set together!")
                    pass
                else:
                    of_actions.append(of.ofp_action_vlan_pcp(vlan_pcp=actions['vlan_pcp']))
            if (not inport is None) and (outport == inport):
                of_actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
            else:
                of_actions.append(of.ofp_action_output(port=outport))
        return of_actions

    def install_flow(self,pred,priority,action_list):
        switch = pred['switch']
        if 'inport' in pred:        
            inport = pred['inport']
        else:
            inport = None
        match = self.build_of_match(switch,inport,pred)
        of_actions = self.build_of_actions(inport,action_list)
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                              priority=priority,
                              idle_timeout=of.OFP_FLOW_PERMANENT,
                              hard_timeout=of.OFP_FLOW_PERMANENT,
                              match=match,
                              actions=of_actions)
        try:
            self.switches[switch]['connection'].send(msg)
        except RuntimeError, e:
            print "WARNING:install_flow: %s to switch %d" % (str(e),switch)
        except KeyError, e:
            print "WARNING:install_flow: No connection to switch %d available" % switch

    def delete_flow(self,pred,priority):
        switch = pred['switch']
        if 'inport' in pred:        
            inport = pred['inport']
        else:
            inport = None
        match = self.build_of_match(switch,inport,pred)
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT,
                              priority=priority,
                              match=match)
        try:
            self.switches[switch]['connection'].send(msg)
        except RuntimeError, e:
            print "WARNING:delete_flow: %s to switch %d" % (str(e),switch)
        except KeyError, e:
            print "WARNING:delete_flow: No connection to switch %d available" % switch

    def barrier(self,switch):
        b = of.ofp_barrier_request()
        self.switches[switch]['connection'].send(b) 

    def flow_stats_request(self,switch):
        sr = of.ofp_stats_request()
        sr.body = of.ofp_flow_stats_request()
        match = of.ofp_match()
        sr.body.match = match
        sr.body.table_id = 0xff
        sr.body.out_port = of.OFPP_NONE
        self.switches[switch]['connection'].send(sr) 
    
    def clear(self,switch=None):
        if switch is None:
            for switch in self.switches.keys():
                self.clear(switch)
        else:
            d = of.ofp_flow_mod(command = of.OFPFC_DELETE)
            self.switches[switch]['connection'].send(d) 

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


    def of_match_to_dict(self, m):
        h = {}
        if not m.in_port is None:
            h["inport"] = m.in_port
        if not m.dl_src is None:
            h["srcmac"] = m.dl_src.toRaw()
        if not m.dl_dst is None:
            h["dstmac"] = m.dl_dst.toRaw()
        if not m.dl_type is None:
            h["ethtype"] = m.dl_type
        if not m.dl_vlan is None:
            h["vlan_id"] = m.dl_vlan
        if not m.dl_vlan_pcp is None:
            h["vlan_pcp"] = m.dl_vlan_pcp
        if not m.nw_src is None:
            h["srcip"] = m.nw_src.toRaw()
        if not m.nw_dst is None:
            h["dstip"] = m.nw_dst.toRaw()
        if not m.nw_proto is None:
            h["protocol"] = m.nw_proto
        if not m.nw_tos is None:
            h["tos"] = m.nw_tos
        if not m.tp_src is None:
            h["srcport"] = m.tp_src
        if not m.tp_dst is None:
            h["dstport"] = m.tp_dst
        return h

    def of_actions_to_dicts(self, actions):
        action_dicts = []
        for a in actions:
            d = {}
            if a.type == of.OFPAT_OUTPUT:
                d['output'] = a.port
            elif a.type == of.OFPAT_ENQUEUE:
                d['enqueue'] = a.port
            elif a.type == of.OFPAT_STRIP_VLAN:
                d['strip_vlan_id'] = 0
            elif a.type == of.OFPAT_SET_VLAN_VID:
                d['vlan_id'] = a.vlan_vid
            elif a.type == of.OFPAT_SET_VLAN_PCP:
                d['vlan_pcp'] = a.vlan_pcp
            elif a.type == of.OFPAT_SET_DL_SRC:
                d['srcmac'] = a.dl_addr.toRaw()
            elif a.type == of.OFPAT_SET_DL_DST:
                d['dstmac'] = a.dl_addr.toRaw()
            elif a.type == of.OFPAT_SET_NW_SRC:
                d['srcip'] = a.nw_addr.toRaw()
            elif a.type == of.OFPAT_SET_NW_DST:
                d['dstip'] = a.nw_addr.toRaw()
            elif a.type == of.OFPAT_SET_NW_TOS:
                d['tos'] = a.nw_tos
            elif a.type == of.OFPAT_SET_TP_SRC:
                d['srcport'] = a.tp_port
            elif a.type == of.OFPAT_SET_TP_DST:
                d['dstport'] = a.tp_port
            action_dicts.append(d)
        return action_dicts

    def _handle_FlowStatsReceived (self, event):
        dpid = event.connection.dpid
        def handle_ofp_flow_stat(flow_stat):
            flow_stat_dict = {}
            flow_stat_dict['table_id'] = flow_stat.table_id 
            #flow_stat.match
            flow_stat_dict['duration_sec'] = flow_stat.duration_sec
            flow_stat_dict['duration_nsec'] = flow_stat.duration_nsec
            flow_stat_dict['priority'] = flow_stat.priority
            flow_stat_dict['idle_timeout'] = flow_stat.idle_timeout
            flow_stat_dict['hard_timeout'] = flow_stat.hard_timeout
            flow_stat_dict['cookie'] = flow_stat.cookie    
            flow_stat_dict['packet_count'] = flow_stat.packet_count
            flow_stat_dict['byte_count'] = flow_stat.byte_count
            match = self.of_match_to_dict(flow_stat.match)
            flow_stat_dict['match'] = match
            actions = self.of_actions_to_dicts(flow_stat.actions)
            flow_stat_dict['actions'] = actions
            return flow_stat_dict
        flow_stats = [handle_ofp_flow_stat(s) for s in event.stats]
        self.send_to_pyretic(['flow_stats_reply',dpid,flow_stats])

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

        received = self.packet_from_network(switch=event.dpid, inport=event.ofp.in_port, raw=event.data)
        self.send_to_pyretic(['packet',received])
        
       
def launch():

    class asyncore_loop(threading.Thread):
        def run(self):
            asyncore.loop()

    POXClient()
    al = asyncore_loop()
    al.start()



    
    
