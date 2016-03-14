
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
import pox.openflow.nicira as nx
from pox.core import core
from pox.lib import revent, addresses as packetaddr, packet as packetlib
from pox.lib.packet.ethernet      import ethernet
from pox.lib.packet.ethernet      import LLDP_MULTICAST, NDP_MULTICAST
from pox.lib.packet.lldp          import lldp, chassis_id, port_id, end_tlv
from pox.lib.packet.lldp          import ttl, system_description

from pyretic.backend.comm import *
from pyretic.mt_config.mtcs import *

import time

IP_TYPE = 0x800
ARP_TYPE = 0x806

# TODO: This "next table" port number is custom; not OF compliant.
# Since it also appears in the pyretic frontend (network.py), it will require
# updating in both places eventually.
CUSTOM_NEXT_TABLE_PORT = 0xfff4

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
        # If there are delays in receiving messages from the other side, and
        # they are because of large message sizes, increase this buffer size.
        self.ac_in_buffer_size = 4096 * 50
        self.ac_out_buffer_size = 4096 * 50
        self.set_terminator(TERM_CHAR)
        self.start_time = 0
        self.interval = 0
        self.total_interval = 0
        self.num_intervals  = 0
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

        # Set up time for starting rule installs.
        if msg[0] == 'reset_install_time':
            self.start_time = time.time()
            # TODO(): need logging levels in of client also!
            # print "[path_queries] Last rule interval:", self.interval,
            self.total_interval += self.interval
            self.num_intervals  += 1
            # print "total:", self.total_interval,
            # print "num:", self.num_intervals
            self.interval = 0

        # USE DESERIALIZED MSG
        elif msg[0] == 'inject_discovery_packet':
            switch = msg[1]
            port = msg[2]
            self.of_client.inject_discovery_packet(switch,port)
        elif msg[0] == 'packet':
            packet = self.dict2OF(msg[1])
            self.of_client.send_to_switch(packet)
        elif msg[0] == 'install' or msg[0] == 'modify':
            pred = self.dict2OF(msg[1])
            priority = int(msg[2])
            actions = map(self.dict2OF,msg[3])
            cookie = int(msg[4])
            notify = bool(msg[5])
            table_id = int(msg[6])
            if msg[0] == 'install':
                self.of_client.install_flow(pred,priority,actions,cookie,notify,table_id)
            else:
                self.of_client.modify_flow(pred,priority,actions,cookie,notify,table_id)
            self.interval = time.time() - self.start_time
        elif msg[0] == 'delete':
            pred = self.dict2OF(msg[1])
            priority = int(msg[2])
            self.of_client.delete_flow(pred,priority)
        elif msg[0] == 'clear':
            switch = int(msg[1])
            table_id = int(msg[2])
            self.of_client.clear(switch, table_id)
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
    def __init__(self,show_traces=False,debug_packet_in=False,ip='127.0.0.1',port=BACKEND_PORT,use_nx=False,pipeline=None):
        self.switches = {}
        self.show_traces = show_traces
        self.debug_packet_in = debug_packet_in
        self.use_nx = use_nx
        if pipeline:
            pipe_config_fun = globals()[str(pipeline)]
            self.pipeline = globals()[str(pipeline)]()
        else:
            self.pipeline = default_pipeline()
        self.packetno = 0
        self.channel_lock = threading.Lock()
        self.send_time = 0.0

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
        outport   = packet["port"]
        # inport is unnecessary unless we are asking the switch to process the
        # packet through a flow table. Since this is a direct packet-out through
        # a switch interface, it's ok to set some garbage value here.
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
        if 'ethtype' in pred and pred['ethtype']==0x86dd:
            match = nx.nx_match()
            if inport:
                match.in_port = inport
            if 'ethtype' in pred:
                match.eth_type = pred['ethtype']
        else:
            match = of.ofp_match()
            match.in_port = inport
            if 'ethtype' in pred:
                match.dl_type = pred['ethtype']

        if 'srcmac' in pred:
            match.dl_src = pred['srcmac']
        if 'dstmac' in pred:
            match.dl_dst = pred['dstmac']
        if 'vlan_id' in pred:
            match.dl_vlan = pred['vlan_id']
            # Checks to ensure correct use of VLANs with single-stage tables
            assert 'vlan_total_stages' in pred
            assert pred['vlan_total_stages'] == 1, ("Cannot use multi-stage "
                "virtual header fields without enabling the multistage (--nx) "
                "option.")
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

    def build_nx_match(self,switch,inport,pred,table_id):
        ### BUILD NX MATCH
        match = nx.nx_match()
        if inport:
            if table_id == 0:
                match.of_in_port = inport
            else:
                """NXM_NX_REG2 is the per-packet metadata register where we store the current
                port value of the packet, including actions from previous tables' forwarding
                actions.
                """
                match.reg2 = inport

        if 'srcmac' in pred:
            match.of_eth_src = packetaddr.EthAddr(pred['srcmac'])
        if 'dstmac' in pred:
            match.of_eth_dst = packetaddr.EthAddr(pred['dstmac'])
        if 'vlan_id' in pred:
            assert 'vlan_pcp' in pred
            assert 'vlan_offset' in pred and 'vlan_nbits' in pred
            assert 'vlan_total_stages' in pred
            # Setting the 16-bit TCI: (from highest to least significant bits):
            # 3 bits vlan_pcp
            # 1 bit CFI forced to 1
            # 12 bits vlan_id
            # Ref: manpages.ubuntu.com/manpages/trusty/man8/ovs-ofctl.8.html
            if table_id == 0:
                match.dl_vlan = pred['vlan_id']
                match.dl_vlan_pcp = pred['vlan_pcp']
            else:
                """NXM_NX_REG3 is where we store the intermittent value of
                VLAN. The VLAN ID and PCP are loaded as one contiguous set of 15
                bits in the register. See `vlan_load_reg()` for more details.

                Further, whenever the VLAN is matched, we also check whether the
                packet has a VLAN in the first place, by checking the VLAN CFI
                bit, which is now loaded in bit 15 in the register.
                """
                vlan_16bit = ((int(pred['vlan_pcp']) << 12) |
                              0x8000 |
                              (int(pred['vlan_id'])))
                vlan_mask = ((((1 << pred['vlan_nbits']) - 1) <<
                              pred['vlan_offset']) | 0x8000)
                # zero out the unmasked value bits
                # Ref: ~/pox/pox/openflow/nicira.py#L1817
                vlan_value = vlan_16bit & vlan_mask
                match.append(nx.NXM_NX_REG3(value=vlan_value, mask=vlan_mask))
        if 'ethtype' in pred:
            match.of_eth_type = pred['ethtype']
        if 'srcip' in pred:
            assert 'ethtype' in pred
            if pred['ethtype'] == IP_TYPE:
                match.NXM_OF_IP_SRC = pred['srcip']
            elif pred['ethtype'] == ARP_TYPE:
                match.arp_spa = packetaddr.IPAddr(pred['srcip'])
            else:
                raise RuntimeError("Unknown ethtype for srcip match!")
        if 'dstip' in pred:
            assert 'ethtype' in pred
            if pred['ethtype'] == IP_TYPE:
                match.NXM_OF_IP_DST = pred['dstip']
            elif pred['ethtype'] == ARP_TYPE:
                match.arp_tpa = packetaddr.IPAddr(pred['dstip'])
            else:
                raise RuntimeError("Unknown ethtype for dstip match!")
        if 'tos' in pred:
            match.of_ip_tos = pred['tos']
        if 'protocol' in pred:
            match.of_ip_proto = pred['protocol']
        if 'srcport' in pred:
            assert 'protocol' in pred
            match.append(nx.NXM_OF_TCP_SRC(pred['srcport']))
        if 'dstport' in pred:
            assert 'protocol' in pred
            match.append(nx.NXM_OF_TCP_DST(pred['dstport']))
        return match

    def build_of_actions(self,inport,action_list, debug=False):
        ### BUILD OF ACTIONS
        of_actions = []
        for actions in action_list:
            if debug:
                print "pox_client: build_of_actions: Actions:", actions
            outport = actions['port']
            del actions['port']
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
                    assert 'vlan_total_stages' in actions
                    assert actions['vlan_total_stages'] == 1
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

    def build_nx_actions(self,inport,action_list,table_id,pipeline,debug=False):
        ### BUILD NX ACTIONS
        of_actions = []
        ctlr_outport = False # there is a controller outport action
        phys_outports = list() # list of physical outports to forward out of
        possibly_resubmit_next_table = False # should packet be passed on to next table?
        atleast_one_action = False

        # vlan handling flags
        vlan_removed = False
        vlan_written = {}

        if debug:
            print "pox_client: build_nx_actions: Received actions:"
            print action_list

        for actions in action_list:
            atleast_one_action = True
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
                    vlan_removed = True
                else:
                    assert 'vlan_pcp' in actions
                    assert 'vlan_offset' in actions
                    assert 'vlan_nbits' in actions
                    vlan_written = {k: actions['vlan_' + k] for k in
                                      ['pcp', 'offset', 'nbits', 'id']}
            if 'vlan_pcp' in actions:
                assert 'vlan_id' in actions, "vlan_id and vlan_pcp must be set together"
            assert 'port' in actions
            outport = actions['port']

            if outport == of.OFPP_CONTROLLER:
                ctlr_outport = True
            else:
                """ There is either a physical output action (i.e., on a
                non-controller port), or a "send to next table" action."""
                possibly_resubmit_next_table = True
                if outport != CUSTOM_NEXT_TABLE_PORT:
                    phys_outports.append(outport)
                """ Otherwise there are no physical outports; just a possibility
                of resubmitting to the next table. Pass. """

        """Construct routines to move packet VLAN into the register, do a masked write
        into the register, and to write back the register into the packet.
        """
        vlan_reg = nx.NXM_NX_REG3
        def vlan_load_reg():
            if vlan_removed:
                of_actions.append(nx.nx_reg_load(dst=vlan_reg,
                                                 value=0, nbits=16))
            else:
                """The load/unload operations are complicated to simplify the intermediate
                masked write operations. This is really helpful with multiple
                stages: it's easier to do a single masked write per stage; there
                are more stages which do the former than load/unload.

                Basically what is happening is the following mapping of
                different parts of the VLAN_TCI field into the register
                (typically NXM_NX_REG3) as follows:

                REG3:        CFI PCP2 PCP1 PCP0 ID11 ID10 ... ID1 ID0
                VLAN_TCI:    PCP2 PCP1 PCP0 CFI ID11 ID10 ... ID1 ID0

                This enables masked writes considering the VLAN as one
                *contiguous* 15 bit field, instead of breaking the masked write
                into two writes, one for the ID part and one for the PCP part
                (yuck!)
                """
                of_actions.append(nx.nx_reg_move(dst=vlan_reg,
                                                 src=nx.NXM_OF_VLAN_TCI,
                                                 dst_ofs=0, src_ofs=0,
                                                 nbits=12))
                of_actions.append(nx.nx_reg_move(dst=vlan_reg,
                                                 src=nx.NXM_OF_VLAN_TCI,
                                                 dst_ofs=12, src_ofs=13,
                                                 nbits=3))
                of_actions.append(nx.nx_reg_move(dst=vlan_reg,
                                                 src=nx.NXM_OF_VLAN_TCI,
                                                 dst_ofs=15, src_ofs=12,
                                                 nbits=1))

        def vlan_masked_write():
            if debug:
                print "pox_client: build_nx_actions: in rewrite function:"
                print vlan_removed, vlan_written
            if vlan_removed:
                if debug:
                    print "pox_client: build_nx_actions: VLAN was removed"
                of_actions.append(nx.nx_reg_load(dst=vlan_reg,
                                                 value=0, nbits=16))
            elif vlan_written:
                vlan_16bit = ((int(vlan_written['pcp']) << 12) |
                              (int(vlan_written['id'])))
                load_value = ((vlan_16bit >> vlan_written['offset']) &
                              ((1 << vlan_written['nbits'])-1))
                of_actions.append(nx.nx_reg_load(dst=vlan_reg,
                                                 value=load_value,
                                                 offset=vlan_written['offset'],
                                                 nbits=vlan_written['nbits']))
                of_actions.append(nx.nx_reg_load(dst=vlan_reg,
                                                 value=1,
                                                 offset=15,
                                                 nbits=1))

        def vlan_write_back():
            """ The write back operation is slightly complicated for reasons
            described under `vlan_load_reg()`. """
            if debug:
                print "pox_client: build_nx_actions: Writing back VLAN. The actions are:"
                print actions
            if table_id > 0:
                of_actions.append(nx.nx_reg_move(src=vlan_reg,
                                                 dst=nx.NXM_OF_VLAN_TCI,
                                                 src_ofs=0, dst_ofs=0,
                                                 nbits=12))
                of_actions.append(nx.nx_reg_move(src=vlan_reg,
                                                 dst=nx.NXM_OF_VLAN_TCI,
                                                 src_ofs=12, dst_ofs=13,
                                                 nbits=3))
                of_actions.append(nx.nx_reg_move(src=vlan_reg,
                                                 dst=nx.NXM_OF_VLAN_TCI,
                                                 src_ofs=15, dst_ofs=12,
                                                 nbits=1))

        """In general, actual packet forwarding may have to wait until the final table
        in the pipeline. This means we must determine if there is a "next" table
        that processes the packet from here, or if this is the last one.

        But first, the easy part. There are exactly three cases where a
        forwarding table *will* in fact "immediately forward" a packet according
        to the current rule (and all previous table stages that processed the
        packet), without waiting for any other further processing:

        (1) if the packet is dropped by the current rule,
        (2) if the packet is forwarded to the controller port, or
        (3) if this is the last stage of the pipeline.

        In the case of (1) and (2), packet forwarding may happen immediately and
        only depend on the current rule. But in (3), the forwarding decision
        must take the current rule as well as previous port changes into
        account, as follows:

        (a) if the current rule specifies an output port, forward the packet out
        of that port.

        (b) if the current rule does not specify an outport, then forward the
        packet out of the port using the value stored in the dedicated
        per-packet port register.

        If neither of (1)-(3) above is true, then we take the following
        approach:

        (a) if there is an outport set by this rule, write that value into the
        dedicated per-packet register that contains the current port the
        packet is in.

        (b) if there is no outport set by this rule, and if this is table id 0,
        move the value of the inport into the dedicated per-packet port
        register. This denotes that the packet is currently still on its inport.

        (c) resubmit the packet to the "next" table (according to the pipeline).
        """
        exists_next_table = table_id in pipeline.edges

        # Decide first on "immediate forwarding" conditions:
        immediately_fwd = True
        if not atleast_one_action: # (1) drop
            of_actions = []
        elif ctlr_outport: # (2) controller
            of_actions = []
            vlan_write_back()
            of_actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        elif possibly_resubmit_next_table and (not exists_next_table):
            # (3) last stage of pipeline
            vlan_masked_write()
            vlan_write_back()
            if len(phys_outports) > 0: # fwd out of latest assigned ports
                for p in phys_outports:
                    of_actions.append(of.ofp_action_output(port=p))
            else:
                # fwd out of stored port value
                of_actions.append(nx.nx_output_reg(reg=nx.NXM_NX_REG2,
                                                   nbits=16))
        elif (not exists_next_table) and (not possibly_resubmit_next_table):
            raise RuntimeError("Unexpected condition in multi-stage processing")
        else: # must resubmit packet to subsequent tables for processing
            immediately_fwd = False

        if immediately_fwd:
            return of_actions

        if debug:
            print "pox_client: build_nx_actions: Not the last stage."

        # Act on packet with knowledge that subsequent tables must process it
        assert (possibly_resubmit_next_table and exists_next_table and
                (not immediately_fwd))

        # 1. Handle VLAN writing for resubmitted packets
        if table_id == 0:
            vlan_load_reg()
        vlan_masked_write()

        # 2. Handle packet forwarding for resubmitted packets
        next_table = pipeline.edges[table_id]
        if len(phys_outports) > 0:
            # move port register to latest assigned port values
            for p in phys_outports:
                of_actions.append(nx.nx_reg_load(dst=nx.NXM_NX_REG2,
                                                 value=p, nbits=16))
                of_actions.append(nx.nx_action_resubmit.resubmit_table(
                    table=next_table))
        elif table_id == 0:
            # move the inport value to reg2.
            of_actions.append(nx.nx_reg_move(src=nx.NXM_OF_IN_PORT,
                                             dst=nx.NXM_NX_REG2,
                                             nbits=16))
            of_actions.append(nx.nx_action_resubmit.resubmit_table(
                table=next_table))
        else:
            of_actions.append(nx.nx_action_resubmit.resubmit_table(
                table=next_table))
        return of_actions

    def flow_mod_action(self,pred,priority,action_list,cookie,command,notify,table_id):
        switch = pred['switch']
        """ Set `inport` from matching predicate """
        if 'port' in pred:
            inport = pred['port']
        else:
            inport = None
        if self.use_nx:
            match = self.build_nx_match(switch,inport,pred,table_id)
        else:
            match = self.build_of_match(switch,inport,pred)
        if self.use_nx:
            debug = False # use for debugging specific rules in build_nx_actions
            of_actions = self.build_nx_actions(inport, action_list, table_id,
                                               self.pipeline, debug=debug)
        else:
            debug = False # use for debugging specific rules in build_of_actions
            of_actions = self.build_of_actions(inport, action_list, debug=debug)

        flags = 0
        if notify:
            flags = of.OFPFF_SEND_FLOW_REM

        if 'ethtype' in pred and pred['ethtype']==0x86dd:
            msg = nx.nx_flow_mod(command=command,
                                 priority=priority,
                                 idle_timeout=of.OFP_FLOW_PERMANENT,
                                 hard_timeout=of.OFP_FLOW_PERMANENT,
                                 match=nx.nx_match(match),
                                 flags=flags,
                                 cookie=cookie,
                                 actions=of_actions)

        elif self.use_nx:
            msg = nx.nx_flow_mod(command=command,
                                 priority=priority,
                                 idle_timeout=of.OFP_FLOW_PERMANENT,
                                 hard_timeout=of.OFP_FLOW_PERMANENT,
                                 match=match,
                                 flags=flags,
                                 cookie=cookie,
                                 actions=of_actions,
                                 table_id=table_id)

        else:
            msg = of.ofp_flow_mod(command=command,
                                  priority=priority,
                                  idle_timeout=of.OFP_FLOW_PERMANENT,
                                  hard_timeout=of.OFP_FLOW_PERMANENT,
                                  match=match,
                                  flags=flags,
                                  cookie=cookie,
                                  actions=of_actions)
        try:
            self.switches[switch]['connection'].send(msg)
        except RuntimeError, e:
            print "WARNING:install_flow: %s to switch %d" % (str(e),switch)
        except KeyError, e:
            print "WARNING:install_flow: No connection to switch %d available" % switch

    def install_flow(self,pred,priority,action_list,cookie,notify,table_id):
        self.flow_mod_action(pred,priority,action_list,cookie,of.OFPFC_ADD,notify,table_id)

    def modify_flow(self,pred,priority,action_list,cookie,notify,table_id):
        self.flow_mod_action(pred,priority,action_list,cookie,of.OFPFC_MODIFY_STRICT,notify,table_id)

    def delete_flow(self,pred,priority):
        switch = pred['switch']
        if 'port' in pred:
            inport = pred['port']
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
        try:
            self.switches[switch]['connection'].send(b)
        except KeyError, e:
            print "WARNING: couldn't send barrier to switch %s (%s)" % (
                str(switch), e)

    def flow_stats_request(self,switch):
        sr = of.ofp_stats_request()
        sr.body = of.ofp_flow_stats_request()
        match = of.ofp_match()
        sr.body.match = match
        sr.body.table_id = 0xff
        sr.body.out_port = of.OFPP_NONE
        try:
            self.switches[switch]['connection'].send(sr)
        except KeyError, e:
            print ( ("ERROR:flow_stats_request: No connection to switch %d" +
                     " available") % switch )
    
    def clear(self,switch=None,table_id=0):
        if switch is None:
            for switch in self.switches.keys():
                self.clear(switch)
        else:
            if self.use_nx:
                d = nx.nx_flow_mod(command = of.OFPFC_DELETE, table_id=table_id)
            else:
                d = of.ofp_flow_mod(command = of.OFPFC_DELETE)
            self.switches[switch]['connection'].send(d) 

    def __nx_switch_pipeline_init(self, dpid, p):
        """ Initialize switch `dpid` according to the input pipeline
        configuration `p`. """
        """ Clear all tables; install default actions. """
        for t in range(0, p.num_tables):
            msg = nx.nx_flow_mod(command=of.OFPFC_DELETE, table_id=t)
            self.switches[dpid]['connection'].send(msg)
            msg = nx.nx_flow_mod()
            msg.table_id = t
            msg.priority = 1
            msg.match = nx.nx_match()
            if (t+1) < p.num_tables and t in p.edges:
                """ If not last table in the pipeline, fallthrough to next. """
                dst_t = p.edges[t]
                msg.actions.append(nx.nx_action_resubmit.resubmit_table(table=dst_t))
            else:
                """ If last table in pipeline, or no further edges, send to
                controller. """
                msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            self.switches[dpid]['connection'].send(msg)

    def _handle_ConnectionUp(self, event):
        assert event.dpid not in self.switches
        
        self.switches[event.dpid] = {}
        self.switches[event.dpid]['connection'] = event.connection
        self.switches[event.dpid]['ports'] = {}

        if self.use_nx:
            """ Enable nicira packet-ins (e.g., to get rule cookies) """
            msg = nx.nx_packet_in_format()
            self.switches[event.dpid]['connection'].send(msg)
            """ Enable multi-stage table with nicira extensions """
            msg = nx.nx_flow_mod_table_id()
            self.switches[event.dpid]['connection'].send(msg)
            self.__nx_switch_pipeline_init(event.dpid, self.pipeline)
        else:
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
                PORT_TYPE = self.active_ofp_port_features(port.curr)
                self.send_to_pyretic(['port','join',event.dpid, port.port_no, CONF_UP, STAT_UP, PORT_TYPE])                        
   
        self.send_to_pyretic(['switch','join',event.dpid,'END'])

                        
    def _handle_ConnectionDown(self, event):
        assert event.dpid in self.switches

        del self.switches[event.dpid]
        self.send_to_pyretic(['switch','part',event.dpid])


    def of_match_to_dict(self, m):
        h = {}
        if not m.in_port is None:
            h["port"] = m.in_port
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
                PORT_TYPE =  self.active_ofp_port_features(port.curr)
                self.send_to_pyretic(['port','join',event.dpid, port.port_no, CONF_UP, STAT_UP, PORT_TYPE])                        
            elif event.deleted:
                try:
                    del self.switches[event.dpid]['ports'][event.port] 
                except KeyError:
                    pass  # SWITCH ALREADY DELETED
                self.send_to_pyretic(['port','part',event.dpid,event.port])
            elif event.modified:
                CONF_UP = not 'OFPPC_PORT_DOWN' in self.active_ofp_port_config(port.config)
                STAT_UP = not 'OFPPS_LINK_DOWN' in self.active_ofp_port_state(port.state)
                PORT_TYPE = self.active_ofp_port_features(port.curr)
                if not CONF_UP:
                    self.send_to_pyretic(['port','part',event.dpid,event.port])
                else:
                    self.send_to_pyretic(['port','join',event.dpid, port.port_no, CONF_UP, STAT_UP, PORT_TYPE])                        
            else:
                raise RuntimeException("Unknown port status event")

    def _handle_FlowRemoved(self, event):
        dpid = event.connection.dpid
        ofp = event.ofp
        flow_stat_dict = {}
        flow_stat_dict['match'] = self.of_match_to_dict(ofp.match)
        flow_stat_dict['cookie'] = ofp.cookie
        flow_stat_dict['priority'] = ofp.priority
        flow_stat_dict['timeout'] = event.timeout
        flow_stat_dict['hard_timeout'] = event.hardTimeout
        flow_stat_dict['idle_timeout'] = event.idleTimeout
        flow_stat_dict['deleted'] = event.deleted
        flow_stat_dict['duration_sec'] = ofp.duration_sec
        flow_stat_dict['duration_nsec'] = ofp.duration_nsec
        flow_stat_dict['idle_timeout'] = ofp.idle_timeout
        flow_stat_dict['packet_count'] = ofp.packet_count
        flow_stat_dict['byte_count'] = ofp.byte_count
        self.send_to_pyretic(['flow_removed', dpid, flow_stat_dict])

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

        if self.use_nx:
            assert isinstance(event.ofp, nx.nxt_packet_in)
            cookie = event.ofp.cookie
            reg2_entry = event.ofp.match.find(nx.NXM_NX_REG2)
            """If the reg2 value is valid, it is not necessary that a policy set a port
            field on this packet already. It might just be the inport on which
            the packet came in, which was copied into the reg2 register. So, the
            name of this raw_pkt field should rather be `port` as opposed to
            `outport`.
            """
            if reg2_entry:
                port = reg2_entry.value
            else:
                port = event.ofp.in_port
        else:
            cookie = 0
            port = event.ofp.in_port

        received = self.packet_from_network(switch=event.dpid, port=port, raw=event.data)
        self.send_to_pyretic(['packet',received,cookie])
        
       
def launch(use_nx=False, pipeline=None):

    class asyncore_loop(threading.Thread):
        def run(self):
            asyncore.loop()

    POXClient(use_nx=use_nx,pipeline=pipeline)
    al = asyncore_loop()
    al.start()



    
    
