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

from pyretic.core.network import Network
import pyretic.core.util as util
from pyretic.core.netcore import *
from pyretic.core.network import *


import threading
import ipdb


class Runtime(object):
    def __init__(self, backend, main, show_traces, debug_packet_in, kwargs):
        self.network = ConcreteNetwork(self)
        self.policy = main(**kwargs)
        self.policy.set_network(self.network)
        self.debug_packet_in = debug_packet_in
        self.show_traces = show_traces
        self.backend = backend
        self.backend.runtime = self
        self.vlan_to_extended_values_db = {}
        self.extended_values_to_vlan_db = {}
        self.extended_values_lock = threading.RLock()
        self.threads = set()

    def network_update(self,ignore):
        try:
            self.policy.set_network(self.network)
        except:
            pass

    def handle_switch_join(self,switch_id):
        self.network.switch_joins.signal(switch_id)

    def handle_switch_part(self,switch_id):
        self.network.switch_parts.signal(switch_id)

    def handle_port_join(self,switch_id,port_id,conf_up,stat_up):
        self.network.port_joins.signal((switch_id,port_id,conf_up,stat_up))

    def handle_port_mod(self, switch, port_no, config, status):
        self.network.port_mods.signal((switch, port_no, config, status))

    def handle_port_part(self, switch, port_no):
        self.network.port_parts.signal((switch, port_no))

    def handle_link_update(self, s1, p_no1, s2, p_no2):
        self.network.link_updates.signal((s1, p_no1, s2, p_no2))

    def handle_packet_in(self, concrete_pkt):

        pyretic_pkt = self.concrete2pyretic(concrete_pkt)

        if self.debug_packet_in:
            ipdb.set_trace()
        
        with ipdb.launch_ipdb_on_exception():
            output = self.policy.eval(pyretic_pkt)
            
        if self.show_traces:
            print "<<<<<<<<< RECV <<<<<<<<<<<<<<<<<<<<<<<<<<"
            print util.repr_plus([pyretic_pkt], sep="\n\n")
            print
            print ">>>>>>>>> SEND >>>>>>>>>>>>>>>>>>>>>>>>>>"
            print util.repr_plus(output.elements(), sep="\n\n")
            print
        
        for pkt in output.elements():
            self.send_packet(pkt)
        
    def pyretic2concrete(self,packet):
        concrete_packet = ConcretePacket()
        for header in ['switch','inport','outport']:
            try:
                concrete_packet[header] = packet[header]
                packet = packet.pop(header)
            except:
                pass
        for header in native_headers:
            try:
                val = packet[header]
                concrete_packet[header] = val
            except:
                pass
        extended_values = extended_values_from(packet)
        if extended_values:
            vlan_id, vlan_pcp = self.encode_extended_values(extended_values)
            concrete_packet['vlan_id'] = vlan_id
            concrete_packet['vlan_pcp'] = vlan_pcp
        return concrete_packet

    def concrete2pyretic(self,packet):
        def convert(h,val):
            if h in ['srcmac','dstmac']:
                return MAC(val)
            elif h in ['srcip','dstip']:
                return IP(val)
            else:
                return val
        try:
            vlan_id = packet['vlan_id']
            vlan_pcp = packet['vlan_pcp']
            extended_values = self.decode_extended_values(vlan_id, vlan_pcp)
        except KeyError:
            extended_values = util.frozendict()       
        pyretic_packet = Packet(extended_values)
        d = { h : convert(h,v) for (h,v) in packet.items() if not h in ['vlan_id','vlan_pcp'] }
        return pyretic_packet.pushmany(d)


    def send_packet(self,pyretic_packet):
        concrete_packet = self.pyretic2concrete(pyretic_packet)
        self.backend.send_packet(concrete_packet)


    def inject_discovery_packet(self,dpid, port):
        self.backend.inject_discovery_packet(dpid,port)


    def encode_extended_values(self, extended_values):
        with self.extended_values_lock:
            vlan = self.extended_values_to_vlan_db.get(extended_values)
            if vlan is not None:
                return vlan
            r = len(self.extended_values_to_vlan_db)
            pcp = r & 0b111000000000000
            vid = r & 0b000111111111111
            self.extended_values_to_vlan_db[extended_values] = (vid, pcp)
            self.vlan_to_extended_values_db[(vid, pcp)] = extended_values
            return (vid, pcp)

        
    def decode_extended_values(self, vid, pcp):
        with self.extended_values_lock:
            extended_values = self.vlan_to_extended_values_db.get((vid, pcp))
            assert extended_values is not None, "use of vlan that pyretic didn't allocate! not allowed."
            return extended_values


################################################################################
# Extended Values
################################################################################

native_headers = ["srcmac", "dstmac", "srcip", "dstip", "tos", "srcport", "dstport",
                 "ethtype", "protocol", "payload"]

@util.cached
def extended_values_from(packet):
    extended_values = {}
    for k, v in packet.header.items():
        if k not in native_headers and v:
            extended_values[k] = v
        elif v and len(v) > 1:
            extended_values[k] = v[1:]
    return util.frozendict(extended_values)


################################################################################
# Concrete Packet and Network
################################################################################

class ConcretePacket(dict):
    def to_ascii(self):
        def convert(h,v):
            if h in ['srcip','dstip','srcmac','dstmac']:
                return repr(v)
            else:
                return v
        return { h : convert(h,v) for (h,v) in self.items() }


DEBUG_TOPO_DISCOVERY = False
class ConcreteNetwork(Network):
    def __init__(self,runtime=None):
        super(ConcreteNetwork,self).__init__()
        self.runtime = runtime
        self._topology.notify(runtime.network_update)
        self.events = ["switch_joins", "switch_parts",
                       "port_joins", "port_parts",
                       "port_mods", "link_updates"]
        for event in self.events:
            e = util.Event()
            setattr(self, event, e)
            e.notify(getattr(self, "_handle_%s" % event))

    def inject_packet(self, packet):
        self.runtime.send_packet(packet)

    #
    # Topology Detection
    #
           
    def inject_discovery_packet(self, dpid, port_no):
        self.runtime.inject_discovery_packet(dpid, port_no)

        
    def _handle_switch_joins(self, switch):
        if DEBUG_TOPO_DISCOVERY:  print "_handle_switch_joins"
        ## PROBABLY SHOULD CHECK TO SEE IF SWITCH ALREADY IN TOPOLOGY
        self.topology.add_node(switch, ports={})  
        print "OpenFlow switch %s connected" % switch
        if DEBUG_TOPO_DISCOVERY:  print self.topology
        self._topology.signal_mutation()

    def remove_associated_link(self,location):
        port = self.topology.node[location.switch]["ports"][location.port_no]
        if not port.linked_to is None:
            # REMOVE CORRESPONDING EDGE
            try:      
                self.topology.remove_edge(location.switch, port.linked_to.switch)
            except:
                pass  # ALREADY REMOVED
            # UNLINK LINKED_TO PORT
            try:      
                self.topology.node[port.linked_to.switch]["ports"][port.linked_to.port_no].linked_to = None
            except KeyError:
                pass  # LINKED TO PORT ALREADY DELETED
            # UNLINK SELF
            self.topology.node[location.switch]["ports"][location.port_no].linked_to = None
        
    def _handle_switch_parts(self, switch):
        print "OpenFlow switch %s disconnected" % switch
        if DEBUG_TOPO_DISCOVERY:  print "_handle_switch_parts"
        # REMOVE ALL ASSOCIATED LINKS
        for port_no in self.topology.node[switch]["ports"].keys():
            self.remove_associated_link(Location(switch,port_no))
        self.topology.remove_node(switch)
        if DEBUG_TOPO_DISCOVERY:  print self.topology
        self._topology.signal_mutation()
        
    def _handle_port_joins(self, (switch, port_no, config, status)):
        if DEBUG_TOPO_DISCOVERY:  print "_handle_port_joins %s:%s:%s:%s" % (switch, port_no, config, status)
        self.topology.node[switch]["ports"][port_no] = Port(port_no,config,status)
        if config or status:
            self.inject_discovery_packet(switch,port_no)
            if DEBUG_TOPO_DISCOVERY:  print self.topology
            self._topology.signal_mutation()

    def _handle_port_parts(self, (switch, port_no)):
        if DEBUG_TOPO_DISCOVERY:  print "_handle_port_parts"
        try:
            self.remove_associated_link(Location(switch,port_no))
            del self.topology.node[switch]["ports"][port_no]
            if DEBUG_TOPO_DISCOVERY:  print self.topology
            self._topology.signal_mutation()
        except KeyError:
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY _handle_switch_parts
        
    def _handle_port_mods(self, (switch, port_no, config, status)):
        if DEBUG_TOPO_DISCOVERY:  print "_handle_port_mods %s:%s:%s:%s" % (switch, port_no, config, status)
        # GET PREV VALUES
        try:
            prev_config = self.topology.node[switch]["ports"][port_no].config
            prev_status = self.topology.node[switch]["ports"][port_no].status
        except KeyError:
            print "KeyError CASE!!!!!!!!"
            self.port_down(switch, port_no)
            return

        # UPDATE VALUES
        self.topology.node[switch]["ports"][port_no].config = config
        self.topology.node[switch]["ports"][port_no].status = status

        # DETERMINE IF/WHAT CHANGED
        if (prev_config and not config):
            self.port_down(switch, port_no)
        if (prev_status and not status):
            self.port_down(switch, port_no,double_check=True)

        if (not prev_config and config) or (not prev_status and status):
            self.port_up(switch, port_no)

    def port_up(self, switch, port_no):
        if DEBUG_TOPO_DISCOVERY:  print "port_up %s:%s"
        self.inject_discovery_packet(switch,port_no)
        if DEBUG_TOPO_DISCOVERY:  print self.topology
        self._topology.signal_mutation()

    def port_down(self, switch, port_no, double_check=False):
        if DEBUG_TOPO_DISCOVERY: print "port_down %s:%s:double_check=%s"
        try:
            self.remove_associated_link(Location(switch,port_no))
            if DEBUG_TOPO_DISCOVERY:  print self.topology
            self._topology.signal_mutation()
            if double_check: self.inject_discovery_packet(switch,port_no)
        except KeyError:  
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY _handle_switch_parts

    def _handle_link_updates(self, (s1, p_no1, s2, p_no2)):
        if DEBUG_TOPO_DISCOVERY:  print "_handle_link_updates"
        try:
            p1 = self.topology.node[s1]["ports"][p_no1]
            p2 = self.topology.node[s2]["ports"][p_no2]
        except KeyError:
            if DEBUG_TOPO_DISCOVERY: print "node doesn't yet exist"
            return  # at least one of these ports isn't (yet) in the topology

        # LINK ALREADY EXISTS
        try:
            link = self.topology[s1][s2]

            # LINK ON SAME PORT PAIR
            if link[s1] == p_no1 and link[s2] == p_no2:         
                if p1.possibly_up() and p2.possibly_up():   
                    if DEBUG_TOPO_DISCOVERY: print "nothing to do"
                    return                                      #   NOTHING TO DO
                else:                                           # ELSE RAISE AN ERROR - SOMETHING WEIRD IS HAPPENING
                    raise RuntimeError('Link update w/ bad port status %s,%s' % (p1,p2))
            # LINK PORTS CHANGED
            else:                                               
                # REMOVE OLD LINKS
                if link[s1] != p_no1:
                    self.remove_associated_link(Location(s1,link[s1]))
                if link[s2] != p_no2:
                    self.remove_associated_link(Location(s2,link[s2]))

        # COMPLETELY NEW LINK
        except KeyError:     
            pass
        
        # ADD LINK IF PORTS ARE UP
        if p1.possibly_up() and p2.possibly_up():
            self.topology.node[s1]["ports"][p_no1].linked_to = Location(s2,p_no2)
            self.topology.node[s2]["ports"][p_no2].linked_to = Location(s1,p_no1)   
            self.topology.add_edge(s1, s2, {s1: p_no1, s2: p_no2})
            
        # IF REACHED, WE'VE REMOVED AN EDGE, OR ADDED ONE, OR BOTH
        if DEBUG_TOPO_DISCOVERY:  print self.topology
        self._topology.signal_mutation()

