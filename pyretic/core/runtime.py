
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

import pyretic.core.util as util
from pyretic.core.language import *
from pyretic.core.network import *
from tools.logger import simpleLogger

import threading
try:
    import ipdb as debugger
    USE_IPDB=True
except:
    import pdb as debugger
    import traceback, sys
    USE_IPDB=False


class Runtime(object):
    def __init__(self, backend, main, kwargs, mode='interpreted', verbosity='normal', 
                 show_traces=False, debug_packet_in=False):   
        
        self.debug = True
        #self.trace = simpleLogger.geTracePyretic()
        self.network = ConcreteNetwork(self)
        self.prev_network = self.network.copy()
        self.policy = main(**kwargs)
        if mode == 'reactive0':
            self.active_dynamic_policies = set()
            def find_dynamic_sub_pols(policy,recursive_pols_seen):
                dynamic_sub_pols = set()
                if isinstance(policy,DynamicPolicy):
                    dynamic_sub_pols.add(policy)
                    dynamic_sub_pols |= find_dynamic_sub_pols(policy._policy,
                                                              recursive_pols_seen)
                elif isinstance(policy,CombinatorPolicy):
                    for sub_policy in policy.policies:
                        dynamic_sub_pols |= find_dynamic_sub_pols(sub_policy,
                                                                  recursive_pols_seen)
                elif isinstance(policy,recurse):
                    if policy in recursive_pols_seen:
                        return dynamic_sub_pols
                    recursive_pols_seen.add(policy)
                    dynamic_sub_pols |= find_dynamic_sub_pols(policy.policy,
                                                              recursive_pols_seen)
                elif isinstance(policy,DerivedPolicy):
                    dynamic_sub_pols |= find_dynamic_sub_pols(policy.policy,
                                                              recursive_pols_seen)
                else:
                    pass
                return dynamic_sub_pols
            self.find_dynamic_sub_pols = find_dynamic_sub_pols
            dynamic_sub_pols = self.find_dynamic_sub_pols(self.policy,set())
            for p in dynamic_sub_pols:
                p.attach(self.handle_policy_change)
        self.debug_packet_in = debug_packet_in
        self.show_traces = show_traces
        self.mode = mode
        self.verbosity = verbosity
        self.backend = backend
        self.backend.runtime = self
        self.vlan_to_extended_values_db = {}
        self.extended_values_to_vlan_db = {}
        self.extended_values_lock = threading.RLock()
        self.threads = set()
        self.in_update_network = False

    def trace(self, logLine, timeStamped=False):
      if not self.debug:
        return
        
      simpleLogger.geTracePyretic()(logLine, timeStamped)

    def update_network(self):
        if self.network.topology != self.prev_network.topology:
            self.in_update_network = True
            self.prev_network = self.network.copy()
            self.policy.set_network(self.prev_network)
            if self.mode == 'reactive0':
                self.clear_all()
            self.in_update_network = False

    def handle_policy_change(self, changed, old, new):
        old_dynamics = self.find_dynamic_sub_pols(old,set())
        new_dynamics = self.find_dynamic_sub_pols(new,set())
        for p in (old_dynamics - new_dynamics):
            p.detach()
        for p in (new_dynamics - old_dynamics):
            p.attach(self.handle_policy_change)
        if self.in_update_network:
            pass
        else:
            if self.mode == 'reactive0':
                self.clear_all()  ## PLAY IT VERY CONSERVATIVE
            pass

    def handle_switch_join(self,switch_id):
        self.network.handle_switch_join(switch_id)

    def handle_switch_part(self,switch_id):
        self.network.handle_switch_part(switch_id)

    def handle_port_join(self,switch_id,port_id,conf_up,stat_up):
        self.network.handle_port_join(switch_id,port_id,conf_up,stat_up)

    def handle_port_mod(self, switch, port_no, config, status):
        self.network.handle_port_mod(switch, port_no, config, status)

    def handle_port_part(self, switch, port_no):
        self.network.handle_port_part(switch, port_no)

    def handle_link_update(self, s1, p_no1, s2, p_no2):
        self.network.handle_link_update(s1, p_no1, s2, p_no2)

    def match_on_all_fields_pred(self, pkt):
        try:
            return match(
                switch=pkt['switch'],
                inport=pkt['inport'],
                srcmac=pkt['srcmac'],
                dstmac=pkt['dstmac'],
                ethtype=pkt['ethtype'],
                srcip=pkt['srcip'],
                dstip=pkt['dstip'],
                protocol=pkt['protocol'],
                tos=pkt['tos'],
                srcport=pkt['srcport'],
                dstport=pkt['dstport'],
                vlan_id=pkt['vlan_id'],
                vlan_pcp=pkt['vlan_pcp'])
        except:
            try:
                return match(
                    switch=pkt['switch'],
                    inport=pkt['inport'],
                    srcmac=pkt['srcmac'],
                    dstmac=pkt['dstmac'],
                    ethtype=pkt['ethtype'],
                    srcip=pkt['srcip'],
                    dstip=pkt['dstip'],
                    protocol=pkt['protocol'],
                    tos=pkt['tos'],
                    srcport=pkt['srcport'],
                    dstport=pkt['dstport'])
            except:
                try:
                    return match(
                        switch=pkt['switch'],
                        inport=pkt['inport'],
                        srcmac=pkt['srcmac'],
                        dstmac=pkt['dstmac'],
                        ethtype=pkt['ethtype'],
                        srcip=pkt['srcip'],
                        dstip=pkt['dstip'],
                        protocol=pkt['protocol'],
                        vlan_id=pkt['vlan_id'],
                        vlan_pcp=pkt['vlan_pcp'])
                except:
                    try:
                        return match(
                            switch=pkt['switch'],
                            inport=pkt['inport'],
                            srcmac=pkt['srcmac'],
                            dstmac=pkt['dstmac'],
                            ethtype=pkt['ethtype'],
                            srcip=pkt['srcip'],
                            dstip=pkt['dstip'],
                            protocol=pkt['protocol'])
                    except:
                        try:
                            return match(
                                switch=pkt['switch'],
                                inport=pkt['inport'],
                                srcmac=pkt['srcmac'],
                                dstmac=pkt['dstmac'],
                                ethtype=pkt['ethtype'],
                                protocol=pkt['protocol'],
                                vlan_id=pkt['vlan_id'],
                                vlan_pcp=pkt['vlan_pcp'])
                        except:
                            try:
                                return match(
                                    switch=pkt['switch'],
                                    inport=pkt['inport'],
                                    srcmac=pkt['srcmac'],
                                    dstmac=pkt['dstmac'],
                                    ethtype=pkt['ethtype'],
                                    protocol=pkt['protocol'])
                            except:
                                try:
                                    return match(
                                        vlan_id=pkt['vlan_id'],
                                        vlan_pcp=pkt['vlan_pcp'])
                                except:
                                    return no_packets


    def match_on_all_fields_rule(self, pkt_in, pkts_out):
        concrete_pkt_in = self.pyretic2concrete(pkt_in)
        pred = self.match_on_all_fields_pred(concrete_pkt_in)
        action_list = []
        
        ### IF NO PKTS OUT THEN INSTALL DROP (EMPTY ACTION LIST)
        if len(pkts_out) == 0:
            return (pred,action_list)

        for pkt_out in pkts_out:
            concrete_pkt_out = self.pyretic2concrete(pkt_out)
            actions = {}
            header_fields = set(concrete_pkt_out.keys()) | set(concrete_pkt_in.keys())
            for field in header_fields:
                if field not in native_headers + ['outport']:
                    continue
                try:
                    in_val = concrete_pkt_in[field]
                except:
                    in_val = None
                try:
                    out_val = concrete_pkt_out[field]
                except:
                    out_val = None
                if not out_val == in_val: 
                    actions[field] = out_val
            action_list.append(actions)
        return (pred,action_list)


    def reactive0(self,in_pkt,out_pkts,eval_trace):
        if self.mode == 'reactive0':
            rule = None
            ### DON'T INSTALL RULES THAT CONTAIN QUERIES
            if eval_trace.contains_class(packets.BoolWrappedFwdBucket):
                pass
            elif eval_trace.contains_class(counts):
                pass
            elif eval_trace.contains_class(sizes):
                pass
            else:
                rule = self.match_on_all_fields_rule(in_pkt,out_pkts)
                if rule:
                    self.install_rule(rule)
                    if self.verbosity == 'high' or True:
                        from datetime import datetime
                        self.trace(str(datetime.now()))
                        self.trace(" | install rule")
                        self.trace(rule[0])
                        self.trace(rule[1])
                        self.trace("")

    def handle_packet_in(self, concrete_pkt):
        pyretic_pkt = self.concrete2pyretic(concrete_pkt)
        if self.debug_packet_in:
            debugger.set_trace()
        if USE_IPDB:
             with debugger.launch_ipdb_on_exception():
                 if self.mode == 'interpreted':
                     output = self.policy.eval(pyretic_pkt)
                 else:
                     (output,eval_trace) = self.policy.track_eval(pyretic_pkt,dry=False)
                     self.reactive0(pyretic_pkt,output,eval_trace)
        else:
            try:
                if self.mode == 'interpreted':
                    output = self.policy.eval(pyretic_pkt)
                else:
                    (output,eval_trace) = self.policy.track_eval(pyretic_pkt,dry=False)
                    self.reactive0(pyretic_pkt,output,eval_trace)
            except :
                type, value, tb = sys.exc_info()
                traceback.print_exc()
                debugger.post_mortem(tb)
        if self.show_traces or True:
            self.trace("<<<<<<<<< RECV <<<<<<<<<<<<<<<<<<<<<<<<<<", timeStamped=True)
            self.trace(util.repr_plus([pyretic_pkt], sep="\n\n"))
            self.trace("")
            self.trace(">>>>>>>>> SEND >>>>>>>>>>>>>>>>>>>>>>>>>>", timeStamped=True)
            self.trace(util.repr_plus(output, sep="\n\n"))
            self.trace("")
        map(self.send_packet,output)
  
    def pyretic2concrete(self,packet):
        concrete_packet = ConcretePacket()
        for header in ['switch','inport','outport']:
            try:
                concrete_packet[header] = packet[header]
                packet = packet.pop(header)
            except:
                pass
        for header in native_headers + content_headers:
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

    def install_rule(self,(pred,action_list)):
        concrete_pred = { k:v.pattern for (k,v) in pred.map.items() }
        self.backend.send_install(concrete_pred,action_list)

    def clear_all(self):
        self.backend.send_clear_all()
        if self.verbosity == 'high' or True:
            from datetime import datetime
            self.trace(str(datetime.now()))
            self.trace(" | clear_all")
            self.trace("")
            
    def inject_discovery_packet(self,dpid, port):
        self.backend.inject_discovery_packet(dpid,port)

    def encode_extended_values(self, extended_values):
        with self.extended_values_lock:
            vlan = self.extended_values_to_vlan_db.get(extended_values)
            if vlan is not None:
                return vlan
            r = 1+len(self.extended_values_to_vlan_db) #VLAN ZERO IS RESERVED
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

basic_headers = ["srcmac", "dstmac", "srcip", "dstip", "tos", "srcport", "dstport",
                 "ethtype", "protocol"]
tagging_headers = ["vlan_id", "vlan_pcp"]
native_headers = basic_headers + tagging_headers
content_headers = [ "raw", "header_len", "payload_len"]

@util.cached
def extended_values_from(packet):
    extended_values = {}
    for k, v in packet.header.items():
        if k not in basic_headers + content_headers and v:
            extended_values[k] = v
        elif v and len(v) > 1:
            extended_values[k] = v[1:]
    return util.frozendict(extended_values)


################################################################################
# Concrete Packet and Network
################################################################################

class ConcretePacket(dict):
    pass

DEBUG_TOPO_DISCOVERY = True
class ConcreteNetwork(Network):
    def __init__(self,runtime=None):
        self.trace = simpleLogger.geTracePyretic()
        super(ConcreteNetwork,self).__init__()
        self.runtime = runtime

    def inject_packet(self, pkt):
        self.runtime.send_packet(pkt)

    #
    # Topology Detection
    #

    def update_network(self):
        self.runtime.update_network()
           
    def inject_discovery_packet(self, dpid, port_no):
        self.runtime.inject_discovery_packet(dpid, port_no)
        
    def handle_switch_join(self, switch):
        if DEBUG_TOPO_DISCOVERY:  self.trace("handle_switch_joins\n", timeStamped=True)
        ## PROBABLY SHOULD CHECK TO SEE IF SWITCH ALREADY IN TOPOLOGY
        self.topology.add_switch(switch)
        print("OpenFlow switch %s connected" % switch)
        if DEBUG_TOPO_DISCOVERY:  self.trace("\n%s\n" % self.topology, timeStamped=True)
        self.update_network()

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
        
    def handle_switch_part(self, switch):
        print("OpenFlow switch %s disconnected" % switch)
        if DEBUG_TOPO_DISCOVERY:  self.trace("handle_switch_parts\n", timeStamped=True)
        # REMOVE ALL ASSOCIATED LINKS
        for port_no in self.topology.node[switch]["ports"].keys():
            self.remove_associated_link(Location(switch,port_no))
        self.topology.remove_node(switch)
        if DEBUG_TOPO_DISCOVERY:  self.trace("\n%s\n" % self.topology, timeStamped=True)
        self.update_network()
        
    def handle_port_join(self, switch, port_no, config, status):
        if DEBUG_TOPO_DISCOVERY:  self.trace("handle_port_joins %s:%s:%s:%s\n" % (switch, port_no, config, status), timeStamped=True)
        self.topology.add_port(switch,port_no,config,status)
        if config or status:
            self.inject_discovery_packet(switch,port_no)
            if DEBUG_TOPO_DISCOVERY:  self.trace("\n%s\n" % self.topology, timeStamped=True)
            self.update_network()

    def handle_port_part(self, switch, port_no):
        if DEBUG_TOPO_DISCOVERY:  self.trace("handle_port_parts\n", timeStamped=True)
        try:
            self.remove_associated_link(Location(switch,port_no))
            del self.topology.node[switch]["ports"][port_no]
            if DEBUG_TOPO_DISCOVERY:  self.trace("\n%s\n" % self.topology, timeStamped=True)
            self.update_network()
        except KeyError:
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY handle_switch_parts
        
    def handle_port_mod(self, switch, port_no, config, status):
        if DEBUG_TOPO_DISCOVERY:  self.trace("handle_port_mods %s:%s:%s:%s\n" % (switch, port_no, config, status), timeStamped=True)
        # GET PREV VALUES
        try:
            prev_config = self.topology.node[switch]["ports"][port_no].config
            prev_status = self.topology.node[switch]["ports"][port_no].status
        except KeyError:
            print("KeyError CASE!!!!!!!!")
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
        if DEBUG_TOPO_DISCOVERY:  self.trace("port_up %s:%s\n" % (switch,port_no), timeStamped=True)
        self.inject_discovery_packet(switch,port_no)
        if DEBUG_TOPO_DISCOVERY:  self.trace("\n%s\n" % self.topology, timeStamped=True)
        self.update_network()

    def port_down(self, switch, port_no, double_check=False):
        if DEBUG_TOPO_DISCOVERY: self.trace("port_down %s:%s:double_check=%s\n" % (switch,port_no,double_check), timeStamped=True)
        try:
            self.remove_associated_link(Location(switch,port_no))
            if DEBUG_TOPO_DISCOVERY:  self.trace("\n%s\n" % self.topology, timeStamped=True)
            self.update_network()
            if double_check: self.inject_discovery_packet(switch,port_no)
        except KeyError:  
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY handle_switch_parts

    def handle_link_update(self, s1, p_no1, s2, p_no2):
        if DEBUG_TOPO_DISCOVERY:  self.trace("handle_link_updates\n", timeStamped=True)
        try:
            p1 = self.topology.node[s1]["ports"][p_no1]
            p2 = self.topology.node[s2]["ports"][p_no2]
        except KeyError:
            if DEBUG_TOPO_DISCOVERY: self.trace("node doesn't yet exist\n", timeStamped=True)
            return  # at least one of these ports isn't (yet) in the topology

        # LINK ALREADY EXISTS
        try:
            link = self.topology[s1][s2]

            # LINK ON SAME PORT PAIR
            if link[s1] == p_no1 and link[s2] == p_no2:         
                if p1.possibly_up() and p2.possibly_up():   
                    if DEBUG_TOPO_DISCOVERY: self.trace("nothing to do\n", timeStamped=True)
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
        if DEBUG_TOPO_DISCOVERY:  self.trace("\n%s\n" % self.topology, timeStamped=True)
        self.update_network()

