
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

import socket
import struct
from bitarray import bitarray
import networkx as nx

from pyretic.core import util

### DEFINITIONS
OFPP_IN_PORT = 0xfff8
OFPP_CONTROLLER = 0xfffd
# TODO: "Next table" port:
# Custom; not openflow spec-compliant.
# This number is also used in pox_client, so will need to be updated at both
# places, eventually.
CUSTOM_NEXT_TABLE_PORT = 0xfff4

LLDP_TYPE = 0x88cc
ARP_TYPE = 0x806
IP_TYPE  = 0x800
IPV6_TYPE = 0x86dd
TCP_TYPE = 0x6
UDP_TYPE = 0x11

################################################################################
# Fixed width stuff
################################################################################

class IPPrefix(object):
    def __init__(self, pattern):
        self.masklen = 32
        parts = pattern.split("/")
        self.pattern = IP(parts[0])
        if len(parts) == 2:
            self.masklen = int(parts[1])
        else:
            raise TypeError
        self.prefix = self.pattern.to_bits()[:self.masklen]

    def __eq__(self, other):
        """Match by checking prefix equality"""
        if isinstance(other,IPAddr):
            return self.prefix == other.to_bits()[:self.masklen]
        else:
            return False

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash((self.pattern,self.masklen))

    def __repr__(self):
        return "%s/%d" % (repr(self.pattern),self.masklen)

class IPAddr(object):
    def __init__(self, ip):

        # already a IP object
        if isinstance(ip, IPAddr):
            self.bits = ip.bits

        # otherwise will be in byte or string encoding
        else:
            assert isinstance(ip, basestring)
            
            b = bitarray()

            # byte encoding
            if len(ip) == 4:
                b.frombytes(ip)

            # string encoding
            else:
                b.frombytes(socket.inet_aton(ip))

            self.bits = b

    def to_bits(self):
        return self.bits

    def to01(self):
        return self.bits.to01()

    def to_bytes(self):
        return self.bits.tobytes()

    def fromRaw(self):
        return self.to_bytes()

    def __repr__(self):
        return socket.inet_ntoa(self.to_bytes())

    def __hash__(self):
        return hash(self.to_bytes())    

    def __eq__(self,other):
        return repr(self) == repr(other)

    def __ne__(self, other):
        return not (self == other)

class IP(IPAddr):
    pass

            
class EthAddr(object):
    def __init__(self, mac):

        # already a MAC object
        if isinstance(mac, EthAddr):
            self.bits = mac.bits

        # otherwise will be in byte or string encoding
        else:
            assert isinstance(mac, basestring)
            
            b = bitarray()

            # byte encoding
            if len(mac) == 6:
                b.frombytes(mac)

            # string encoding
            else:
                import re
                m = re.match(r"""(?xi)
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})
                             """, mac)
                if not m:
                    raise ValueError
                else:
                    b.frombytes(struct.pack("!BBBBBB", *(int(s, 16) for s in m.groups())))

            self.bits = b
        
    def to_bits(self):
        return self.bits

    def to01(self):
        return self.bits.to01()

    def to_bytes(self):
        return self.bits.tobytes()

    def __repr__(self):
        parts = struct.unpack("!BBBBBB", self.to_bytes())
        mac = ":".join(hex(part)[2:].zfill(2) for part in parts)
        return mac

    def __hash__(self):
        return hash(self.to_bytes())

    def __eq__(self,other):
        return repr(self) == repr(other)

    def __ne__(self, other):
        return not (self == other)

class MAC(EthAddr):
    pass

################################################################################
# Tools
################################################################################
class Port(object):
    def __init__(self,port_no,config=True,status=True,port_type=[],linked_to=None):
        self.port_no = port_no
        self.config = config
        self.status = status
        self.linked_to = linked_to
        self.port_type = port_type

    def definitely_down(self):
        return not self.config and not self.status

    def possibly_up(self):
        """User switch reports ports having LINK_DOWN status when in fact link is up"""
        return not self.definitely_down()

    def __hash__(self):
        return hash(self.port_no)

    def __eq__(self,other):
        return (self.port_no == other.port_no and 
                self.config == other.config and 
                self.status == other.status and 
                self.linked_to == other.linked_to)

    def __repr__(self):
        return "%d:config_up=%s:status_up=%s:linked_to=%s:port_type=%s" % (self.port_no,self.config,self.status,self.linked_to,self.port_type)



class Location(object):
    def __init__(self,switch,port_no):
        self.switch = switch
        self.port_no = port_no

    def __hash__(self):
        return hash((self.switch, self.port_no))

    def __eq__(self,other):
        if other is None:
            return False
        return self.switch == other.switch and self.port_no == other.port_no

    def __repr__(self):
        return "%s[%s]" % (self.switch,self.port_no)


class Topology(nx.Graph):
    def __eq__(self,other):
        def exact_node_match(n1,n2):
            return n1 == n2
        def exact_edge_match(e1,e2):
            return e1 == e2
        return nx.is_isomorphic(self,other,node_match=exact_node_match,edge_match=exact_edge_match)

    def switch_list(self):
        return self.nodes()

    def switch_with_port_ids_list(self):
        return [(switch,attrs['ports'].keys()) 
                for switch,attrs in self.nodes(data=True)]
    
    def switch_with_ports_list(self):
        return [(switch,attrs['ports'].values()) 
                for switch,attrs in self.nodes(data=True)]

    def add_switch(self,switch):
        self.add_node(switch, name=switch, ports={})  

    def add_port(self,switch,port_no,config,status,port_type):
        self.node[switch]["ports"][port_no] = Port(port_no,config,status,port_type)

    def add_link(self,loc1,loc2):
        self.add_edge(loc1.switch, loc2.switch, {loc1.switch: loc1.port_no, loc2.switch: loc2.port_no})
        self.node[loc1.switch]['ports'][loc1.port_no].linked_to = loc2
        self.node[loc2.switch]['ports'][loc2.port_no].linked_to = loc1

    def is_connected(self):
        return nx.is_connected(self)

    def egress_locations(self,switch=None):
        locs = set()
        if switch is None:
            for s in self.nodes():
                locs |= (self.egress_locations(s))
        else:
            try: 
                for port in self.node[switch]['ports'].values():
                    if port.possibly_up() and port.linked_to is None:
                        locs.add(Location(switch,port.port_no))
            except KeyError:
                pass
        return locs

    def interior_locations(self,switch=None):
        locs = set()
        if switch is None:
            for s in self.nodes():
                locs |= (self.interior_locations(s))
        else:
            for port in self.node[switch]['ports'].values():
                if port.possibly_up() and not port.linked_to is None:
                    locs.add(Location(switch,port.port_no))
        return locs

    def copy_attributes(self,initial_topo):
        """TAKES A TRANSFORMED TOPOLOGY AND COPIES IN ATTRIBUTES FROM INITIAL TOPOLOGY"""
        for s,data in initial_topo.nodes(data=True):
            try:
                if self.node[s] == data:
                    # matching node data
                    pass
                else:
                    # reconcile node data
                    for (k,v) in data.items():
                        self.node[s][k] = v
            except KeyError:
                # removed node
                pass

        # REMOVE PORT ATTRIBUTES CORRESPONDING TO REMOVED EDGES
        for (s1,s2,data) in initial_topo.edges(data=True):
            try:
                if self[s1][s2] == data:
                    # matching edge data
                    pass
                else:
                    # copying edge data
                    for (k,v) in data.items():
                        self[s1][s2][k] = v
            except: 
                # no edge to copy
                pass

    ### TAKES A TRANSFORMED TOPOLOGY AND UPDATES ITS ATTRIBUTES
    def reconcile_attributes(self,initial_topo,new_egress=False):
        # REMOVE PORT ATTRIBUTES CORRESPONDING TO REMOVED EDGES
        for (s1,s2,data) in initial_topo.edges(data=True):
            try:
                if self[s1][s2] == data:
                    # matching edge data
                    pass
                else:
                    raise RuntimeError("NON-MATCHING EDGE DATA")
            except KeyError:  
               # removed edge, reconcile node ports"
                to_remove = [Location(s1,data[s1]),Location(s2,data[s2])]
                for loc in to_remove:
                    try:
                        new_port_nos = self.node[loc.switch]['ports'].copy() 
                        if new_egress:
                            new_port_nos[loc.port_no].linked_to = None
                        else:
                            del new_port_nos[loc.port_no]
                            self.node[loc.switch]['ports'] = new_port_nos
                    except KeyError:
                        pass                # node removed

    def filter_nodes(self, switches=[]):
        remove = [ s for s in self.nodes() if not s in switches] 
        return self.filter_out_nodes(remove)

    def filter_out_nodes(self, switches=[]):
        filtered_copy = self.copy()
        filtered_copy.remove_nodes_from(switches)
        filtered_copy.reconcile_attributes(self,new_egress=True)
        return filtered_copy

    @classmethod
    def difference(cls,topo1,topo2):
        try:
            self = cls(nx.difference(topo1,topo2))
        except nx.NetworkXError:
            return None

        if len(self.edges()) == 0:
            return None

        self.copy_attributes(topo1)
        self.reconcile_attributes(topo1)
        return self

    @classmethod
    def minimum_spanning_tree(cls,topology):
        self = cls(nx.minimum_spanning_tree(topology))
        self.copy_attributes(topology)
        self.reconcile_attributes(topology)
        return self
        
    ### A RANDOMIZED MINIMUM SPANNING TREE
    @classmethod
    def random_minimum_spanning_tree(cls,topology):
        self = cls(Kruskal(topology))
        self.copy_attributes(topology)
        self.reconcile_attributes(topology)
        return self

    ### HEURISTIC. PICKS A RANDOM MST, REMOVES FROM TOPOLOGY, ADD TO SET
    ### WHILE TOPOLOGY STILL CONNECTED, LOOP
    @classmethod
    def disjoint_minimum_spanning_tree_set(cls,topology):
        msts = set()
        remainder = topology.copy()
        if remainder is None or len(remainder) == 0 or not remainder.is_connected():
            return msts
        mst = (cls.random_minimum_spanning_tree(remainder))
        msts.add(mst)
        remainder = Topology.difference(remainder,mst)
        while(not remainder is None and remainder.is_connected()):
            mst = (cls.random_minimum_spanning_tree(remainder))
            msts.add(mst)
            remainder = Topology.difference(remainder,mst)
        return msts

    @classmethod
    def all_pairs_shortest_path(cls,topology):
        location_paths = {}
        switch_paths = nx.all_pairs_shortest_path(topology)
        for s1, paths in switch_paths.items():
            location_paths[s1] = {}
            for s2, path in paths.items():
                location_paths[s1][s2] = []
                cur = s1
                for nxt in path + [s2]:
                    if cur != nxt:
                        link = topology[cur][nxt]
                        loc = Location(cur,link[cur])
                        location_paths[s1][s2].append(loc)
                    cur = nxt
        return location_paths

    def __repr__(self):
        output_str = ''
        edge_str = {}
        egress_str = {}
        switch_str_maxlen = len('switch')
        edge_str_maxlen = len('internal links')
        egress_str_maxlen = len('egress ports')
        for switch in self.nodes():
            edge_str[switch] = \
                ', '.join([ "%s[%s] --- %s[%s]" % (s1,port_nos[s1],s2,port_nos[s2]) \
                                for (s1,s2,port_nos) in self.edges(data=True) \
                                if s1 == switch or s2 == switch])
            egress_str[switch] = \
                ', '.join([ "%s---" % l for l in self.egress_locations(switch)])

        if len(self.nodes()) > 0:
            edge_str_maxlen = \
                max( [len(ed) for ed in edge_str.values()] + [edge_str_maxlen] )
            egress_str_maxlen = \
                max( [len(eg) for eg in egress_str.values()] + [egress_str_maxlen] )

        table_width = switch_str_maxlen + 5 + edge_str_maxlen + 5 + egress_str_maxlen + 3
        output_str += '\n'.rjust(table_width+1,'-')
        output_str += "%s  |  %s  |  %s  |\n" % \
            ('switch','switch edges'.rjust(edge_str_maxlen/2+1).ljust(edge_str_maxlen),\
                 'egress ports'.rjust(egress_str_maxlen/2+1).ljust(egress_str_maxlen),)        
        output_str += '\n'.rjust(table_width+1,'-')
        for switch in self.nodes():
            edge_str[switch] = edge_str[switch].ljust(edge_str_maxlen)
            egress_str[switch] = egress_str[switch].ljust(egress_str_maxlen)
            output_str += "%s  |  %s  |  %s  |\n" % \
                (str(switch).ljust(switch_str_maxlen),edge_str[switch],egress_str[switch])
        output_str += ''.rjust(table_width,'-')
        return output_str
        
    def __str__(self):
        return repr(self)
        

class Network(object):
    """Abstract class for networks"""
    def __init__(self,topology=None):
        if topology is None:
            self._topology = Topology()
        else:
            self._topology = topology

    @property
    def topology(self):
        return self._topology
    
    @topology.setter
    def topology(self,topology):
        self._topology = topology

    def inject_packet(self, pkt):
        raise NotImplementedError

    def __eq__(self,other):
        if other is None:
            return False
        return self._topology == other._topology

    def copy(self):
        topology = self._topology.copy()
        network = Network(topology)
        network.inject_packet = self.inject_packet
        return network

    def switch_list(self):
        return self.topology.switch_list()

    def switch_with_port_ids_list(self):
        return self.topology.switch_with_port_ids_list()

    def switch_with_ports_list(self):
        return self.topology.switch_with_ports_list()
