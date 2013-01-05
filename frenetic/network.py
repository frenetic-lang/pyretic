
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

import socket
import struct
from abc import ABCMeta, abstractmethod, abstractproperty
from numbers import Integral
from itertools import chain

from bitarray import bitarray

from frenetic import util, generators as gs
from frenetic.util import Data

import networkx as nx
from frenetic.graph_util import * 
from Queue import Queue

################################################################################
# Fixed width stuff
################################################################################

class IP(object):
    def __init__(self, ip):

        # already a IP object
        if isinstance(ip, IP):
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
        
    def to_bytes(self):
        return self.bits.tobytes()

    def fromRaw(self):
        return self.to_bytes()

    def __repr__(self):
        return socket.inet_ntoa(self.to_bytes())
    

class MAC(object):
    def __init__(self, mac):

        # already a MAC object
        if isinstance(mac, MAC):
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

    def to_bytes(self):
        return self.bits.tobytes()

    def fromRaw(self):
        return self.to_bytes()

    def __repr__(self):
        parts = struct.unpack("!BBBBBB", self.to_bytes())
        mac = ":".join(hex(part)[2:].zfill(2) for part in parts)
        return mac

    def __eq__(self,other):
        try:
            return self.bits == other.bits
        except:
            return False

        
################################################################################
# Packet and tools
################################################################################

class Packet(object):
    __slots__ = ["header"]
    
    def __init__(self, state):
        self.header = util.frozendict(state)
        
    def get_stack(self, field):
        return self.header.get(field, ())
    
    def pushmany(self, d):
        r = {}
        for k, v in d.iteritems():
            r[k] = (v,) + self.get_stack(k)
        return Packet(self.header.update(r))

    def push(self, **kwargs):
        return self.pushmany(kwargs)
    
    def popmany(self, fields):
        r = {}
        for field in fields:
            v = self.get_stack(field)
            assert v, "can't pop only value"
            r[field] = v[1:]
        return Packet(self.header.update(r))

    def pop(self, *args):
        return self.popmany(args)

    def clear(self, *args):
        return self.clearmany(args)
        
    def clearmany(self, fields):
        hdr = {}
        for field in fields:
            hdr[field] = ()
        return Packet(self.header.update(hdr))
            
    def modifymany(self, map):
        return self.popmany(map).pushmany(map)

    def modify(self, **kwargs):
        return self.modifymany(kwargs)

    def __getitem__(self, item):
        v = self.get_stack(item)
        if not v:
            raise KeyError
        # Return top of stack
        return v[0]

    def __hash__(self):
        return hash(self.header)
        
    def __repr__(self):
        l = []
        size = max(map(len, self.header) or [0]) + 3
        for k, v in sorted(self.header.iteritems()):
            if v:
                l.append("%s:%s%s" % (k, " " * (size - len(k)), v))
        return "\n".join(l)


class Location(object):
    def __init__(self,switch,port):
        self.switch = switch
        self.port = port

    def __hash__(self):
        return hash(self.__repr__())

    def __eq__(self,other):
        return self.switch == other.switch and self.port == other.port

    def __repr__(self):
        return "%s[%s]" % (self.switch,self.port)


class Topology(nx.Graph):

    def is_connected(self):
        return nx.is_connected(self)

    def interior_locations(self, sw):
        interior = set()
        for attrs in self[sw].itervalues():
            interior.add(Location(sw,attrs[sw]))
        return interior

    def egress_locations(self, sw=None):
        if sw is None:
            locations = set()
            for sw in self.nodes():
                locations |= self.egress_locations(sw)
            return locations
        else:
            attrs = self.node[sw]
            try:
                all_locations = {Location(sw,p) for p in attrs["ports"]}
            except KeyError:
                all_locations = set()
            non_egress_locations = self.interior_locations(sw)
            return all_locations - non_egress_locations

    ### TAKES A TRANSFORMED TOPOLOGY AND COPIES IN ATTRIBUTES FROM INITIAL TOPOLOGY
    def copy_attributes(self,initial_topo):
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
    def reconcile_attributes(self,initial_topo):
        # REMOVE PORT ATTRIBUTES CORRESPONDING TO REMOVED EDGES
        for (s1,s2,data) in initial_topo.edges(data=True):
            try:
                if self[s1][s2] == data:
                    # matching edge data
                    pass
                else:
                    raise Exception("NON-MATCHING EDGE DATA")
            except: 
               # removed edge, reconcile node ports"
                to_remove = [Location(s1,data[s1]),Location(s2,data[s2])]
                for loc in to_remove:
                    old_ports = self.node[loc.switch]['ports'] 
                    new_ports = old_ports - {loc.port}
                    self.node[loc.switch]['ports'] = new_ports

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

    ### A RANDOMIZED MINIMUM SPANNING TREE
    @classmethod
    def minimum_spanning_tree(cls,topology):
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
        mst = (cls.minimum_spanning_tree(remainder))
        msts.add(mst)
        remainder = Topology.difference(remainder,mst)
        while(not remainder is None and remainder.is_connected()):
            mst = (cls.minimum_spanning_tree(remainder))
            msts.add(mst)
            remainder = Topology.difference(remainder,mst)
        return msts

    def __repr__(self):
        output_str = ''
        edge_str = {}
        egress_str = {}
        switch_str_maxlen = len('switch')
        edge_str_maxlen = len('internal links')
        egress_str_maxlen = len('egress ports')
        for switch in self.nodes():
            edge_str[switch] = \
                ', '.join([ "%s[%s] --- %s[%s]" % (s1,ports[s1],s2,ports[s2]) \
                                for (s1,s2,ports) in self.edges(data=True) \
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
        return self.__repr__()

        
class Network(object):
    def __init__(self,backend):
        from frenetic.netcore import drop
        self._policy = gs.Behavior(drop)
        self._sub_policies = {}
        self.backend = backend

    @classmethod
    def clone(cls, network):
        self = cls(network.backend)
        self.inherit_events(network)
        return self
        
    @classmethod
    def fork(cls, network):
        self = cls.clone(network)
        self.connect(network)
        return self

    def connect(self, network):
        @self._policy.notify
        def change(policy):
            network.install_sub_policy(self, policy)
        
    #
    
    def init_events(self):
        self._topology = gs.Behavior(Topology())                
        self.events = ["switch_joins", "switch_parts",
                       "port_ups", "port_downs",
                       "link_ups", "link_downs"]
        for event in self.events:
            e = gs.Event()
            setattr(self, event, e)
            e.notify(getattr(self, "_handle_%s" % event))

    def inherit_events(self, network):
        self._topology = network._topology
        self.events = network.events
        for event in network.events:
            setattr(self, event, getattr(network, event))

    #

    topology = gs.Behavior.property("_topology")
    
    @property
    def topology_changes(self):
        return iter(self._topology)

    #

    def inject_packet(self, packet):
        self.backend.send_packet(packet)
        
    def install_policy(self, policy):
        self.install_sub_policy(self, policy)
        
    def install_sub_policy(self, id, policy):
        self._sub_policies[id] = policy
        self._policy.set(self._aggregate_policy())

    @property
    @util.cached
    def flood(self):
        from frenetic.netcore import flood
        return flood(self)

    def install_flood(self):
        self.install_policy(self.flood)
        
    @property
    def policy(self):
        return self._policy.get()
        
    @property
    def policy_changes(self):
        return iter(self._policy)
    
    def _aggregate_policy(self):
        from frenetic.netcore import drop
        pol = drop
        for policy in self._sub_policies.itervalues():
            pol |= policy
        return pol

    #
    # Events
    #
           
    def _handle_switch_joins(self, switch):
        self.topology.add_node(switch, ports=set())
        self._topology.signal_mutation()
        
    def _handle_switch_parts(self, switch):
        self.topology.remove_node(switch)
        self._topology.signal_mutation()
        
    def _handle_port_ups(self, (switch, port)):
        self.topology.node[switch]["ports"].add(port)
        self._topology.signal_mutation()

    def _handle_port_downs(self, (switch, port)):
        self.topology.node[switch]["ports"].remove(port)
        self._topology.signal_mutation()
        
    def _handle_link_ups(self, (s1, p1, s2, p2)):
        try:
            port_mapping = self.topology[s1][s2]
            if port_mapping[s1] == p1 and port_mapping[s2] == p2:
                pass # THE LINK BETWEEN THESE SWITCHES HASN'T CHANGED AT ALL
            else:
                # THE LINK BETWEEN THESE SWITCHES HAS MOVED PORT(S)!
                self.topology.add_edge(s1, s2, {s1: p1, s2: p2})
                self._topology.signal_mutation()
        except KeyError:
            # NO LINK CURRENTLY EXISTS BETWEEN THESE SWITCHES
            self.topology.add_edge(s1, s2, {s1: p1, s2: p2})
            self._topology.signal_mutation()
        
    def _handle_link_downs(self, (s1, p1, s2, p2)):
        try:
            self.topology.remove_edge(s1, s2)
            self._topology.signal_mutation()
        except nx.NetworkXError:
            pass  # LINK HAS ALREADY BEEN REMOVED


    #
    # Policies
    #

    def __ior__(self, policy):
        self.install_policy(self._sub_policies[self] | policy)
        return self
        
    def __iand__(self, policy):
        self.install_policy(self._sub_policies[self] & policy)
        return self

    def __isub__(self, policy):
        self.install_policy(self._sub_policies[self] - policy)
        return self

    def __irshift__(self, policy):
        self.install_policy(self._sub_policies[self] >> policy)
        return self


class Bucket(gs.Event):
    """A safe place for packets!"""
    def __init__(self, fields=[], time=None):
        self.fields = fields
        self.time = time
        super(Bucket, self).__init__()


class UniqueBucket(Bucket):
    """A safe place for unique packets!"""
    def __init__(self, network, fields=[], time=None):
        self.seen = {}
        self.network = network
        super(UniqueBucket, self).__init__(fields,time)

    def filter_queue(self):
        from frenetic.netcore import match
        
        # MAKE PREDICATE
        pred = None

        while(True):
            pkt = self.queue.get()

            pred = match([(field,pkt[field]) for field in self.fields])

            # RETURN PACKET IF NOT QUERIED FIELDS NOT YET SEEN    
            # OTHERWISE CONTINUE WAITING
            if not hash(pred) in self.seen:
                self.seen[hash(pred)] = True
                self.network -= pred
                break

        return pkt

    def __iter__(self):
        self.queue = Queue()
        
        self.notify(self.queue.put)
        
        def gen():
            while True: yield self.filter_queue()

        return gen()
