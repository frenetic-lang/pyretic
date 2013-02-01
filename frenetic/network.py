
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

import networkx as nx
from frenetic.graph_util import * 
from Queue import Queue

import threading

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
        try:
            return self.bits == other.bits
        except:
            return False

            
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

    def available_fields(self):
        available = []
        for field in self.header:
            v = self.get_stack(field)
            if v:
                available.append(field)
        return available
                
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

class Port(object):
    def __init__(self,port_no,status='UP',linked_to=None):
        self.port_no = port_no
        self.status = status
        self.linked_to = linked_to

    def __hash__(self):
        return hash(self.port_no)

    def __eq__(self,other):
        return self.port_no == other.port_no

    def __repr__(self):
        return "%d:%s:%s" % (self.port_no,self.status,self.linked_to)



class Location(object):
    def __init__(self,switch,port_no):
        self.switch = switch
        self.port_no = port_no

    def __hash__(self):
        return hash((self.switch, self.port_no))

    def __eq__(self,other):
        return self.switch == other.switch and self.port_no == other.port_no

    def __repr__(self):
        return "%s[%s]" % (self.switch,self.port_no)


class Topology(nx.Graph):
    def is_connected(self):
        return nx.is_connected(self)

    def egress_locations(self,switch=None):
        locs = set()
        if switch is None:
            for s in self.nodes():
                locs |= (self.egress_locations(s))
        else:
            for port in self.node[switch]['ports'].values():
                if port.status == 'UP' and port.linked_to is None:
                    locs.add(Location(switch,port.port_no))
        return locs

    def interior_locations(self,switch=None):
        locs = set()
        if switch is None:
            for s in self.nodes():
                locs |= (self.interior_locations(s))
        else:
            for port in self.node[switch]['ports'].values():
                if port.status == 'UP' and not port.linked_to is None:
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
    def reconcile_attributes(self,initial_topo):
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
                        del new_port_nos[loc.port_no]
                        self.node[loc.switch]['ports'] = new_port_nos
                    except KeyError:
                        pass                # node removed

    def remove_nodes_from(self,switches=[]):
        self.remove_nodes_from(switches)
        self.reconcile_attributes(initial_topo)
        return self

    @classmethod
    def filter_out_nodes(cls,initial_topo,switches=[]):
        try:
            self = initial_topo.copy()
        except nx.NetworkXError:
            return node
        return self.remove_nodes_from(switches)
        
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
                       "port_joins", "port_parts",
                       "port_ups", "port_downs", "link_updates"]
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

    def inject_discovery_packet(self, dpid, port_no):
        self.backend.inject_discovery_packet(dpid, port_no)
    
    def install_policy_func(self, policy_func):
        self.install_policy(policy_func(self))

    def install_policy(self, policy):
        self.install_sub_policy(self, policy)
        
    def install_sub_policy(self, id, policy):
        self._sub_policies[id] = policy
        self._policy.set(self._aggregate_policy())
        
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
        self.topology.add_node(switch, ports={})
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
        # REMOVE ALL ASSOCIATED LINKS
        for port_no in self.topology.node[switch]["ports"].keys():
            self.remove_associated_link(Location(switch,port_no))
        self.topology.remove_node(switch)
        self._topology.signal_mutation()
        
    def _handle_port_joins(self, (switch, port_no, status)):
        self.topology.node[switch]["ports"][port_no] = Port(port_no,status)
        if status == 'UP':
            self.inject_discovery_packet(switch,port_no)
            self._topology.signal_mutation()

    def _handle_port_parts(self, (switch, port_no)):
        try:
            self.remove_associated_link(Location(switch,port_no))
            del self.topology.node[switch]["ports"][port_no]
            self._topology.signal_mutation()
        except KeyError:
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY _handle_switch_parts
        
    def _handle_port_ups(self, (switch, port_no)):
        if self.topology.node[switch]["ports"][port_no].status != 'UP':
            self.topology.node[switch]["ports"][port_no].status = 'UP'
            self.inject_discovery_packet(switch,port_no)
            self._topology.signal_mutation()

    def _handle_port_downs(self, (switch, port_no)):
        try:
            switch_data = self.topology.node[switch]
            if switch_data["ports"][port_no].status == 'DOWN':
                return
            self.topology.node[switch]["ports"][port_no].status = 'DOWN'
            self.remove_associated_link(Location(switch,port_no))
            self._topology.signal_mutation()
        except KeyError:  
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY _handle_switch_parts

    def _handle_link_updates(self, (s1, p_no1, s2, p_no2)):
        try:
            p1 = self.topology.node[s1]["ports"][p_no1]
            p2 = self.topology.node[s2]["ports"][p_no2]
        except KeyError:
            return  # at least one of these ports isn't (yet) in the topology

        # LINK ALREADY EXISTS
        try:
            link = self.topology[s1][s2]

            # LINK ON SAME PORT PAIR
            if link[s1] == p_no1 and link[s2] == p_no2:         
                if p1.status == 'UP' and p2.status == 'UP':     #  AND BOTH PORTS ARE UP
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
        if p1.status == 'UP' and p2.status == 'UP':
            self.topology.node[s1]["ports"][p_no1].linked_to = Location(s2,p_no2)
            self.topology.node[s2]["ports"][p_no2].linked_to = Location(s1,p_no1)   
            self.topology.add_edge(s1, s2, {s1: p_no1, s2: p_no2})
            
        # IF REACHED, WE'VE REMOVED AN EDGE, OR ADDED ONE, OR BOTH
        self._topology.signal_mutation()



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
    def __init__(self, fields=[]):
        self.fields = fields
        super(Bucket, self).__init__()


class LimitBucket(Bucket):
    """A safe place for limiting packets!"""
    def __init__(self, network, fields=[], limit=None):
        self.seen = {}
        self.network = network
        self.limit = limit
        super(LimitBucket, self).__init__(fields)

    # YIELD ONLY THE FIRST limit MATCHING PACKETS
    # UPDATE BUCKET FORWARDING POLICY TO STOP FORWARDING PACKETS ALREADY SEEN limit TIMES
    def filter_queue(self):
        from frenetic.netcore import match
        
        pred = None
        while(True):
            # GET PACKET
            pkt = self.queue.get()

            # MATCH ON PROVIDED FIELDS
            if self.fields: 
                pred = match([(field,pkt[field]) for field in self.fields])
            # OTHERWISE, MATCH ON ALL AVAILABLE FIELDS
            else:
                pred = match([(field,pkt[field]) 
                              for field in pkt.available_fields()])


            # INCREMENT THE NUMBER OF TIMES MATCHING PACKET SEEN
            try:
                self.seen[pred] += 1
            except KeyError:
                self.seen[pred] = 1

            # STOP FORWARDING MATCHING PACKETS TO THIS BUCKET IF WE'VE HIT THE LIMIT
            if self.seen[pred] == self.limit:
                self.network -= pred

            # IF WE HAVEN'T YET RETURNED LIMIT PACKETS, BREAK THE LOOP 
            if self.seen[pred] <= self.limit:
                break
            
        return pkt

    def __iter__(self):
        
        # IF NO VALID LIMIT SPECIFIED, WE ASSUME INFINITE
        # AND ACT LIKE AN UNLIMITED BUCKET
        if self.limit is None or self.limit == 0:
            return super(LimitBucket,self).__iter__()

        # OTHERWISE, WE SET UP OUR QUEUE AND PUT A NEW PACKET IN EVERYTIME ONE ARRIVES
        self.queue = Queue()
        self.notify(self.queue.put)
        
        # AND YIELD PACKETS ACCORDING TO filter_queue
        def gen():
            while True: yield self.filter_queue()

        return gen()


class CountingBucket(Bucket):
    """A safe place for couting packets!"""
    def __init__(self, interval=None, group_by=[]):
        self.lock = threading.Lock()
        self.interval = interval
        self.group_by = group_by
        if group_by:
            self.count = {}
        else:
            self.count = 0
        super(CountingBucket, self).__init__([])

    # THREADSAFE INCREMENT OF COUNTER
    def inc(self,pkt):
        if self.group_by:
            from frenetic.netcore import match
            groups = set(self.group_by) & set(pkt.available_fields())
            pred = match([(field,pkt[field]) for field in groups])
            try:
                self.count[pred] += 1
            except KeyError:
                self.count[pred] = 1
            return self.count
        else:
            self.lock.acquire()
            self.count += 1
            self.lock.release()
            return self.count

    def __iter__(self):

        # IF NO INTERVAL SELECTED, YIELD count ON EVERY UPDATE
        if self.interval is None:

            # CONVERT GENERATOR OF PACKETS TO GENERATOR OF COUNTS
            # USING THE inc METHOD
            def convert_gen(gen):
                for y in gen:
                    yield self.inc(y)

            return convert_gen(
                super(CountingBucket,self).__iter__())

        # OTHERWISE WE UPDATE count AS PACKETS ARRIVE
        self.notify(self.inc)
        
        # AND YIELD count EVERY interval SECONDS
        def gen():
            import time
            while True:
                yield self.count
                time.sleep(self.interval)
                
        return gen()
    
