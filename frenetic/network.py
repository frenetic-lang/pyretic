
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
        self._topology = gs.Behavior(nx.Graph())                
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

            pred = match()
            for field in self.fields:
                pred.set_field(field,pkt[field])

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
