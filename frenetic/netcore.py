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

# This module is designed for import *.
import functools
import itertools
import struct
from abc import ABCMeta, abstractmethod
from collections import Counter
from numbers import Integral
from itertools import chain
import networkx as nx

from bitarray import bitarray

from frenetic import util
from frenetic.network import *
from frenetic.util import frozendict, singleton

################################################################################
# Matching and wildcards
################################################################################

class Matchable(object):
    """Assumption: the binary operators are passed in the same class as the
    invoking object.

    """
    __metaclass__ = ABCMeta

    @classmethod
    @abstractmethod
    def top(cls):
        """Return the matchable greater than all other matchables of the same
        class.

        """

    @abstractmethod
    def __and__(self, other):
        """Return the intersection of two matchables of the same class.  Return
        value is None if there is no intersection.

        """

    @abstractmethod
    def __le__(self, other):
        """Return true if `other' matches every object `self' does."""

    @abstractmethod
    def match(self, other):
        """Return true if we match `other'.""" 

        
# XXX some of these should be requirements on matchable.
class MatchableMixin(object):
    """Helper"""
    def disjoint_with(self, other):
        """Return true if there is no object both matchables match."""
        return self & other is None
    
    def overlaps_with(self, other):
        """Return true if there is an object both matchables match."""
        return not self.overlaps_with(other)
        
    def __eq__(self, other):
        return self <= other and other <= self

    def __ne__(self, other):
        """Implemented in terms of __eq__"""
        return not self == other


class Approx(object):
    """Interface for things which can be approximated."""
    __metaclass__ = ABCMeta

    @abstractmethod
    def overapprox(self, overapproxer):
        """Docs here."""

    @abstractmethod
    def underapprox(self, underapproxer):
        """Docs here."""

        
@util.cached
def Wildcard(width_):
    @functools.total_ordering
    class Wildcard_(MatchableMixin, Data("prefix mask")):
        """Full wildcards."""

        width = width_

        @classmethod
        def is_wildstr(cls, value):
            return isinstance(value, basestring) and len(value) == cls.width and set(value) <= set("?10")

        def __new__(cls, prefix, mask=None):
            """Create a wildcard. Prefix is a binary string.
            Mask can either be an integer (how many bits to mask) or a binary string."""

            if cls.is_wildstr(prefix):
                bprefix = bitarray(prefix.replace("?", "0"))
                bmask = bitarray(prefix.replace("1", "0").replace("?", "1"))
                prefix = bprefix
                mask = bmask
            elif isinstance(prefix, Wildcard_):
                (prefix, mask) = prefix.prefix, prefix.mask
            elif mask is None:
                mask = bitarray([False] * len(prefix))
                assert len(prefix) == cls.width == len(mask), "mask and prefix must be same length"
                
            return super(Wildcard_, cls).__new__(cls, prefix, mask)

        def __hash__(self):
            return hash((self.prefix.tobytes(), self.mask.tobytes()))

        def __repr__(self):
            l = []
            for pb, mb in zip(self.prefix, self.mask):
                if mb:
                    l.append("?")
                else:
                    l.append(str(int(pb)))
            return "".join(l)
        
        @classmethod
        def top(cls):
            prefix = bitarray(cls.width)
            prefix.setall(False)
            mask = bitarray(cls.width)
            mask.setall(False)
            return cls(prefix, mask)

        def match(self, other):
            return other.to_bits() | self.mask == self._normalize()

        def __and__(self, other):
            if self.overlaps_with(other):
                return self.__class__(self._normalize() & other._normalize(),
                                      self.mask & other.mask)

        def overlaps_with(self, other):
            c_mask = self.mask | other.mask
            return self.prefix | c_mask == other.prefix | c_mask

        def __le__(self, other):
            return (self.mask & other.mask == other.mask) and \
                (self.prefix | self.mask == other.prefix | self.mask)

        def _normalize(self):
            """Return a bitarray, masked."""
            return self.prefix | self.mask

    Matchable.register(Wildcard_)
    Wildcard_.__name__ += repr(width_)
    
    return Wildcard_

    
class IPWildcard(Wildcard(32)):
    def __new__(cls, ipexpr, mask=None):
        if isinstance(ipexpr, basestring):
            parts = ipexpr.split("/")

            if len(parts) == 2:
                ipexpr = parts[0]
                try:
                    mask = int(parts[1], 10)
                except ValueError:
                    mask = parts[1]
            elif len(parts) != 1:
                raise ValueError

            if mask is None:
                prefix = bitarray()
                mask = bitarray(32)
                (a, b, c, d) = ipexpr.split(".")
                mask.setall(False)
                if a == "*":
                    mask[0:8] = True
                    prefix.extend("00000000")
                else:
                    prefix.frombytes(struct.pack("!B", int(a)))
                if b == "*":
                    mask[8:16] = True
                    prefix.extend("00000000")
                else:
                    prefix.frombytes(struct.pack("!B", int(b)))
                if c == "*":
                    mask[16:24] = True
                    prefix.extend("00000000")
                else:
                    prefix.frombytes(struct.pack("!B", int(c)))
                if d == "*":
                    mask[24:32] = True
                    prefix.extend("00000000")
                else:
                    prefix.frombytes(struct.pack("!B", int(d)))
            elif isinstance(mask, Integral):
                prefix = IP(ipexpr)
                bmask = bitarray(32)
                bmask.setall(True)
                bmask[0:mask] = False
                mask = bmask
            elif isinstance(mask, basestring):
                prefix = IP(ipexpr)
                mask = IP(mask).to_bits()
                mask.invert()
        else:
            prefix = ipexpr
                
        return super(IPWildcard, cls).__new__(cls, prefix, mask)


class Exact(object):
    def __init__(self, obj):
        self.obj = obj

    def match(self, other):
        return self.obj == other

    def __repr__(self):
        return str(self.obj)
        
################################################################################
# Lifts
################################################################################

_header_to_matchclass = {}

def register_header(header, matchclass):
    _header_to_matchclass[header] = matchclass

def matchable_for_header(header):
    return _header_to_matchclass.get(header, Exact)

### JREICH - disabled incorrect registration calls
### Wildcard takes a binary encoding, but srcmac/dstmac fields are ':' delimited hex strings
### call should be - register_header("srcmac", MACWildcard)
### class MACWildcard(Wildcard(48)) must be implemented first
### Not a priority as wildcard matching on MAC addresses not needed for current examples
#register_header("srcmac", Wildcard(48))
#register_header("dstmac", Wildcard(48))
register_header("srcip", IPWildcard)
register_header("dstip", IPWildcard)

    
################################################################################
# Predicates
################################################################################
    
class Predicate(object):
    """Top-level abstract class for predicates."""
        
    def __sub__(self, other):
        return difference(self, other)

    def __and__(self, other):
        if isinstance(other,Predicate):
            return intersect([self, other])
        else:
            return other.__and__(self)
       
    def __or__(self, other):
        return union([self, other])

    def __getitem__(self, policy):
        return restrict(policy, self)
        
    def __invert__(self):
        return negate(self)

    def __eq__(self, other):
        raise NotImplementedError

    def __ne__(self, other):
        raise NotImplementedError


class DerivedPredicate(Predicate):
    def get_predicate(self):
        raise NotImplementedError
    
    def __repr__(self):
        return repr(self.get_predicate())

    def eval(self, packet):
        return self.get_predicate().eval(packet)

        
@singleton
class all_packets(Predicate):
    """The always-true predicate."""
    def __repr__(self):
        return "all packets"
        
    def eval(self, packet):
        return True

        
@singleton
class no_packets(Predicate):
    """The always-false predicate."""
    def __repr__(self):
        return "no packets"
        
    def eval(self, packet):
        return False

        
class is_bucket(Predicate):
    def __init__(self, field):
        self.field = field
        
    def eval(self, packet):
        return isinstance(packet[self.field], Bucket)
        
    def __repr__(self):
        return "is_bucket %s" % self.field

        
class match(Predicate):
    # THIS DESCRIPTION SEEMS INCORRECT - JREICH..."
    """A set of field matches (one per field)"""
    
    def __init__(self, *args, **kwargs):
        self.map = {}
        for (k, v) in dict(*args, **kwargs).iteritems():
            self.map[k] = matchable_for_header(k)(v)
                     
    def __repr__(self):
        return "match:\n%s" % util.repr_plus(self.map.items())
    
    def eval(self, packet):
        for field, pattern in self.map.iteritems():
            v = packet.get_stack(field)
            if v:
                if pattern is None or not pattern.match(v[0]):
                    return False
            else:
                if pattern is not None:
                    return False
        return True

        
class union(Predicate):
    """A predicate representing the union of two predicates."""

    def __init__(self, predicates):
        self.predicates = predicates
        
    def __repr__(self):
        return "union:\n%s" % util.repr_plus(self.predicates)
        
    def eval(self, packet):
        return any(predicate.eval(packet) for predicate in self.predicates)

        
class intersect(Predicate):
    """A predicate representing the intersection of two predicates."""

    def __init__(self, predicates):
        self.predicates = predicates
        
    def __repr__(self):
        return "intersect:\n%s" % util.repr_plus(self.predicates)
    
    def eval(self, packet):
        return all(predicate.eval(packet) for predicate in self.predicates)

        
class difference(Predicate, Data("base_predicate diff_predicates")):
    """A predicate representing the difference of two predicates."""

    def __new__(cls, base_predicate, diff_predicates):
        return super(difference, cls).__new__(cls,
                                              base_predicate,
                                              list(diff_predicates))
    
    def __repr__(self):
        return "difference:\n%s" % util.repr_plus([self.base_predicate,
                                                   self.diff_predicates])
        
    def eval(self, packet):
        return self.base_predicate.eval(packet) and not any(pred.eval(packet)
                                                            for pred in self.diff_predicates)

        
class negate(Predicate, Data("predicate")):
    """A predicate representing the difference of two predicates."""
    def __repr__(self):
        return "negate:\n%s" % util.repr_plus([self.predicate])
    
    def eval(self, packet):
        return not self.predicate.eval(packet)

        
################################################################################
# Policies
################################################################################

class Policy(object):
    """Top-level abstract description of a static network program."""

    def __sub__(self, pred):
        return remove(self, pred)

    def __and__(self, pred):
        return restrict(self, pred)

    def __or__(self, other):
        return parallel([self, other])
        
    def __rshift__(self, pol):
        return compose([self, pol])

    def __eq__(self, other):
        raise NotImplementedError

    def __ne__(self, other):
        raise NotImplementedError

    def eval(self, packet):
        raise NotImplementedError


class DerivedPolicy(Policy):
    def get_policy(self):
        raise NotImplementedError
        
    def __repr__(self):
        return repr(self.get_policy())

    def eval(self, packet):
        return self.get_policy().eval(packet)

        
@singleton
class drop(Policy):
    """Policy that drops everything."""
    def __repr__(self):
        return "drop"
        
    def eval(self, packet):
        return Counter()

        
@singleton
class passthrough(Policy):
    def __repr__(self):
        return "passthrough"
        
    def eval(self, packet):
        return Counter([packet])

        
class modify(Policy):
    """Policy that drops everything."""
                                            
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    def __repr__(self):
        return "modify:\n%s" % util.repr_plus(self.map.items())
        
    def eval(self, packet):
        packet = packet.modifymany(self.map)
        return Counter([packet])

        
class fwd(Policy):
    """Forward"""
    
    def __init__(self, port):
        self.port = port

    def __repr__(self):
        return "fwd %s" % self.port
    
    def eval(self, packet):
        packet = packet.push(outport=self.port)
        return Counter([packet])

        
class push(Policy):
    """Policy that drops everything."""
    
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    def __repr__(self):
        return "push:\n%s" % util.repr_plus(self.map.items())
        
    def eval(self, packet):
        packet = packet.pushmany(self.map)
        return Counter([packet])

        
class pop(Policy):
    """Policy that drops everything."""
    
    def __init__(self, fields):
        self.fields = set(fields)

    def __repr__(self):
        return "pop:\n%s" % util.repr_plus(self.fields)
        
    def eval(self, packet):
        packet = packet.popmany(self.fields)
        return Counter([packet])

        
class copy(Policy):
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    def __repr__(self):
        return "copy:\n%s" % util.repr_plus(self.map.items())
  
    """Policy that drops everything."""
    def eval(self, packet):
        pushes = {}
        for (dstfield, srcfield) in self.map.iteritems():
            pushes[srcfield] = packet[dstfield]
        pops = self.map.values()
        packet = packet.pushmany(pushes).popmany(pops)
        return Counter([packet])


class remove(Policy, Data("policy predicate")):
    def __repr__(self):
        return "remove:\n%s" % util.repr_plus([self.predicate, self.policy])
        
    def eval(self, packet):
        if not self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return Counter()
        

class restrict(Policy, Data("policy predicate")):
    """Policy for mapping a single predicate to a list of actions."""
    def __repr__(self):
        return "restrict:\n%s" % util.repr_plus([self.predicate,
                                                 self.policy])
        
    def eval(self, packet):
        if self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return Counter()

                    
class parallel(Policy, Data("policies")):
    def __repr__(self):
        return "parallel:\n%s" % util.repr_plus(self.policies)
        
    def eval(self, packet):
        c = Counter()
        for policy in self.policies:
            rc = policy.eval(packet)
            c.update(rc)
        return c


class compose(Policy, Data("policies")):
    def __repr__(self):
        return "compose:\n%s" % util.repr_plus(self.policies)
  
    def eval(self, packet):
        lc = Counter([packet])
        for policy in self.policies:
            c = Counter()
            for lpacket, lcount in lc.iteritems():
                rc = policy.eval(lpacket)
                for rpacket, rcount in rc.iteritems():
                    c[rpacket] = lcount * rcount
            lc = c
        return lc

            
class if_(Policy):
    def __init__(self, pred, t_branch, f_branch=passthrough):
        self.pred = pred
        self.t_branch = t_branch
        self.f_branch = f_branch

    def __repr__(self):
        return "if\n%s" % util.repr_plus(["PREDICATE",
                                          self.pred,
                                          "T BRANCH",
                                          self.t_branch,
                                          "F BRANCH",
                                          self.f_branch])

    def eval(self, packet):
        if self.pred.eval(packet):
            return self.t_branch.eval(packet)
        else:
            return self.f_branch.eval(packet)

            
class breakpoint(Policy):
    def __init__(self, policy, condition=lambda ps: True):
        self.policy = policy
        self.condition = condition
        
    def __repr__(self):
        return "***debug***\n%s" % util.repr_plus([self.policy])
        
    def eval(self, packet):
        import ipdb
        ipdb.set_trace()
        return self.policy.eval(packet)

        
class simple_route(Policy):
    def eval(self, packet):
        policy = drop
        headers = tuple(headers)
        for header_preds, act in args:
            policy |= match(dict(zip(headers, header_preds))) & act
        return policy.eval(packet)

        
class flood(Policy):
    def __init__(self, network):
        self.network = network
        @network._topology.notify
        def handle(topo):
            self.mst = nx.minimum_spanning_tree(topo)
    
    def __repr__(self):
        return "flood %s" % self.network
    
    def eval(self, packet):
        switch = packet["switch"]
        inport = packet["inport"]
        if switch in self.network.topology.nodes():
            ports = set()
            ports.update(egress_ports(self.network.topology, switch))
            for sw in self.mst.neighbors(switch):
                port = self.mst[switch][sw][switch]
                ports.add(port)
            packets = [packet.push(outport=port)
                       for port in ports if port != inport]
            return Counter(packets)
        else:
            return Counter()

def egress_points(topo):
    for sw in topo.nodes():
        ports = egress_ports(topo, sw)
        if ports:
            yield sw, ports
    
def egress_ports(topo, sw):
    attrs = topo.node[sw]
    all_ports = attrs["ports"]
    non_egress_ports = set()
    for attrs in topo[sw].itervalues():
        non_egress_ports.add(attrs[sw])
    return all_ports - non_egress_ports
    
def query(network, pred=all_packets, fields=(), time=None):
    b = Bucket(fields, time)
    sub_net = Network.fork(network)
    sub_net.install_policy(pred & fwd(b))
    return b

def query_unique(network, pred=all_packets, fields=(), time=None):
    b = UniqueBucket(fields, time)
    sub_net = Network.fork(network)
    sub_net.install_policy(pred & fwd(b))    
    return b
