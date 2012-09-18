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
from frenetic.util import frozendict, Data, singleton, merge_dicts

################################################################################
# Matching and wildcards
################################################################################

class Matchable(object):
    """Assumption: the binary operators are passed in the same class as the invoking object."""
    __metaclass__ = ABCMeta

    @classmethod
    @abstractmethod
    def top(cls):
        """Return the matchable greater than all other matchables of the same class. """

    @abstractmethod
    def __and__(self, other):
        """Return the intersection of two matchables of the same class.
        Return value is None if there is no intersection."""

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
            else:
                if isinstance(prefix, FixedWidth):
                    prefix = prefix.to_bits()
                if isinstance(mask, FixedWidth):
                    mask = mask.to_bits()
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

@util.cached
def MatchExact(match_cls):
    class MatchExact_(Wildcard(match_cls.width)):
        def __new__(cls, *v):
            try:
                # XXX ugh.
                w = super(MatchExact_, cls).__new__(cls, *v)
                assert w is not None
                return w
            except:
                bits = match_cls(*v).to_bits()
                return super(MatchExact_, cls).__new__(cls, bits) 

    MatchExact_.__name__ += match_cls.__name__
    return MatchExact_

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

################################################################################
# Lifts
################################################################################

header_to_matchable_lift = dict(
    srcip=IPWildcard,
    dstip=IPWildcard,)

for k, v in header_to_fixedwidth_lift.iteritems():
    header_to_matchable_lift.setdefault(k, MatchExact(v))

def lift_matchable(k, v):
    cls = header_to_matchable_lift.get(k)

    if cls is None:
        assert isinstance(v, Matchable)
        return v
    else:
        if not isinstance(v, tuple):
            v = (v,)
        return cls(*v)
    
################################################################################
# Predicates
################################################################################
    
class Predicate(object):
    """Top-level abstract class for predicates."""
   
    def __and__(self, other):
        if isinstance(other, Policy):
            return restrict(self, other)
        else:
            return intersect([self, other])
    def __or__(self, other):
        return union([self, other])
    def __sub__(self, other):
        return difference(self, other)
    def __invert__(self):
        return negate(self)
    def __eq__(self, other):
        raise NotImplementedError
    def __ne__(self, other):
        raise NotImplementedError

@singleton
class all_packets(Predicate):
    """The always-true predicate."""
    def __repr__(self):
        return "all_packets"
    def eval(self, packet):
        return True
      
class no_packets(Predicate):
    """The always-false predicate."""
    def __repr__(self):
        return "no_packets"
    def eval(self, packet):
        return False

class is_bucket(Predicate, Data("field")):
    def eval(self, packet):
        return match({self.field: "1" + "?" * (Port.width - 1)}).eval(packet)

    def __repr__(self):
        return "is_bucket %s" % self.field
    
class match(Predicate):
    """A basic predicate matching against a single field"""
    def __init__(self, _d={}, **kwargs):
        self.map = m = merge_dicts(_d, kwargs)
        for k, v in m.items():
            if v is not None:
                m[k] = lift_matchable(k, v)

    def __repr__(self):
        return "match:\n%s" % util.repr_plus(self.map.items())
    
    def eval(self, packet):
        for field, pattern in self.map.iteritems():
            v = getattr(packet, field, None)
            if v is None:
                if pattern is not None:
                    return False
            else:
                if pattern is None or not pattern.match(v):
                    return False
        return True
        
class union(Predicate):
    """A predicate representing the union of two predicates."""
    def __init__(self, arg=[], *args):
        if isinstance(arg, Policy):
            arg = [arg]

        self.predicates = []
        for predicate in chain(arg, args):
            if isinstance(predicate, union):
                self.predicates.extend(predicate.predicates)
            elif not isinstance(predicate, no_packets.__class__):
                self.predicates.append(predicate)
        
    def __repr__(self):
        return "union:\n%s" % util.repr_plus(self.predicates)
        
    def eval(self, packet):
        return any(predicate.eval(packet) for predicate in self.predicates)
        
class intersect(Predicate):
    """A predicate representing the intersection of two predicates."""
    def __init__(self, arg=[], *args):
        if isinstance(arg, Policy):
            arg = [arg]
            
        self.predicates = []
        for predicate in chain(arg, args):
            if isinstance(predicate, intersect):
                self.predicates.extend(predicate.predicates)
            elif not isinstance(predicate, all_packets.__class__):
                self.predicates.append(predicate)

    def __repr__(self):
        return "intersect:\n%s" % util.repr_plus(self.predicates)
    
    def eval(self, packet):
        return all(predicate.eval(packet) for predicate in self.predicates)

class difference(Predicate, Data("left right")):
    """A predicate representing the difference of two predicates."""
    def __repr__(self):
        return "difference:\n%s" % util.repr_plus([self.left, self.right])
        
    def eval(self, packet):
        return self.left.eval(packet) and not self.right.eval(packet)

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
    def __or__(self, other):
        return parallel([self, other])
    def __and__(self, pred):
        assert isinstance(pred, Predicate)
        return restrict(pred, self)
    def __sub__(self, pred):
        assert isinstance(pred, Predicate)
        return remove(self, pred)
    def __rshift__(self, pol):
        return compose([self, pol])
    def __eq__(self, other):
        raise NotImplementedError
    def __ne__(self, other):
        raise NotImplementedError
    def eval(self, packet):
        raise NotImplementedError

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
    def __init__(self, _d={}, **kwargs):
        self.map = merge_dicts(_d, kwargs)

    def __repr__(self):
        return "modify:\n%s" % util.repr_plus(self.map.items())
        
    def eval(self, packet):
        packet = packet._modify(self.map)
        return Counter([packet])

class fwd(Policy):
    """Policy that drops everything."""
    def __init__(self, port):
        self.port = port

    def __repr__(self):
        return "fwd %s" % self.port
    
    def eval(self, packet):
        packet = packet._push(outport=self.port)
        return Counter([packet])
        
class push(Policy):
    """Policy that drops everything."""
    def __init__(self, _d={}, **kwargs):
        self.map = merge_dicts(_d, kwargs)

    def __repr__(self):
        return "push:\n%s" % util.repr_plus(self.map.items())
        
    def eval(self, packet):
        packet = packet._push(self.map)
        return Counter([packet])

class pop(Policy):
    """Policy that drops everything."""
    def __init__(self, arg=[], *args):
        if isinstance(arg, basestring):
            arg = [arg]
        self.fields = list(chain(arg, args))

    def __repr__(self):
        return "pop:\n%s" % util.repr_plus(self.fields)
        
    def eval(self, packet):
        packet = packet._pop(self.fields)
        return Counter([packet])
        
class copy(Policy):
    def __init__(self, _d={}, **kwargs):
        self.map = merge_dicts(_d, kwargs)

    def __repr__(self):
        return "copy:\n%s" % util.repr_plus(self.map.items())
  
    """Policy that drops everything."""
    def eval(self, packet):
        pushes = {field1: getattr(packet, field2, None) for (field1, field2) in self.map.iteritems()}
        pops = self.map.values()
        packet = packet._push(pushes)._pop(pops)
        return Counter([packet])

class restrict(Policy, Data("predicate policy")):
    """Policy for mapping a single predicate to a list of actions."""
    def __repr__(self):
        return "restrict:\n%s" % util.repr_plus([self.predicate, self.policy])
        
    def eval(self, packet):
        if self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return Counter([])

class compose(Policy):
    def __init__(self, arg=[], *args):
        if isinstance(arg, Policy):
            arg = [arg]
        self.policies = []
        for policy in chain(arg, args):
            if isinstance(policy, compose):
                self.policies.extend(policy.policies)
            elif not isinstance(policy, passthrough.__class__):
                self.policies.append(policy)

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
            
class parallel(Policy):
    def __init__(self, arg=[], *args):
        if isinstance(arg, Policy):
            arg = [arg]
        self.policies = []
        for policy in chain(arg, args):
            if isinstance(policy, parallel):
                self.policies.extend(policy.policies)
            elif not isinstance(policy, drop.__class__):
                self.policies.append(policy)
        
    def __repr__(self):
        return "parallel:\n%s" % util.repr_plus(self.policies)
        
    def eval(self, packet):
        c = Counter()
        for policy in self.policies:
            rc = policy.eval(packet)
            c.update(rc)
        return c
        
class remove(Policy, Data("policy predicate")):
    def __repr__(self):
        return "remove:\n%s" % util.repr_plus([self.predicate, self.policy])
        
    def eval(self, packet):
        if not self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return Counter()

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

class debug(Policy):
    def __init__(self, policy):
        self.policy = policy
        
    def __repr__(self):
        return "***debug***\n%s" % self.policy
        
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

