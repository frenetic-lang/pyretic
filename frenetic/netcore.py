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

from bitarray import bitarray

from frenetic import util
from frenetic.network import *
from frenetic.util import frozendict, Data


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
# Predicates
################################################################################
    
class Predicate(object):
    """Top-level abstract class for predicates."""
   
    def __and__(self, other):
        if isinstance(other, Policy):
            return PolRestrict(self, other)
        else:
            return PredIntersection(self, other)
    def __or__(self, other):
        return PredUnion(self, other)
    def __sub__(self, other):
        return PredDifference(self, other)
    def __invert__(self):
        return PredNegation(self)
    def __eq__(self, other):
        raise NotImplementedError
    def __ne__(self, other):
        raise NotImplementedError

class PredAll(Predicate):
    """The always-true predicate."""
    def __repr__(self):
        return "all_packets"
    def eval(self, packet):
        return True
      
class PredNone(Predicate):
    """The always-false predicate."""
    def __repr__(self):
        return "no_packets"
    def eval(self, packet):
        return False
    
class PredMatch(Predicate, Data("field pattern")):
    """A basic predicate matching against a single field"""
    def __repr__(self):
        return "%s = %s" % self
    def eval(self, packet):
        v = getattr(packet, self.field, None)
        if self.pattern is None:
            return v is None
        else:
            if v is None:
                return False
            else:
                return self.pattern.match(v)
        
class PredUnion(util.ReprPlusMixin, Predicate, Data("left right")):
    """A predicate representing the union of two predicates."""
    _mes_drop = PredNone
    def eval(self, packet):
        return self.left.eval(packet) or self.right.eval(packet)
        
class PredIntersection(util.ReprPlusMixin, Predicate, Data("left right")):
    """A predicate representing the intersection of two predicates."""
    _mes_drop = PredAll
    def eval(self, packet):
        return self.left.eval(packet) and self.right.eval(packet)

class PredDifference(util.ReprPlusMixin, Predicate, Data("left right")):
    """A predicate representing the difference of two predicates."""
    _mes_attrs = {"left": 0}
    def eval(self, packet):
        return self.left.eval(packet) and not self.right.eval(packet)

class PredNegation(util.ReprPlusMixin, Predicate, Data("pred")):
    """A predicate representing the difference of two predicates."""
    _mes_attrs = {}
    def eval(self, packet):
        return not self.pred.eval(packet)
        
################################################################################
# Policies
################################################################################

class Policy(object):
    """Top-level abstract description of a static network program."""
    def __or__(self, other):
        return PolUnion(self, other)
    def __and__(self, other):
        assert isinstance(other, Predicate)
        return PolRestrict(other, self)
    def __sub__(self, pred):
        return PolRemove(self, pred)
    def __rshift__(self, pol):
        return PolComposition(self, pol)
    def __eq__(self, other):
        raise NotImplementedError
    def __ne__(self, other):
        raise NotImplementedError
    def eval(self, packet):
        raise NotImplementedError
        
class PolDrop(Policy):
    """Policy that drops everything."""
    def __repr__(self):
        return "drop"
    def eval(self, packet):
        return Counter()

class PolPassthrough(Policy):
    def __repr__(self):
        return "passthrough"
    def eval(self, packet):
        return Counter([packet])
        
class PolModify(Policy, Data("field value")):
    """Policy that drops everything."""
    def __repr__(self):
        return "modify %s <- %s" % self
    def eval(self, packet):
        packet = packet._replace({self.field: self.value})
        return Counter([packet])

class PolPush(Policy, Data("field")):
    """Policy that drops everything."""
    def __repr__(self):
        return "push %s" % self.field
    def eval(self, packet):
        packet = packet._push(self.field)
        return Counter([packet])

class PolPop(Policy, Data("field")):
    """Policy that drops everything."""
    def __repr__(self):
        return "pop %s" % self.field
    def eval(self, packet):
        packet = packet._pop(self.field)
        return Counter([packet])
        
class PolCopy(Policy, Data("field1 field2")):
    """Policy that drops everything."""
    def __repr__(self):
        return "copy %s <- %s" % self
    def eval(self, packet):
        packet = packet._replace({self.field1: getattr(packet, self.field2, None)})
        return Counter([packet])

class PolRestrict(util.ReprPlusMixin, Policy, Data("predicate policy")):
    """Policy for mapping a single predicate to a list of actions."""
    _mes_attrs = {"predicate": PredIntersection} 
    def eval(self, packet):
        if self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return Counter([])

class PolComposition(util.ReprPlusMixin, Policy, Data("left right")):
    _mes_drop = PolPassthrough
    def eval(self, packet):
        lc = self.left.eval(packet)
        c = Counter()
        for lpacket, lcount in lc.iteritems():
            rc = self.right.eval(lpacket)
            for rpacket, rcount in rc.iteritems():
                c[rpacket] = lcount * rcount 
        return c
            
class PolUnion(util.ReprPlusMixin, Policy, Data("left right")):
    _mes_drop = PolDrop
    def eval(self, packet):
        lc = self.left.eval(packet)
        rc = self.right.eval(packet)
        return lc + rc
        
class PolRemove(util.ReprPlusMixin, Policy, Data("policy predicate")):
    _mes_attrs = {"predicate": PredDifference}
    def eval(self, packet):
        if not self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return Counter([])

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
# Predicates and policies
################################################################################

all_packets = PredAll()
no_packets = PredNone()
drop = PolDrop()
passthrough = PolPassthrough()

def match(_d={}, **kwargs):
    d = util.merge_dicts(_d, kwargs)
    pred = all_packets
    for k, v in d.iteritems():
        if v is not None:
            v = lift_matchable(k, v)
        pred &= PredMatch(k, v)
    return pred

def is_bucket(name):
    return match({name: "1" + "?" * (Port.width - 1)})
    
def if_(pred, t_branch, f_branch=passthrough):
    return pred & t_branch | ~pred & f_branch

def case(*args):
    r = drop
    not_pred = all_packets
    for pred, branch in args:
        r |= not_pred & pred & branch
        not_pred &= ~pred
    return r
        
def or_(arg=[], *args):
    if isinstance(arg, (Predicate, Policy)):
        arg = [arg]
    args = chain(arg, args)
    k = args.next()
    for arg in args:
        k |= arg
    return k
    
def and_(arg=[], *args):
    if isinstance(arg, (Predicate, Policy)):
        arg = [arg]
    args = chain(arg, args)
    k = args.next()
    for arg in args:
        k &= arg
    return k

def fwd(port):
    return modify(outport=port)

def modify(_d={}, **kwargs):
    d = util.merge_dicts(_d, kwargs)
    policy = passthrough
    for k, v in d.items():
        policy >>= PolModify(k, v)
    return policy

flood = fwd(Port.flood_port)

def clear(arg=[], **args):
    if isinstance(arg, basestring):
        arg = [arg]
    args = chain(arg, args)
    return modify({arg : None for arg in args})
    
def copy(_d={}, **kwargs):
    d = util.merge_dicts(_d, kwargs)
    policy = passthrough
    for k, v in d.iteritems():
        policy >>= PolCopy(k, v)
    return policy

def move(_d={}, **kwargs):
    d = util.merge_dicts(_d, kwargs)
    policy = copy(d)
    policy >>= clear(d)
    return policy

def push(arg=[], *args):
    if isinstance(arg, basestring):
        arg = [arg]
    args = chain(arg, args)
    k = passthrough
    for arg in args:
        k >>= PolPush(arg)
    return k

def pop(arg=[], *args):
    if isinstance(arg, basestring):
        arg = [arg]
    args = chain(arg, args)
    k = passthrough
    for arg in args:
        k >>= PolPop(arg)
    return k
        
def simple_route(headers, *args):
    policy = drop
    headers = tuple(headers)
    for header_preds, act in args:
        policy |= match(dict(zip(headers, header_preds))) & act
    return policy
