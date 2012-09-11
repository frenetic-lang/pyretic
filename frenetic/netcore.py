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

def get_env(env, varname, field, packet):
    if varname != "_":
        packet = env[varname]
    
    return getattr(packet, field, None)
    
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
    def eval(self, packet, env=frozendict()):
        return True
      
class PredNone(Predicate):
    """The always-false predicate."""
    def __repr__(self):
        return "no_packets"
    def eval(self, packet, env=frozendict()):
        return False
    
class PredMatch(Predicate, Data("varname field pattern")):
    """A basic predicate matching against a single field"""
    def __repr__(self):
        return "%s.%s == %s" % self
    def eval(self, packet, env=frozendict()):
        v = get_env(env, self.varname, self.field, packet) 
        if v is None:
            return False
        else:
            return self.pattern.match(v)

class PredMissing(Predicate, Data("varname field")):
    """A basic predicate matching against a single field"""
    def __repr__(self):
        return "%s.%s is missing" % self
    def eval(self, packet, env=frozendict()):
        v = get_env(env, self.varname, self.field, packet) 
        return v is None
        
class PredUnion(util.ReprPlusMixin, Predicate, Data("left right")):
    """A predicate representing the union of two predicates."""
    _mes_drop = PredNone
    def eval(self, packet, env=frozendict()):
        return self.left.eval(packet, env) or self.right.eval(packet, env)
        
class PredIntersection(util.ReprPlusMixin, Predicate, Data("left right")):
    """A predicate representing the intersection of two predicates."""
    _mes_drop = PredAll
    def eval(self, packet, env=frozendict()):
        return self.left.eval(packet, env) and self.right.eval(packet, env)

class PredDifference(util.ReprPlusMixin, Predicate, Data("left right")):
    """A predicate representing the difference of two predicates."""
    _mes_attrs = {"left": 0}
    def eval(self, packet, env=frozendict()):
        return self.left.eval(packet, env) and not self.right.eval(packet, env)

class PredNegation(util.ReprPlusMixin, Predicate, Data("pred")):
    """A predicate representing the difference of two predicates."""
    _mes_attrs = {}
    def eval(self, packet, env=frozendict()):
        return not self.pred.eval(packet, env)
                
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
    def packets_to_send(self, packet):
        c = self.eval(packet)
        pc = Counter()
        for m, count in c.iteritems():
            packet_ = packet.update_header_fields(m)
            pc[packet_] += count 
        return pc
    
class PolDrop(Policy):
    """Policy that drops everything."""
    def __repr__(self):
        return "drop"
    def eval(self, packet, env=frozendict()):
        return Counter()

class PolPassthrough(Policy):
    def __repr__(self):
        return "passthrough"
    def eval(self, packet, env=frozendict()):
        return Counter([frozendict()])
        
class PolModify(Policy, Data("field value")):
    """Policy that drops everything."""
    def __repr__(self):
        return "modify %s <- %s" % self
    def eval(self, packet, env=frozendict()):
        return Counter([frozendict({self.field: self.value})])
        
class PolCopy(Policy, Data("field1 varname field2")):
    """Policy that drops everything."""
    def __repr__(self):
        return "copy %s <- %s.%s" % self
    def eval(self, packet, env=frozendict()):
        d = frozendict({self.field1: get_env(env, self.varname, self.field2, packet)})
        return Counter([d])
        
class PolRestrict(util.ReprPlusMixin, Policy, Data("predicate policy")):
    """Policy for mapping a single predicate to a list of actions."""
    _mes_attrs = {"predicate": PredIntersection} 
    def eval(self, packet, env=frozendict()):
        if self.predicate.eval(packet, env):
            return self.policy.eval(packet, env)
        else:
            return Counter()

class PolLet(util.ReprPlusMixin, Policy, Data("varname policy body")):
    _mes_attrs = {}
    def eval(self, packet, env=frozendict()):
        c = Counter()
        pc = self.policy.eval(packet, env)
        for pm, pcount in pc.items():
            packet_ = packet.update_header_fields(pm)
            env_ = env.update({self.varname: packet_})
            # Note not packet_!
            bc = self.body.eval(packet, env_)
            for bm, bcount in bc.iteritems():
                # Note no pm!
                c[bm] += pcount * bcount
        return c
        
class PolComposition(util.ReprPlusMixin, Policy, Data("left right")):
    _mes_drop = PolPassthrough
    def eval(self, packet, env=frozendict()):
        c = Counter()
        lc = self.left.eval(packet, env)
        for lm, lcount in lc.iteritems():
            packet_ = packet.update_header_fields(lm)
            rc = self.right.eval(packet_, env)
            for rm, rcount in rc.iteritems():
                c[lm.update(rm)] += lcount * rcount
        return c
            
class PolUnion(util.ReprPlusMixin, Policy, Data("left right")):
    _mes_drop = PolDrop
    def eval(self, packet, env=frozendict()):
        l = self.left.eval(packet, env)
        r = self.right.eval(packet, env)
        return l + r
        
class PolRemove(util.ReprPlusMixin, Policy, Data("policy predicate")):
    _mes_attrs = {"predicate": PredDifference}
    def eval(self, packet, env=frozendict()):
        if not self.predicate.eval(packet, env):
            return self.policy.eval(packet, env)
        else:
            return Counter()

################################################################################
# Lifts
################################################################################

header_to_matchable_lift = dict(
    switch=MatchExact(Switch),
    vswitch=MatchExact(Switch),
    inport=MatchExact(Port),
    outport=MatchExact(Port),
    vinport=MatchExact(Port),
    voutport=MatchExact(Port),
    srcmac=MatchExact(MAC),
    dstmac=MatchExact(MAC),
    vlan=MatchExact(FixedInt(12)),
    vlan_pcp=MatchExact(FixedInt(3)),
    srcip=IPWildcard,
    dstip=IPWildcard,
    srcport=MatchExact(FixedInt(16)),
    dstport=MatchExact(FixedInt(16)),
    protocol=MatchExact(FixedInt(8)),
    tos=MatchExact(FixedInt(6)),
    type=MatchExact(FixedInt(16)),)

def lift_matchable_kv(k, v):
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

class FieldMatch(Data("varname field")):
    def __repr__(self):
        return "%s.%s" % self
    def __eq__(self, other):
        other = lift_matchable_kv(self.field, other)
        return PredMatch(self.varname, self.field, other)
    def __ne__(self, other):
        return ~(self == other)
    def is_(self, other):
        return self == other
    def is_not(self, other):
        return self == other
    def is_missing(self):
        return PredMissing(self.varname, self.field)
        
class PacketMatch(Data("varname")):
    def __getattr__(self, attr):
        return FieldMatch(self.varname, attr)

_ = PacketMatch("_")

#

all_packets = PredAll()
no_packets = PredNone()

def let(policy, body):
    assert hasattr(body, "func_code"), "must be a function (literally)"
    name = body.func_code.co_varnames[0]
    assert name != "_", "the name _ is reserved for the implicit packet"
    return PolLet(name,
                  policy,
                  body(PacketMatch(name)))
        
def if_(pred, t_branch, f_branch):
    return pred & t_branch | ~pred & f_branch

def or_(*args):
    k = args[0]
    for arg in args[1:]:
        k |= arg
    return k
    
def and_(*args):
    k = args[0]
    for arg in args[1:]:
        k &= arg
    return k

drop = PolDrop()
passthrough = PolPassthrough()

def modify(**kwargs):
    policy = passthrough
    for k, v in kwargs.iteritems():
        policy = policy >> PolModify(k, v)
    return policy

strip_vlan = modify(vlan=None, vlan_pcp=None)

def fwd(port):
    return modify(outport=port)

def copy_fields(**kwargs):
    policy = passthrough
    for k, v in kwargs.iteritems():
        policy = policy >> PolCopy(k, v.varname, v.field)
    return policy
            
flood = fwd(Port.flood_port)

def enum(*args):
    fnargs = args[:-1]
    fn = args[-1]

    fields = [ field for field, values in fnargs ]
    value_row = itertools.product(*[values for field, values in fnargs])

    policy = drop
    
    for vr in value_row:
        pred = all_packets
        for i, v in enumerate(vr):
            pred &= fields[i] == v
        policy |= pred & fn(*vr)
        
    return policy
        

def is_port_real(port_match):
    """is the port real?"""

    return port_match == "0" + "?" * (Port.width - 1)
