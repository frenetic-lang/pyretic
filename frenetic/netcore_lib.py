
################################################################################
# The Frenetic Project                                                         #
# frenetic@frenetic-lang.org                                                   #
################################################################################
# Licensed to the Frenetic Project by one or more contributors. See the        #
# NOTICE file distributed with this work for additional information            #
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

"""Netcore grammar objects and related functions."""

from abc import ABCMeta, abstractmethod, abstractproperty
from collections import Counter
import functools

from bitarray import bitarray

from frenetic import util
from frenetic.util import Data, Case, frozendict
from frenetic.generators import Event

################################################################################
# Structures
################################################################################

class Header(frozendict):
    pass

class Packet(Data("header payload")):
    def __new__(cls, header, payload):
        return super(Packet, cls).__new__(cls, header, payload)


class Bucket(Event):
    """A safe place for packets!"""
    def __init__(self, fields, time):
        self.fields = fields
        self.time = time

        super(Bucket, self).__init__()

        
################################################################################
# Matching and wildcards
################################################################################

class FixedWidth(object):
    __metaclass__ = ABCMeta

    width = abstractproperty()

    @abstractmethod
    def to_bits(self):
        """Convert this to a bitarray."""

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __ne__(self, other):
        pass
        
@util.cached
def Bits(width_):
    class Bits_(object):
        width = width_

        def __init__(self, bits):
            assert isinstance(bits, bitarray)
            self._bits = bits
            super(Bits_, self).__init__()

        def to_bits(self):
            return self._bits

        def __eq__(self, other):
            return self.to_bits() == other.to_bits()

        def __ne__(self, other):
            return self.to_bits() != other.to_bits()
            
    FixedWidth.register(Bits_)
    Bits_.__name__ += repr(width_)
    return Bits_
    

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

        def __new__(cls, prefix, mask):
            """Create a wildcard. Prefix is a binary string.
            Mask can either be an integer (how many bits to mask) or a binary string."""

            assert len(prefix) == cls.width == len(mask) 

            return super(Wildcard_, cls).__new__(cls, prefix, mask)

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

################################################################################
# Predicates
################################################################################

class Predicate(object):
    """Top-level abstract class for predicates."""
   
    def __and__(self, other):
        return PredIntersection(self, other)
    def __or__(self, other):
        return PredUnion(self, other)
    def __sub__(self, other):
        return PredDifference(self, other)
    def __invert__(self):
        return PredNegation(self)
    def __rshift__(self, pol):
        return PolImply(self, pol)

    def __eq__(self, other):
        raise NotImplementedError

    def __ne__(self, other):
        raise NotImplementedError

class PredAll(Predicate):
    """The always-true predicate."""
    def __repr__(self):
        return "*"
    def eval(self, packet, env):
        return True
      
class PredNone(Predicate):
    """The always-false predicate."""
    def __repr__(self):
        return "~*"
    def eval(self, packet, env):
        return False
    
class PredMatch(Predicate, Data("varname pattern")):
   """A basic predicate matching against a single field"""
   def __repr__(self):
      return "%s:%s" % (self.varname, self.pattern)
    def eval(self, packet, env):
        if self.pattern is None:
            return self.varname not in env
        else:
            return self.pattern.match(env[self.varname])
        
class PredUnion(Predicate, Data("left right")):
    """A predicate representing the union of two predicates."""
    def __repr__(self):
        return "(%s) | (%s)" % (self.left, self.right)
    def eval(self, packet, env):
        return self.left.eval(packet, env) or self.right.eval(packet, env)
        
class PredIntersection(Predicate, Data("left right")):
    """A predicate representing the intersection of two predicates."""
    def __repr__(self):
        return "(%s) & (%s)" % (self.left, self.right)
    def eval(self, packet, env):
        return self.left.eval(packet, env) and self.right.eval(packet, env)

class PredDifference(Predicate, Data("left right")):
    """A predicate representing the difference of two predicates."""
    def __repr__(self):
        return "(%s) - (%s)" % (self.left, self.right)
    def eval(self, packet, env):
        return self.left.eval(packet, env) and not self.right.eval(packet, env)

class PredNegation(Predicate, Data("pred")):
    """A predicate representing the difference of two predicates."""
    def __repr__(self):
        return "~(%s)" % (self.pred)
    def eval(self, packet, env):
        return not self.pred.eval(packet, env)

################################################################################
# Actions (these are internal data structures)
################################################################################

class Action(Counter):
    def eval(self, packet):
        packets = []
        for moddict in self.elements():
            header = dict(packet.header)
            for k, v in moddict.iteritems():
                if v is None:
                    if k in h:
                        del h[k]
                else:
                    assert isinstance(v, FixedWidth) 
                    h[k] = v
            header = Header(frozendict(header))
            payload = propagate_header_to_payload(header, packet.payload)
            packets.append(packet._replace(header=header, payload=payload))
        return packets
                
################################################################################
# Policies
################################################################################

class Policy(object):
    """Top-level abstract description of a static network program."""
    def __add__(self, other):
        return PolUnion(self, other)
    def __and__(self, other):
        return PolRestrict(self, other)
    def __sub__(self, pred):
        return PolRemove(self, pred)
    def __rshift__(self, pol):
        return PolComposition(self, pol)
    def __eq__(self, other):
        raise NotImplementedError
    def __ne__(self, other):
        raise NotImplementedError
    def eval(self, packet, env):
        act = Action()
        return self._eval(packet, env, act)
    
class PolDrop(Policy):
    """Policy that drops everything."""
    def __repr__(self):
        return "drop"
    def _eval(self, packet, env, act):
        pass

class PolPassthrough(Policy):
    def __repr__(self):
        return "passthrough"
    def _eval(self, packet, env, act):
        act.append(frozendict())
        
class PolModify(Policy, Data("field value")):
    """Policy that drops everything."""
    def __repr__(self):
        return "modify %s <- %s" % self
    def _eval(self, packet, env, act):
        act.append(frozendict({self.field: self.value}))
    
class PolRestrict(Policy, Data("predicate policy")):
    """Policy for mapping a single predicate to a list of actions."""
    def __repr__(self):
        return "%s & %s" % (self.predicate, self.policy)
    def _eval(self, packet, env, act):
        if self.predicate.eval(packet, env):
            self.policy._eval(packet, env, act)

class PolLet(Policy, Data("varname policy attr body")):
    def __repr__(self):
        return "let %s <- (%s).%s in %s" % (self.varname, self.policy, self.attr, self.body)
    def _eval(self, packet, env, act):
        act_ = Action()
        self.policy._eval(packet, env, act_)
        for n_packet in act_._eval(packet):
            n_env = env.update({self.varname: n_packet.header[self.attr]})
            self.body._eval(n_packet, n_env, act)
        
class PolComposition(Policy, Data("left right")):
    def __repr__(self):
        return "%s >> %s" % (self.left, self.right)
    def _eval(self, packet, env, act):
        act_ = Action()
        self.left._eval(packet, env, act_)
        for n_packet in act_._eval(packet):
            self.right._eval(n_packet, env.update(n_packet.header), act)
            
class PolUnion(Policy, Data("left right")):
    def __repr__(self):
        return "%s | %s" % (self.left, self.right)
    def _eval(self, packet, env, act):
        self.left._eval(packet, env, act)
        self.right._eval(packet, env, act)
        
class PolRemove(Policy, Data("policy predicate")):
    def __repr__(self):
        return "%s - %s" % (self.predicate, self.policy)
    def _eval(self, packet, env, act):
        if not self.predicate._eval(packet, env):
            self.policy._eval(packet, env, act)
        
################################################################################
# Nasty hacks.
################################################################################

# XXX this is slow and we shouldn't have a dep on pox here.
def propagate_header_to_payload(h, data):
    from pox.lib.packet import *
    from frenetic.pox_backend import pyretic_header_to_pox_match
    
    # TODO is this correct? when would we ever not have a payload, as
    # the header is supposed to reflect the payload? ATM this is just for
    # the tests.
    if data is None:
        return data

    packet = ethernet(data)
    match = pyretic_header_to_pox_match(h)

    packet.src = match.dl_src
    packet.dst = match.dl_dst
    packet.type = match.dl_type
    p = packet.next
    
    if isinstance(p, vlan):
        p.eth_type = match.dl_type
        p.id = match.dl_vlan
        p.pcp = match.dl_vlan_pcp
    p = p.next
  
    if isinstance(p, ipv4):
        p.srcip = match.nw_src
        p.dstip = match.nw_dst
        p.protocol = match.nw_proto
        p.tos = match.nw_tos
        p = p.next

        if isinstance(p, udp) or isinstance(p, tcp):
            p.srcport = match.tp_src
            p.dstport = match.tp_dst
        elif isinstance(p, icmp):
            p.type = match.tp_src
            p.code = match.tp_dst
    elif isinstance(p, arp):
        if p.opcode <= 255:
            p.opcode = match.nw_proto
            p.protosrc = match.nw_src
            p.protodst = match.nw_dst

    return packet.pack()


