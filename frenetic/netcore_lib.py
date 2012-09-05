
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

from abc import ABCMeta, abstractmethod
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
    """Expected fields:
    switch location srcmac dstmac dltype vlan vlan_pcp srcip dstip
    protocol srcport dstport"""

class Packet(Data("header payload")):
    """Class representing packets (insightful, huh)"""

    def __new__(cls, header, payload):
        return super(Packet, cls).__new__(cls, header, payload)
        
class Bucket(Event):
    """A safe place for packets!"""
    def __init__(self, fields, time):
        self.fields = fields
        self.time = time
        
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


class MatchableMixin(object):
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

        
_wildcard_cache = {}        
def Wildcard(width_):
    try:
        return _wildcard_cache[width_]
    except KeyError:
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
        _wildcard_cache[width_] = Wildcard_
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
   def __rshift__(self, act):
       return PolImply(self, act)

class PredTop(Predicate):
    """The always-true predicate."""
    def __repr__(self):
        return "*"
      
class PredBottom(Predicate):
    """The always-false predicate."""
    def __repr__(self):
        return "!*"
    
class PredMatch(Predicate, Data("varname pattern")):
   """A basic predicate matching against a single field"""
   def __repr__(self):
      return "%s:%s" % (self.varname, self.pattern)

class PredUnion(Predicate, Data("left right")):
    """A predicate representing the union of two predicates."""
    def __repr__(self):
        return "(%s) | (%s)" % (self.left, self.right)
        
class PredIntersection(Predicate, Data("left right")):
    """A predicate representing the intersection of two predicates."""
    def __repr__(self):
        return "(%s) & (%s)" % (self.left, self.right)

class PredDifference(Predicate, Data("left right")):
    """A predicate representing the difference of two predicates."""
    def __repr__(self):
        return "(%s) - (%s)" % (self.left, self.right)

class PredNegation(Predicate, Data("pred")):
    """A predicate representing the difference of two predicates."""
    def __repr__(self):
        return "~(%s)" % (self.pred)

################################################################################
# Actions (these are internal data structures)
################################################################################

class Action(object):
    def __add__(self, act):
        return ActChain(self, act)

    def _set_counter(self):
        raise NotImplementedError

    def get_counter(self):
        c = Counter()
        self._set_counter(c)
        return c

    def __eq__(self, other):
        return self.get_counter() == other.get_counter()

class ActDrop(Action):
    def __repr__(self):
        return "Drop"
    def _set_counter(self, c):
        return
    
class ActMod(Action, Data("mapping")):
    def __new__(cls, mapping):
        assert isinstance(mapping, frozendict)
        return super(ActMod, cls).__new__(cls, mapping)
    
    def __repr__(self):
        return repr(self.mapping)

    def _set_counter(self, c):
        c[self.mapping] += 1
       
class ActChain(Action, Data("left right")):
    def __repr__(self):
        return "(%s, %s)" % (self.left, self.right)
    def _set_counter(self, c):
        self.left._set_counter(c)
        self.right._set_counter(c)
            
################################################################################
# Policies
################################################################################

class Policy(object):
   """Top-level abstract description of a static network program."""
   def __or__(self, other):
      return PolUnion(self, other)
   def __sub__(self, pred):
      return PolRestriction(self, pred)
   def __mul__(self, pol):
      return PolComposition(self, pol)
      
class DropPolicy(Policy):
    """Policy that drops everything."""
    def __repr__(self):
        return "drop"
        
class ModPolicy(Policy, Data("mapping")):
    """Policy that drops everything."""
    def __new__(cls, mapping):
        if not isinstance(mapping, frozendict):
            mapping = frozendict(mapping)
        return super(ModPolicy, cls).__new__(cls, mapping)
    def __repr__(self):
        return repr(self.mapping)
    
class PolImply(Policy, Data("predicate policy")):
    """Policy for mapping a single predicate to a list of actions."""
    def __repr__(self):
        return "%s >> %s" % (self.predicate, self.policy)

class PolLet(Policy, Data("varname policy attr body")):
    def __repr__(self):
        return "let %s <- (%s).%s in %s" % (self.varname, self.policy, self.attr, self.body)
        
class PolComposition(Policy, Data("left right")):
    def __repr__(self):
        return "%s * %s" % (self.left, self.right)

class PolUnion(Policy, Data("left right")):
    def __repr__(self):
        return "%s + %s" % (self.left, self.right)

class PolRestriction(Policy, Data("policy predicate")):
    def __repr__(self):
        return "%s - %s" % (self.predicate, self.policy)
        
################################################################################
# Evaluation
################################################################################

def eval(expr, packet):
    """Evaluate a NetCore expression, producing an `Action`."""
    return _eval()(expr, packet, packet.header)
    
class _eval(Case):
    def case_PredTop(self, pred, packet, env):
        return True
      
    def case_PredBottom(self, pred, packet, env):
        return False

    def case_PredMatch(self, pred, packet, env):
        if pred.pattern is None:
            return pred.varname not in env
        else:
            return pred.pattern.match(env[pred.varname])

    def case_PredUnion(self, pred, packet, env):
        return self(pred.left, packet, env) or self(pred.right, packet, env)

    def case_PredIntersection(self, pred, packet, env):
        return self(pred.left, packet, env) and self(pred.right, packet, env)

    def case_PredDifference(self, pred, packet, env):
        return self(pred.left, packet, env) and not self(pred.right, packet, env)

    def case_PredNegation(self, pred, packet, env):
        return not self(pred.pred, packet, env)
      
    def case_DropPolicy(self, pol, packet, env):
        return ActDrop()

    def case_ModPolicy(self, pol, packet, env):
        return ActMod(pol.mapping)
    
    def case_PolImply(self, pol, packet, env):
        if self(pol.predicate, packet, env):
            return self(pol.policy, packet, env)
        else:
            return ActDrop()

    def case_PolRestriction(self, pol, packet, env):
        if self(pol.predicate, packet, env):
            return ActDrop()
        else:
            return self(pol.policy, packet, env)

    def case_PolUnion(self, pol, packet, env):
        return self(pol.left, packet, env) + self(pol.right, packet, env)

    def case_PolLet(self, pol, packet, env):
        action = ActDrop()
        for n_packet in mod_packet(self(pol.policy, packet, env), packet):
            n_env = env.update({pol.varname: n_packet.header[pol.attr]})
            action = ActChain(action, self(pol.body, packet, n_env))
        return action

    def case_PolComposition(self, pol, packet, env):
        action = ActDrop()
        for n_packet in mod_packet(self(pol.left, packet, env), packet):
            action = ActChain(action, self(pol.right, n_packet, env.update(n_packet.header)))
        return action

################################################################################
# Action ops
################################################################################
        
class _mod_packet(Case):
    def case_ActDrop(self, act, packet):
        return []
      
    def case_ActMod(self, act, packet):
        h = dict(packet.header)
        for k, v in act.mapping.iteritems():
            if v is None and k in h:
                del h[k]
            else:
                h[k] = v
        return [packet._replace(header=Header(h))]
      
    def case_ActChain(self, act, packet):
        return self(act.left, packet) + self(act.right, packet)
      
def mod_packet(act, packet):
    r = []
    for packet in _mod_packet()(act, packet):
        n_packet = packet.replace(payload=propagate_header_to_payload(packet.header, packet.payload))
        r.append(n_packet) 
    return r

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



    
