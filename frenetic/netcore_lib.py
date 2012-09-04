
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

from bitarray import bitarray

from collections import Counter

from frenetic import util
from frenetic.util import Record, Case, frozendict
from frenetic.generators import Event

################################################################################
# Matching and wildcards
################################################################################


class Matchable(object):
    """Assumption: the binary operatiors are passed in the same class as the invoking object."""
    
    @staticmethod
    def top(self, length):
        pass

    def __and__(self, other):
        pass
    
    def overlap(self, other):
        pass
            
    def disjoint(self, other):
        pass
        
    def __cmp__(self, other):
        pass
    
    def match_object(self, other):
        """other is a something with the .to_bits() method"""
        pass


# TODO
class Approx(object):
    """Interface for things which can be approximated."""
    
    def overapprox(self, overapproxer):
        pass

    
    def underapprox(self, underapproxer):
        pass
        
        
class Wildcard(Matchable, Record):
    """Full wildcards."""

    _fields = "width prefix mask"

    def __new__(cls, prefix, mask=None):
        """Create a wildcard. Prefix is a binary string.
        Mask can either be an integer (how many bits to mask) or a binary string."""
   
        if mask is None:
            mask = bitarray(len(prefix))
            mask.setall(False)

        return Record.__new__(cls, len(prefix), prefix, mask)
        
    # XXX is this really necessary?
    def normalize(self):
        """Return a bitarray, masked."""
        return self.prefix | self.mask 

    @staticmethod
    def top(length):
        return Wildcard(bitarray([False] * length), bitarray([True] * length))
        
    def match_object(self, other):
        return other.to_bits() | self.mask == self.normalize()
        
    def __and__(self, other):
        if self.overlap(other):
            return Wildcard(self.normalize() & other.normalize(),
                            self.mask & other.mask)
        else:
            return None

    def overlap(self, other):
        c_mask = self.mask | other.mask
        return self.prefix | c_mask == other.prefix | c_mask
        
    def disjoint(self, other):
        return not self.overlap(self, other)
        
    def _match(self, other):
        return (self.mask & other.mask == other.mask) and \
            (self.prefix | self.mask == other.prefix | self.mask)

    def __cmp__(self, other):
        x = self._match(other)
        y = other._match(self)
        
        return x - y    

    def __eq__(self, other):
        return self.normalize() == other.normalize()

    def __ne__(self, other):
        return self.normalize() != other.normalize()

    def __lt__(self, other):
        return cmp(self, other) < 0

    def __gt__(self, other):
        return cmp(self, other) > 0    
        
    def __le__(self, other):
        return cmp(self, other) <= 0

    def __ge__(self, other):
        return cmp(self, other) >= 0


        

################################################################################
# Predicates
################################################################################

        
class Predicate(Record):
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
  _fields = ""
   
  def __repr__(self):
    return "*"
      
   
class PredBottom(Predicate):
   """The always-false predicate."""
   _fields = ""

   def __repr__(self):
      return "!*"

   def _match(self, packet, env):
      return False

        
class PredMatch(Predicate):
   """A basic predicate matching against a single field"""

   _fields = "varname pattern"
    
   def __repr__(self):
      return "%s:%s" % (self.varname, self.pattern)

        
class PredUnion(Predicate):
   """A predicate representing the union of two predicates."""
   _fields = "left right"
    
   def __repr__(self):
      return "(%s) | (%s)" % (self.left, self.right)
        

class PredIntersection(Predicate):
   """A predicate representing the intersection of two predicates."""
   _fields = "left right"
    
   def __repr__(self):
      return "(%s) & (%s)" % (self.left, self.right)


class PredDifference(Predicate):
   """A predicate representing the difference of two predicates."""
   _fields = "left right"
    
   def __repr__(self):
      return "(%s) - (%s)" % (self.left, self.right)

      
class PredNegation(Predicate):
   """A predicate representing the difference of two predicates."""
   _fields = "pred"
    
   def __repr__(self):
      return "~(%s)" % (self.pred)

    
################################################################################
# Actions (these are internal data structures)
################################################################################

class Action(Record):
    def __add__(self, act):
        return ActChain(self, act)

    def get_counter(self):
        c = Counter()
        self._set_counter(c)
        return c

    def __eq__(self, other):
        return self.get_counter() == other.get_counter()
        

class ActDrop(Action):
    _fields = ""
    
    def __repr__(self):
        return "Nothing"

    def _set_counter(self, c):
        return
        
        
class ActMod(Action):
    _fields = "mapping"

    def __new__(cls, mapping):
        if not isinstance(mapping, frozendict):
            mapping = frozendict(mapping)

        return Action.__new__(cls, mapping)
    
    def __repr__(self):
        return repr(self.mapping)

    def _set_counter(self, c):
        c[self.mapping] += 1
       

class ActChain(Action):
    _fields = "left right"
    
    def __repr__(self):
        return "(%s, %s)" % (self.left, self.right)

    def _set_counter(self, c):
        self.left._set_counter(c)
        self.right._set_counter(c)
            
################################################################################
# Policies
################################################################################

        
class Policy(Record):
   """Top-level abstract description of a static network program."""

   def __or__(self, other):
      return PolUnion(self, other)

   def __sub__(self, pred):
      return PolRestriction(self, pred)

   def __mul__(self, pol):
      return PolComposition(self, pol)

class DropPolicy(Policy):
    """Policy that drops everything."""
    _fields = ""
    
    def __repr__(self):
        return "drop"

class ModPolicy(Policy):
    """Policy that drops everything."""
    _fields = "mapping"

    def __new__(cls, mapping):
        if not isinstance(mapping, frozendict):
            mapping = frozendict(mapping)

        return Policy.__new__(cls, mapping)
    
    def __repr__(self):
        return repr(self.mapping)
        
class PolImply(Policy):
    """Policy for mapping a single predicate to a list of actions."""

    _fields = "predicate policy"
    
    def __repr__(self):
        return "%s >> %s" % (self.predicate, self.policy)
        
class PolLet(Policy):
    _fields = "varname policy attr body"

    def __repr__(self):
        return "let %s <- (%s).%s in %s" % (self.varname, self.policy, self.attr, self.body)

class PolComposition(Policy):
    _fields = "left right"
    
    def __repr__(self):
        return "%s * %s" % (self.left, self.right)

class PolUnion(Policy):
    _fields = "left right"
    
    def __repr__(self):
        return "%s + %s" % (self.left, self.right)

class PolRestriction(Policy):
    _fields =  "policy predicate"
    
    def __repr__(self):
        return "%s - %s" % (self.predicate, self.policy)
        
################################################################################
# Traversals
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
            return pred.pattern.match_object(env[pred.varname])

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


# Structures
#


class Header(frozendict):
    """Expected fields:
    switch location srcmac dstmac dltype vlan vlan_pcp srcip dstip
    protocol srcport dstport"""

class Packet(Record):
    """Class representing packets (insightful, huh)"""

    _fields = "header size payload time"

    def __new__(cls, header, size, payload, time=None):
        time = time or util.current_time()
        return Record.__new__(cls, header, size, payload, time)
        
class bucket(Event):
    """A safe place for packets!"""
    def __init__(self, fields=(), time=None):
        self.fields = fields
        self.time = time
        
    
