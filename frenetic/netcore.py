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
from frenetic.util import frozendict, singleton

################################################################################
# Matching
################################################################################

class ExactMatch(object):
    """Pattern type for exact match"""

    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, other):
        return self.pattern == other

    def __hash__(self):
        return hash(self.pattern)

    def __eq__(self, other):
        """Match by checking for equality"""
        return self.pattern == other.pattern 
        
    def __repr__(self):
        return repr(self.pattern)

class PrefixMatch(object):
    """Pattern type for IP prefix match"""

    def __init__(self, pattern):
        self.masklen = 32
        if isinstance(pattern, IP):     # IP OBJECT
            self.pattern = pattern
        else:                           # STRING ENCODING
            parts = pattern.split("/")
            self.pattern = IP(parts[0])
            if len(parts) == 2:
                self.masklen = int(parts[1])
        self.prefix = self.pattern.to_bits()[:self.masklen]

    def match(self, other):
        """Match by checking prefix equality"""
        return self.prefix == other.to_bits()[:self.masklen]

    def __hash__(self):
        return hash(self.pattern)

    def __eq__(self, other):
        return self.pattern == other.pattern 
        
    def __repr__(self):
        if self.masklen == 32:
            return repr(self.pattern)
        else:
            return "%s/%d" % (repr(self.pattern),self.masklen)

################################################################################
# Determine how each field will be matched
################################################################################
        
_field_to_patterntype = {}

def register_field(field, patterntype):
    _field_to_patterntype[field] = patterntype

def field_patterntype(field):
    return _field_to_patterntype.get(field, ExactMatch)

register_field("srcip", PrefixMatch)
register_field("dstip", PrefixMatch)

    
################################################################################
# Predicates
################################################################################


class Predicate(object):
    """Top-level abstract class for predicates."""

    ### sub : Predicate -> Predicate
    def __sub__(self, other):
        return difference(self, other)
    
    ### and : Predicate -> Predicate 
    def __and__(self, other):
        return intersect([self, other])
    
    ### or : Predicate -> Predicate 
    def __or__(self, other):
        return union([self, other])

    ### getitem : Policy -> Policy 
    def __getitem__(self, policy):
        return restrict(policy, self)
        
    ### invert : unit -> Predicate
    def __invert__(self):
        return negate(self)

    ### eq : Predicate -> bool
    def __eq__(self, other):
        raise NotImplementedError

    ### ne : Predicate -> bool
    def __ne__(self, other):
        raise NotImplementedError

    def update_network(self, network):
        raise NotImplementedError
        
    def attach(self, network):
        """Not intended for general use."""
        raise NotImplementedError

    def detach(self, network):
        raise NotImplementedError

    def eval(self, network, packet):
        raise NotImplementedError


class DerivedPredicate(Predicate):
    ### repr : unit -> String
    def __repr__(self):
        return repr(self.predicate)

    def update_network(self, network):
        self.predicate.update_network(network)
        
    def attach(self, network):
        self.predicate.attach(network)

    def eval(self, network, packet):
        return self.predicate.eval(network, packet)

    def detach(self, network):
        self.predicate.detach(network)
        

class SimplePredicate(Predicate):
    def update_network(self, network):
        pass
        
    def attach(self, network):
        pass

    def detach(self, network):
        pass
        
        
@singleton
class all_packets(SimplePredicate):
    """The always-true predicate."""
    ### repr : unit -> String
    def __repr__(self):
        return "all packets"

    ### eval : Network -> Packet -> bool
    def eval(self, network, packet):
        return True
        
        
@singleton
class no_packets(SimplePredicate):
    """The always-false predicate."""
    ### repr : unit -> String
    def __repr__(self):
        return "no packets"

    ### eval : Network -> Packet -> bool
    def eval(self, network, packet):
        return False

        
@singleton
class ingress(SimplePredicate):
    ### repr : unit -> String
    def __repr__(self):
        return "ingress"
    
    ### eval : Network -> Packet -> bool
    def eval(self, network, packet):
        switch = packet["switch"]
        port_no = packet["inport"]
        return Location(switch,port_no) in network.topology.egress_locations()

        
@singleton
class egress(SimplePredicate):
    ### repr : unit -> String
    def __repr__(self):
        return "egress"
    
    ### eval : Network -> Packet -> bool
    def eval(self, network, packet):
        switch = packet["switch"]
        try:
            port_no = packet["outport"]
            return Location(switch,port_no) in network.topology.egress_locations()
        except:
            return False

        
class match(SimplePredicate):
    """A set of field matches (one per field)"""
    
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        init_map = {}
        for (k, v) in dict(*args, **kwargs).iteritems():
            if v is not None:
                patterntype = field_patterntype(k)
                pattern_to_match = patterntype(v)
                init_map[k] = pattern_to_match
            else: 
                init_map[k] = None
        self.map = util.frozendict(init_map)

    ### repr : unit -> String
    def __repr__(self):
        return "match:\n%s" % util.repr_plus(self.map.items())

    ### hash : unit -> int
    def __hash__(self):
        return hash(self.map)
    
    ### eq : Predicate -> bool
    def __eq__(self, other):
        return self.map == other.map

    ### eval : Network -> Packet -> bool
    def eval(self, network, packet):
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
    """A predicate representing the union of a list of predicates."""

    ### init : List Predicate -> unit
    def __init__(self, predicates):
        self.predicates = list(predicates)
        
    ### repr : unit -> String
    def __repr__(self):
        return "union:\n%s" % util.repr_plus(self.predicates)

    def update_network(self, network):
        for pred in self.predicates:
            pred.update_network(network)
        
    def attach(self, network):
        for pred in self.predicates:
            pred.attach(network)
            
    def eval(self, network, packet):
        return any(predicate.eval(network, packet) for predicate in self.predicates)

    def detach(self, network):
        for pred in self.predicates:
            pred.detach(network)

        
class intersect(Predicate):
    """A predicate representing the intersection of a list of predicates."""

    def __init__(self, predicates):
        self.predicates = list(predicates)
        
    ### repr : unit -> String
    def __repr__(self):
        return "intersect:\n%s" % util.repr_plus(self.predicates)

    def update_network(self, network):
        for pred in self.predicates:
            pred.update_network(network)
            
    def attach(self, network):
        for pred in self.predicates:
            pred.attach(network)
            
    def eval(self, network, packet):
        return all(predicate.eval(network, packet) for predicate in self.predicates)

    def detach(self, network):
        for pred in self.predicates:
            pred.detach(network)
    

class difference(Predicate):
    """A predicate representing the difference of two predicates."""

    ### init : Predicate -> List Predicate -> unit
    def __init__(self, base_predicate, diff_predicates):
        self.base_predicate = base_predicate
        self.diff_predicates = list(diff_predicates)
        
    ### repr : unit -> String
    def __repr__(self):
        return "difference:\n%s" % util.repr_plus([self.base_predicate,
                                                   self.diff_predicates])

    def update_network(self, network):
        self.base_predicate.update_network(network)
        for pred in self.diff_predicates:
            pred.update_network(network)
            
    ### attach : Network -> (Packet -> bool)
    def attach(self, network):
        self.base_predicate.attach(network)
        for pred in self.diff_predicates:
            pred.attach(network)
        
    def eval(self, network, packet):
        return self.base_predicate.eval(network, packet) and not \
            any(pred.eval(network, packet)
                for pred in self.diff_predicates)

    def detach(self, network):
        self.base_predicate.detach(network)
        for pred in self.diff_predicates:
            pred.detach(network)
        

class negate(Predicate):
    """A predicate representing the difference of two predicates."""

    ### init : Predicate -> unit
    def __init__(self, predicate):
        self.predicate = predicate
        
    ### repr : unit -> String
    def __repr__(self):
        return "negate:\n%s" % util.repr_plus([self.predicate])

    def update_network(self, network):
        self.predicate.attach(network)
    
    ### attach : Network -> (Packet -> bool)
    def attach(self, network):
        self.predicate.attach(network)
        
        ### eval : Packet -> bool
    def eval(self, network, packet):
        return not self.predicate.eval(network, packet)

    def detach(self, network):
        self.predicate.detach(network)
        
        
################################################################################
# Policies
################################################################################

class Policy(object):
    """Top-level abstract description of a static network program."""

    ### sub : Predicate -> Policy
    def __sub__(self, pred):
        return remove(self, pred)

    ### add : Predicate -> Policy
    def __and__(self, pred):
        return restrict(self, pred)

    ### or : Policy -> Policy
    def __or__(self, other):
        return parallel([self, other])
        
    ### rshift : Policy -> Policy
    def __rshift__(self, pol):
        return sequential([self, pol])

    ### eq : Policy -> bool
    def __eq__(self, other):
        raise NotImplementedError

    ### ne : Policy -> bool
    def __ne__(self, other):
        raise NotImplementedError

    def update_network(self, network):
        raise NotImplementedError
    
    def attach(self, network):
        raise NotImplementedError

    def eval(self, network, packet):
        raise NotImplementedError
        
    def detach(self, network):
        raise NotImplementedError

        
class SimplePolicy(Policy):
    def update_network(self, network):
        pass
        
    def attach(self, network):
        pass

    def detach(self, network):
        pass
        

class DerivedPolicy(Policy):
    ### repr : unit -> String
    def __repr__(self):
        return repr(self.policy)

    def update_network(self, network):
        self.policy.update_network(network)

    def attach(self, network):
        self.policy.attach(network)

    def eval(self, network, packet):
        return self.policy.eval(network, packet)

    def detach(self, network):
        self.policy.detach(network)


class pprint(SimplePolicy):
    def __init__(self,s=''):
        self.s = s

    ### repr : unit -> String
    def __repr__(self):
        return "pprint %s" % self.s
        
    ### eval : Network -> Packet -> Counter List Packet
    def eval(self, network, packet):
        print "---- pprint %s -------" % self.s
        print packet
        print "-------------------------------"
        return Counter([packet])
        
@singleton
class passthrough(SimplePolicy):
    ### repr : unit -> String
    def __repr__(self):
        return "passthrough"
        
    ### eval : Network -> Packet -> Counter List Packet
    def eval(self, network, packet):
        return Counter([packet])

        
@singleton
class drop(SimplePolicy):
    """Policy that drops everything."""
    ### repr : unit -> String
    def __repr__(self):
        return "drop"
        
    ### eval : Network -> Packet -> Counter List Packet
    def eval(self, network, packet):
        return Counter()

        
@singleton
class flood(SimplePolicy):
    ### repr : unit -> String
    def __repr__(self):
        return "flood"

    # TODO use attach for the mst?
    def eval(self, network, packet):
        mst = Topology.minimum_spanning_tree(network.topology)
        
        switch = packet["switch"]
        inport = packet["inport"]
        if switch in network.topology.nodes() and switch in mst:
            port_nos = set()
            port_nos.update({loc.port_no for loc in network.topology.egress_locations(switch)})
            for sw in mst.neighbors(switch):
                port_no = mst[switch][sw][switch]
                port_nos.add(port_no)
            packets = [packet.push(outport=port_no)
                       for port_no in port_nos if port_no != inport]
            return Counter(packets)
        else:
            return Counter()

            
class modify(SimplePolicy):
    """Policy that drops everything."""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
       init_map = {}
       for (k, v) in dict(*args, **kwargs).iteritems():
           if k == 'srcip' or k == 'dstip':
               init_map[k] = IP(v) 
           elif k == 'srcmac' or k == 'dstmac':
               init_map[k] = MAC(v)
           else:
               init_map[k] = v
       self.map = util.frozendict(init_map)

    ### repr : unit -> String
    def __repr__(self):
        return "modify:\n%s" % util.repr_plus(self.map.items())

    ### eval : Network -> Packet -> Counter List Packet        
    def eval(self, network, packet):
        packet = packet.modifymany(self.map)
        return Counter([packet])

        
class fwd(SimplePolicy):
    """Forward"""
    ### init : int -> unit
    def __init__(self, port):
        self.port = port

    ### repr : unit -> String
    def __repr__(self):
        return "fwd %s" % self.port
    
    ### eval : Network -> Packet -> Counter List Packet        
    def eval(self, network, packet):
        packet = packet.push(outport=self.port)
        return Counter([packet])

        
class push(SimplePolicy):
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    ### repr : unit -> String
    def __repr__(self):
        return "push:\n%s" % util.repr_plus(self.map.items())
        
    ### eval : Network -> Packet -> Counter List Packet
    def eval(self, network, packet):
        packet = packet.pushmany(self.map)
        return Counter([packet])

        
class pop(SimplePolicy):
    ### init : List String -> unit
    def __init__(self, *args):
        self.fields = list(args)

    ### repr : unit -> String
    def __repr__(self):
        return "pop:\n%s" % util.repr_plus(self.fields)
        
    ### eval : Network -> Packet -> Counter List Packet
    def eval(self, network, packet):
        packet = packet.popmany(self.fields)
        return Counter([packet])


class copy(SimplePolicy):
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    ### repr : unit -> String
    def __repr__(self):
        return "copy:\n%s" % util.repr_plus(self.map.items())
  
    ### eval : Network -> Packet -> Counter List Packet
    def eval(self, network, packet):
        pushes = {}
        for (dstfield, srcfield) in self.map.iteritems():
            pushes[dstfield] = packet[srcfield]
        packet = packet.pushmany(pushes)
        return Counter([packet])
        
        
class move(SimplePolicy):
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    ### repr : unit -> String
    def __repr__(self):
        return "shift:\n%s" % util.repr_plus(self.map.items())
  
    ### eval : Network -> Packet -> Counter List Packet
    def eval(self, network, packet):
        pushes = {}
        for (dstfield, srcfield) in self.map.iteritems():
            pushes[dstfield] = packet[srcfield]
        pops = self.map.values()
        packet = packet.pushmany(pushes).popmany(pops)
        return Counter([packet])


class overwrite(SimplePolicy):
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    ### repr : unit -> String
    def __repr__(self):
        return "overwrite:\n%s" % util.repr_plus(self.map.items())
  
    ### eval : Network -> Packet -> Counter List Packet
    def eval(self, network, packet):
        pushes = {}
        for (dstfield, srcfield) in self.map.iteritems():
            pushes[dstfield] = packet[srcfield]
        pops_before = self.map.keys()
        packet = packet.popmany(pops_before).pushmany(pushes)
        return Counter([packet])

        
class remove(Policy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, predicate):
        self.policy = policy
        self.predicate = predicate

    ### repr : unit -> String
    def __repr__(self):
        return "remove:\n%s" % util.repr_plus([self.predicate, self.policy])

    def update_network(self, network):
        self.predicate.update_network(network)
        self.policy.update_network(network)
        
    ### attach : Network -> (Packet -> Counter List Packet)
    def attach(self, network):
        self.predicate.attach(network)
        self.policy.attach(network)

    ### eval : Packet -> Counter List Packet
    def eval(self, network, packet):
        if not self.predicate.eval(network, packet):
            return self.policy.eval(network, packet)
        else:
            return Counter()
            
    def detach(self, network):
        self.predicate.detach(network)
        self.policy.detach(network)
        

class restrict(Policy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, predicate):
        self.policy = policy
        self.predicate = predicate

    ### repr : unit -> String
    def __repr__(self):
        return "restrict:\n%s" % util.repr_plus([self.predicate,
                                                 self.policy])

    def update_network(self, network):
        self.predicate.update_network(network)
        self.policy.update_network(network)

    ### attach : Network -> (Packet -> Counter List Packet)
    def attach(self, network):
        self.predicate.attach(network)
        self.policy.attach(network)

    ### eval : Packet -> Counter List Packet
    def eval(self, network, packet):
        if self.predicate.eval(network, packet):
            return self.policy.eval(network, packet)
        else:
            return Counter()
            
    def detach(self, network):
        self.predicate.detach(network)
        self.policy.detach(network)
 

class parallel(Policy):
    ### init : List Policy -> unit
    def __init__(self, policies):
        self.policies = list(policies)
    
    ### repr : unit -> String
    def __repr__(self):
        return "parallel:\n%s" % util.repr_plus(self.policies)

    def update_network(self, network):
        for policy in self.policies:
            policy.update_network(network)

    def attach(self, network):
        for policy in self.policies:
            policy.attach(network)

    def detach(self, network):
        for policy in self.policies:
            policy.attach(network)
            
    def eval(self, network, packet):
        c = Counter()
        for policy in self.policies:
            rc = policy.eval(network, packet)
            c.update(rc)
        return c
        

class sequential(Policy):
    ### init : List Policy -> unit
    def __init__(self, policies):
        self.policies = list(policies)
    
    ### repr : unit -> String
    def __repr__(self):
        return "sequential:\n%s" % util.repr_plus(self.policies)

    def update_network(self, network):
        for policy in self.policies:
            policy.update_network(network)

    def attach(self, network):
        for policy in self.policies:
            policy.attach(network)

    def detach(self, network):
        for policy in self.policies:
            policy.attach(network)

    def eval(self, network, packet):
        lc = Counter([packet])
        for policy in self.policies:
            c = Counter()
            for lpacket, lcount in lc.iteritems():
                rc = policy.eval(network, lpacket)
                for rpacket, rcount in rc.iteritems():
                    c[rpacket] = lcount * rcount
            lc = c
        return lc

        
### directional : Predicate -> List Policy -> Policy
def directional(direction_pred, policies):
    pol_list = list(policies)
    positive_direction = sequential(pol_list)
    pol_list.reverse()
    negative_direction = sequential(pol_list)
    return if_(direction_pred,positive_direction,negative_direction)
    

class if_(DerivedPolicy):
    ### init : Predicate -> Policy -> Policy -> unit
    def __init__(self, pred, t_branch, f_branch=passthrough):
        self.pred = pred
        self.t_branch = t_branch
        self.f_branch = f_branch
        self.policy = self.pred[self.t_branch] | (~self.pred)[self.f_branch]

    ### repr : unit -> String
    def __repr__(self):
        return "if\n%s" % util.repr_plus(["PREDICATE",
                                          self.pred,
                                          "T BRANCH",
                                          self.t_branch,
                                          "F BRANCH",
                                          self.f_branch])

        
class breakpoint(DerivedPolicy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, condition=lambda ps: True):
        self.policy = policy
        self.condition = condition

    ### repr : unit -> String
    def __repr__(self):
        return "***debug***\n%s" % util.repr_plus([self.policy])
    
    def eval(self, network, packet):
        import ipdb
        if self.condition(packet):
            ipdb.set_trace()
        return DerivedPolicy.eval(self, network, packet)

        
class simple_route(DerivedPolicy):
    def __init__(self, headers, *args):
        self.policy = drop
        headers = tuple(headers)
        for header_preds, act in args:
            self.policy |= match(dict(zip(headers, header_preds)))[ act ]


class NetworkDerivedPolicy(Policy):
    def __init__(self, make_policy):
        self.make_policy = make_policy
        self.policies = {}

    def update_network(self, network):
        self.detach(network)
        self.attach(network)
        
    def attach(self, network):
        self.policies[network] = self.make_policy(network)
        self.policies[network].attach(network)

    def detach(self, network):
        self.policies[network].detach(network)

    def eval(self, network, packet):
        return self.policies[network].eval(network, packet)

        
def ndp_decorator(fn):
    @property
    @functools.wraps(fn)
    def decr(self):
        return NetworkDerivedPolicy(functools.partial(fn, self))
    return decr

class MultiplexedPolicy(Policy):
    ### init : unit -> unit
    def __init__(self):
        self._policies = {}

    def __getitem__(self, network):
        return self._policies[network]

    def __setitem__(self, network, policy):
        old_policy = self[network]
        old_policy.detach(network)
        self._policies[network] = policy
        policy.attach(network)

    def update_network(self, network):
        self[network].update_network(network)
        
    def attach(self, network):
        pass
        
    def detach(self, network):
        pass

    def eval(self, network, packet):
        return self[network].eval(network, packet)


class Recurse(SimplePolicy):
    def __init__(self, recur):
        self.recur = recur
        
    def eval(self, network, packet):
        return self.recur.eval(network, packet)
        
            
class MutablePolicy(DerivedPolicy):
    ### init : unit -> unit
    def __init__(self):
        self.networks = set()
        self.policy = drop
        
    @property
    def policy(self):
        try:
            return self._policy
        except:
            return None

    @policy.setter
    def policy(self, policy):
        old_policy = self.policy
        self._policy = policy
        for network in self.networks:
            if old_policy is not None:
                old_policy.detach(network)
            policy.attach(network)

    def attach(self, network):
        if network not in self.networks:
            self.networks.add(network)
            DerivedPolicy.attach(self, network)

    def detach(self, network):
        assert network in self.networks
        self.networks.remove(network)
        DerivedPolicy.detach(self, network)

    ### query : Predicate -> ((Packet -> unit) -> (Packet -> unit))
    def query(self, pred=all_packets):
        b = packets()
        self.policy |= pred[b]
        return b.register_callback

    ### query_limit : Predicate -> int -> List String -> ((Packet -> unit) -> (Packet -> unit))
    def query_limit(self, pred=all_packets, limit=None, fields=[]):
        if limit:
            b = packets(limit,fields)
            self.policy |= pred[b]
            return b.register_callback
        else:
            return self.query(pred)

    ### query_unique : Predicate -> List String -> ((Packet -> unit) -> (Packet -> unit))
    def query_unique(self, pred=all_packets, fields=[]):
        return self.query_limit(pred,1,fields)

    ### query_count : Predicate -> int -> List String -> ((Packet -> unit) -> (Packet -> unit))
    def query_count(self, pred=all_packets, interval=None, group_by=[]):
        b = counts(interval,group_by)
        self.policy |= pred[b]
        return b.register_callback

        
# dynamic : (DecoratedPolicy ->  unit) -> DecoratedPolicy
def dynamic(fn):
    class DecoratedPolicy(MutablePolicy):
        def __init__(self, *args, **kwargs):
            # THIS CALL WORKS BY SETTING THE BEHAVIOR OF MEMBERS OF SELF.
            # IN PARICULAR, THE register_callback FUNCTION RETURNED BY self.query 
            # (ITSELF A MEMBER OF A queries_base CREATED BY self.query)
            # THIS ALLOWS FOR DECORATED POLICIES TO EVOLVE ACCORDING TO 
            # FUNCTION REGISTERED FOR CALLBACK EACH TIME A NEW EVENT OCCURS
            MutablePolicy.__init__(self)
            fn(self, *args, **kwargs)
            
    # SET THE NAME OF THE DECORATED POLICY RETURNED TO BE THAT OF THE INPUT FUNCTION
    DecoratedPolicy.__name__ = fn.__name__
    return DecoratedPolicy
 
        
class queries_base(SimplePolicy):
    ### init : unit -> unit
    def __init__(self):
        self.listeners = []

    ### eval : Network -> Packet -> unit
    def eval(self, network, packet):
        for listener in self.listeners:
            listener(packet)
        return Counter()

    ### register_callback : (Packet -> unit) -> (Packet -> unit)  
    # UNCLEAR IF THIS SIGNATURE IS OVERLY RESTRICTIVE 
    # CODE COULD PERMIT (Packet -> X) WHERE X not unit
    # CURRENT EXAMPLES USE SOLELY SIDE-EFFECTING FUNCTIONS
    def register_callback(self, fn):
        self.listeners.append(fn)
        return fn

    def when(self, fn):
        return self.register_callback(fn)

        
class packets(queries_base):
    ### init : int -> List String
    def __init__(self,limit=None,fields=[]):
        self.limit = limit
        self.seen = {}
        self.fields = fields
        queries_base.__init__(self)        

    ### eval : Network -> Packet -> unit
    def eval(self, network, packet):
        if not self.limit is None:

            if self.fields:    # MATCH ON PROVIDED FIELDS
                pred = match([(field,packet[field]) for field in self.fields])
                
            else:              # OTHERWISE, MATCH ON ALL AVAILABLE FIELDS
                pred = match([(field,packet[field]) 
                              for field in packet.available_fields()])

            # INCREMENT THE NUMBER OF TIMES MATCHING PACKET SEEN
            try:
                self.seen[pred] += 1
            except KeyError:
                self.seen[pred] = 1

            if self.seen[pred] > self.limit:
                return

        return queries_base.eval(self, network, packet)

        
class counts(queries_base):
    ### init : int -> List String
    def __init__(self, interval, group_by=[]):
        self.interval = interval
        self.group_by = group_by
        if group_by:
            self.count = {}
        else:
            self.count = 0

        # XXX hack! remove pox dependency!
        from pox.lib.recoco import Timer

        Timer(interval, self.report_count, recurring=True)
        
        queries_base.__init__(self)

    def report_count(self):
        queries_base.eval(self, None, self.count) # We don't actually use the "network" parameter

    ### inc : Packet -> unit
    def inc(self,pkt):
        if self.group_by:
            from frenetic.netcore import match
            groups = set(self.group_by) & set(pkt.available_fields())
            pred = match([(field,pkt[field]) for field in groups])
            try:
                self.count[pred] += 1
            except KeyError:
                self.count[pred] = 1
        else:
            self.count += 1

    ### eval : Network -> Packet -> unit
    def eval(self, network, packet):
        self.inc(packet)
        return Counter([])


class transform_network(Policy):
    def __init__(self, transform, policy):
        self.transformed_networks = {}
        self.transform = transform
        self.policy = policy

    def __repr__(self):
        return "transform_network\n%s" % util.repr_plus([self.policy])

    def update_network(self, network):
        self.detach(network)
        self.attach(network)

    def attach(self, network):
        if network not in self.transformed_networks:
            self.transformed_networks[network] = tn = self.transform(network)
            self.policy.attach(tn)

    def eval(self, network, packet):
        return self.policy.eval(self.transformed_networks[network], packet)

    def detach(self, network):
        if network in self.transformed_networks:
            self.policy.detach(self.transformed_networks[network])
        del self.transformed_networks[network]
