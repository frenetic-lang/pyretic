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
# Netcore Policy Language
################################################################################

class NetworkEvaluated(object):
    @property
    def network(self):
        try:
            return self._network
        except:
            return None

    def set_network(self, value):
        self._network = value

    def eval(self, packet):
        raise NotImplementedError        

    
################################################################################
# Predicates
################################################################################

class Predicate(NetworkEvaluated):
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

        
@singleton
class all_packets(Predicate):
    """The always-true predicate."""
    ### repr : unit -> String
    def __repr__(self):
        return "all packets"

    ### eval : Packet -> bool
    def eval(self, packet):
        return True
        
        
@singleton
class no_packets(Predicate):
    """The always-false predicate."""
    ### repr : unit -> String
    def __repr__(self):
        return "no packets"

    ### eval : Packet -> bool
    def eval(self, packet):
        return False

        
@singleton
class ingress(Predicate):
    ### repr : unit -> String
    def __repr__(self):
        return "ingress"
    
    ### eval : Packet -> bool
    def eval(self, packet):
        switch = packet["switch"]
        port_no = packet["inport"]
        return Location(switch,port_no) in self.network.topology.egress_locations()

        
@singleton
class egress(Predicate):
    ### repr : unit -> String
    def __repr__(self):
        return "egress"
    
    ### eval : Packet -> bool
    def eval(self, packet):
        switch = packet["switch"]
        try:
            port_no = packet["outport"]
        except:
            return False
        return Location(switch,port_no) in self.network.topology.egress_locations()

        
class match(Predicate):
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

    ### eval : Packet -> bool
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
    """A predicate representing the union of a list of predicates."""

    ### init : List Predicate -> unit
    def __init__(self, predicates):
        self.predicates = list(predicates)
        
    ### repr : unit -> String
    def __repr__(self):
        return "union:\n%s" % util.repr_plus(self.predicates)

    def set_network(self, value):
        for pred in self.predicates:
            pred.set_network(value)
        super(union,self).set_network(value)

    def eval(self, packet):
        return any(predicate.eval(packet) for predicate in self.predicates)

        
class intersect(Predicate):
    """A predicate representing the intersection of a list of predicates."""

    def __init__(self, predicates):
        self.predicates = list(predicates)
        
    ### repr : unit -> String
    def __repr__(self):
        return "intersect:\n%s" % util.repr_plus(self.predicates)

    def set_network(self, value):
        for pred in self.predicates:
            pred.set_network(value)
        super(intersect,self).set_network(value)

    def eval(self, packet):
        return all(predicate.eval(packet) for predicate in self.predicates)

    

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

    def set_network(self, value):
        self.base_predicate.set_network(value)
        for pred in self.diff_predicates:
            pred.set_network(value)
        super(difference,self).set_network(value)

    def eval(self, packet):
        return self.base_predicate.eval(packet) and not \
            any(pred.eval(packet)
                for pred in self.diff_predicates)
    

class negate(Predicate):
    """A predicate representing the difference of two predicates."""

    ### init : Predicate -> unit
    def __init__(self, predicate):
        self.predicate = predicate
        
    ### repr : unit -> String
    def __repr__(self):
        return "negate:\n%s" % util.repr_plus([self.predicate])

    def set_network(self, value):
        self.predicate.set_network(value)
        super(negate,self).set_network(value)

    ### eval : Packet -> bool
    def eval(self, packet):
        return not self.predicate.eval(packet)
        
        
################################################################################
# Policies
################################################################################

class Policy(NetworkEvaluated):
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


class pkt_print(Policy):
    def __init__(self,s=''):
        self.s = s

    ### repr : unit -> String
    def __repr__(self):
        return "pkt_print %s" % self.s
        
    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        print "---- pkt_print %s -------" % self.s
        print packet
        print "-------------------------------"
        return Counter([packet])


class net_print(Policy):
    def __init__(self,s=''):
        self.s = s

    ### repr : unit -> String
    def __repr__(self):
        return "net_print %s" % self.s
        
    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        print "---- net_print %s -------" % self.s
        print self.network
        print "-------------------------------"
        return Counter([packet])
        
@singleton
class passthrough(Policy):
    ### repr : unit -> String
    def __repr__(self):
        return "passthrough"
        
    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        return Counter([packet])

        
@singleton
class drop(Policy):
    """Policy that drops everything."""
    ### repr : unit -> String
    def __repr__(self):
        return "drop"
        
    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        return Counter()

        
@singleton
class flood(Policy):
    ### repr : unit -> String
    def __repr__(self):
        try: 
            return "flood on:\n%s" % self.mst
        except:
            return "flood"

    def set_network(self, value):
        if not value is None:
            self.mst = Topology.minimum_spanning_tree(value.topology)
            self._network = value
        
    def eval(self, packet):
        if self.network is None:
            return Counter()
        
        switch = packet["switch"]
        inport = packet["inport"]
        if switch in self.mst:
            port_nos = set()
            port_nos.update({loc.port_no 
                             for loc in self.network.topology.egress_locations(switch)})
            for sw in self.mst.neighbors(switch):
                port_no = self.mst[switch][sw][switch]
                port_nos.add(port_no)
            packets = [packet.push(outport=port_no)
                       for port_no in port_nos if port_no != inport]
            return Counter(packets)
        else:
            return Counter()
        
        
class push(Policy):
    """push(field=value) pushes value onto header field stack"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    ### repr : unit -> String
    def __repr__(self):
        return "push:\n%s" % util.repr_plus(self.map.items())
        
    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        packet = packet.pushmany(self.map)
        return Counter([packet])


class fwd(Policy):
    """Forward packet out of a particular port
    fwd(a) equivalent to push(outport=a)"""
    ### init : int -> unit
    def __init__(self, outport):
        self.outport = outport

    ### repr : unit -> String
    def __repr__(self):
        return "fwd %s" % self.outport
    
    ### eval : Packet -> Counter List Packet        
    def eval(self, packet):
        packet = packet.push(outport=self.outport)
        return Counter([packet])

        
class pop(Policy):
    """pop('field') pops value off field stack"""
    ### init : List String -> unit
    def __init__(self, *args):
        self.fields = list(args)

    ### repr : unit -> String
    def __repr__(self):
        return "pop:\n%s" % util.repr_plus(self.fields)
        
    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        packet = packet.popmany(self.fields)
        return Counter([packet])


class modify(Policy):
    """modify(field=value) is equivalent to
    pop('field') >> push(field=value)"""
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

    ### eval : Packet -> Counter List Packet        
    def eval(self, packet):
        packet = packet.modifymany(self.map)
        return Counter([packet])


class copy(Policy):
    """copy(field1='field2') pushes the value stored at the top of 
    the field2 stack unto the field1 stack"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    ### repr : unit -> String
    def __repr__(self):
        return "copy:\n%s" % util.repr_plus(self.map.items())
  
    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        pushes = {}
        for (dstfield, srcfield) in self.map.iteritems():
            pushes[dstfield] = packet[srcfield]
        packet = packet.pushmany(pushes)
        return Counter([packet])
        
        
class move(Policy):
    """move(field1='field2') is equivalent to 
    copy(field1='field2') >> pop('field2')"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)

    ### repr : unit -> String
    def __repr__(self):
        return "move:\n%s" % util.repr_plus(self.map.items())
  
    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        pushes = {}
        pops = []
        for (dstfield, srcfield) in self.map.iteritems():
            try:
                pushes[dstfield] = packet[srcfield]
                pops.append(srcfield)
            except KeyError:
                pass
        packet = packet.pushmany(pushes).popmany(pops)
        return Counter([packet])




################################################################################
# Policy Derived from Multiple Policies
################################################################################

class MultiplyDerivedPolicy(Policy):
    ### init : List Policy -> unit
    def __init__(self, policies):
        self.policies = list(policies)

    def set_network(self, value):
        for policy in self.policies:
            policy.set_network(value) 
        super(MultiplyDerivedPolicy,self).set_network(value)

                    
class parallel(MultiplyDerivedPolicy):
    def eval(self, packet):
        c = Counter()
        for policy in self.policies:
            rc = policy.eval(packet)
            c.update(rc)
        return c
    
    ### repr : unit -> String
    def __repr__(self):
        return "parallel:\n%s" % util.repr_plus(self.policies)
        

class sequential(MultiplyDerivedPolicy):
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
    
    ### repr : unit -> String
    def __repr__(self):
        return "sequential:\n%s" % util.repr_plus(self.policies)


################################################################################
# Policy Derived from a Single Policy
################################################################################
        
class SinglyDerivedPolicy(Policy):
    def __init__(self, policy):
        self.policy = policy

    def set_network(self, value):
        if not self.policy is None:
            self.policy.set_network(value) 
        super(SinglyDerivedPolicy,self).set_network(value)

    def eval(self, packet):
        return self.policy.eval(packet)

class pol_print(SinglyDerivedPolicy):
    def __init__(self,policy,s=''):
        super(pol_print,self).__init__(policy)
        self.s = s    

    ### repr : unit -> String
    def __repr__(self):
        return "[pol_print %s]\n%s" % (self.s,self.policy)

    def eval(self, packet):
        print self.s 
        print self.policy
        return super(pol_print,self).eval(packet)

class recurse(SinglyDerivedPolicy):
    def set_network(self, value):
        self._network = value

    def eval(self, packet):
        self.policy.set_network(self.network)
        output = super(recurse,self).eval(packet)
        return output

    ### repr : unit -> String
    def __repr__(self):
        return "[recurse]:\n%s" % repr(self.policy)

class remove(SinglyDerivedPolicy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, predicate):
        self.predicate = predicate
        super(remove,self).__init__(policy)

    def set_network(self, value):
        self.predicate.set_network(value)
        super(remove,self).set_network(value)

    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        if not self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return Counter()

    ### repr : unit -> String
    def __repr__(self):
        return "remove:\n%s" % util.repr_plus([self.predicate, self.policy])

    
class restrict(SinglyDerivedPolicy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, predicate):
        self.predicate = predicate
        super(restrict,self).__init__(policy) 

    def set_network(self, value):
        self.predicate.set_network(value)
        super(restrict,self).set_network(value) 

    ### eval : Packet -> Counter List Packet
    def eval(self, packet):
        if self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return Counter()

    ### repr : unit -> String
    def __repr__(self):
        return "restrict:\n%s" % util.repr_plus([self.predicate,
                                                 self.policy])

class if_(SinglyDerivedPolicy):
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
        
class breakpoint(SinglyDerivedPolicy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, condition=lambda ps: True):
        self.condition = condition
        super(breakpoint,self).__init__(policy)

    def set_network(self, value):
        self.condition.set_network(value)
        super(breakpoint,self).set_network(value)

    def eval(self, packet):
        import ipdb
        if self.condition(packet):
            ipdb.set_trace()
        return SinglyDerivedPolicy.eval(self, packet)

    ### repr : unit -> String
    def __repr__(self):
        return "***debug***\n%s" % util.repr_plus([self.policy])


class NetworkDerivedPolicy(SinglyDerivedPolicy):
    """Generates new policy every time a new network is set"""
    def __init__(self, policy_from_network):
        self.policy_from_network = policy_from_network

    def set_network(self, value):
        if not value is None:
            self.policy = self.policy_from_network(value)
        else:
            self.policy = drop
        super(NetworkDerivedPolicy,self).set_network(value)

    def eval(self, packet):
        return self.policy.eval(packet)

    ### repr : unit -> String
    def __repr__(self):
        return "[NetworkDerivedPolicy]\n%s" % repr(self.policy)

    
def NetworkDerivedPolicyPropertyFrom(network_to_policy):
    """Makes a NetworkDerivedPolicy that is a property of a virtualization defintion 
    from a policy taking a network and returning a policy"""
    @property
    @functools.wraps(network_to_policy)
    def wrapper(self):
        return NetworkDerivedPolicy(functools.partial(network_to_policy, self))
    return wrapper


class MutablePolicy(SinglyDerivedPolicy):
    ### init : unit -> unit
    def __init__(self):
        self._policy = drop
        
    @property
    def policy(self):
        return self._policy
        
    @policy.setter
    def policy(self, value):
        self._policy = value
        self.set_network(self.network)

    ### repr : unit -> String
    def __repr__(self):
        return "[MutablePolicy]\n%s" % repr(self.policy)

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

        ### repr : unit -> String
        def __repr__(self):
            return "[DecoratedPolicy]\n%s" % repr(self.policy)
            
    # SET THE NAME OF THE DECORATED POLICY RETURNED TO BE THAT OF THE INPUT FUNCTION
    DecoratedPolicy.__name__ = fn.__name__
    return DecoratedPolicy



############################
# Query classes
############################

        
class queries_base(Policy):
    ### init : unit -> unit
    def __init__(self):
        self.listeners = []

    ### eval : Packet -> unit
    def eval(self, packet):
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

    ### eval : Packet -> unit
    def eval(self, packet):
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

        return queries_base.eval(self, packet)

        
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
        queries_base.eval(self, self.count)

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

    ### eval : Packet -> unit
    def eval(self, packet):
        self.inc(packet)
        return Counter([])



