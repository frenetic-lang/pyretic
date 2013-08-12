
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
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
import time
from bitarray import bitarray

from pyretic.core import util
from pyretic.core.network import *
from pyretic.core.util import frozendict, singleton

import datetime
import os
from tools.logger import simpleLogger

useTraceFile = True
MATCHLOGLEVEL = 3
MATCHPREFIXLOGLEVEL = 4

traceMatch    = None
traceMatchIP  = None

################################################################################
# Matching                                                                     #
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
        #self.trace = simpleLogger.geTracePyretic()
                
        self.masklen = 32
        if isinstance(pattern, IP):     # IP OBJECT
            self.pattern = pattern
        else:                           # STRING ENCODING
            parts = pattern.split("/")
            self.pattern = IP(parts[0])
            if len(parts) == 2:
                self.masklen = int(parts[1])
        self.prefix = self.pattern.to_bits()[:self.masklen]
        #self.trace("pattern=%s prefix=%s" % (self.pattern, self.prefix))
       
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
# Determine how each field will be matched                                     #
################################################################################
        
_field_to_patterntype = {}

def register_field(field, patterntype):
    _field_to_patterntype[field] = patterntype

def field_patterntype(field):
    return _field_to_patterntype.get(field, ExactMatch)

register_field("srcip", PrefixMatch)
register_field("dstip", PrefixMatch)

################################################################################
# Policy Language                                                              #
################################################################################

class Policy(object):
    """Top-level abstract class for policies.
    All Pyretic policies evaluate on a single packet and return a set of packets.
    """
    def __init__(self):
        self._network = None
        
    @property
    def network(self):
        return self._network
        
    def set_network(self, network):
        self._network = network

    ### add : Policy -> Policy
    def __add__(self, pol):
        if isinstance(pol,parallel):
            return parallel([self] + pol.policies)
        else:
            return parallel([self, pol])

    ### or : Policy -> Policy
    def __or__(self, pol):
        return self + pol
        
    ### rshift : Policy -> Policy
    def __rshift__(self, pol):
        if isinstance(pol,sequential):
            return sequential([self] + pol.policies)
        else:
            return sequential([self, pol])

    ### and : Policy -> Policy
    def __and__(self, pol):
        return self >> pol

    ### sub : Policy -> Policy
    def __sub__(self, pol):
        return difference([self, pol])
    
    ### invert : unit -> Policy
    def __invert__(self):
        return negate(self)

    ### eq : Policy -> bool
    def __eq__(self,pol):
        return id(self) == id(pol)

    ### eval : Packet -> Set Packet
    def __eval__(self, pkt):
        raise NotImplementedError

    def track_eval(self, pkt, dry):
        return (self.eval(pkt), EvalTrace(self))

    def name(self):
        return self.__class__.__name__

    ### repr : unit -> String
    def __repr__(self):
        return "%s : %d" % (self.name(),id(self))


class EvalTrace(object):
    def __init__(self,ne):
        self.ne = ne
        self.traces = []

    def add_trace(self,trace):
        self.traces.append(trace)

    def contains_class(self,cls):
        if self.ne.__class__ == cls:
            return True
        for trace in self.traces:
            if trace.contains_class(cls):
                return True
        return False
            
    def __repr__(self):
        if self.traces:
            return self.ne.name() + '[' + ']['.join(map(repr,self.traces))+']'
        else:
            return self.ne.name()

    
class StaticPolicy(Policy):
    """Abstact class for static policies. 
    The behavior of a static policy never changes."""
    pass

class PrimitivePolicy(StaticPolicy):
    """Abstact class for primitive policies."""
    pass


@singleton
class identity(PrimitivePolicy):
    """The identity policy"""
    def eval(self, pkt):
        return {pkt}

    def __repr__(self):
        return "identity"
passthrough = identity   # Imperative alias
all_packets = identity   # Logic alias

        
@singleton
class none(PrimitivePolicy):
    """The policy that drops a pkt"""
    def eval(self, pkt):
        return set()

    def __repr__(self):
        return "none"
drop = none              # Imperative alias
no_packets = none        # Logic alias


class match(PrimitivePolicy):
    """A set of field matches on a packet (one per field)."""
    
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        #self.trace = simpleLogger.geTracePyretic()
                
        init_map = {}
        for (k, v) in dict(*args, **kwargs).iteritems():
            if v is not None:
                patterntype = field_patterntype(k)
                pattern_to_match = patterntype(v)
                init_map[k] = pattern_to_match
            else: 
                init_map[k] = None
        self.map = util.frozendict(init_map)
        #self.trace("patterns to match: %s\n" % self.map, True)                 # hph
        super(match,self).__init__()

    ### hash : unit -> int
    def __hash__(self):
        return hash(self.map)
    
    ### eq : PrimitivePolicy -> bool
    def __eq__(self, other):
        try:
            return self.map == other.map
        except:
            return False

    def eval(self, pkt):
        #self.trace("match eval pkt:\n%s\n" % {pkt}, True)                        # hph

        for field, pattern in self.map.iteritems():
            v = pkt.get_stack(field)
            #self.trace("match eval: pattern=%s field=%s v=%s" % (pattern, field, v))     

            if v:
                if pattern is None or not pattern.match(v[0]):
                    return set()
            else:
                if pattern is not None:
                    return set()
        #self.trace("\nmatch eval return pkt\n")                             # hph
        return {pkt}

    def __repr__(self):
        return "match:\n%s" % util.repr_plus(self.map.items())
        

class push(PrimitivePolicy):
    """push(field=value) pushes value onto header field stack."""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)
        super(push,self).__init__()
        
    def eval(self, pkt):
        return {pkt.pushmany(self.map)}

    def __repr__(self):
        return "push:\n%s" % util.repr_plus(self.map.items())

        
class pop(PrimitivePolicy):
    """pop('field') pops value off header field stack"""
    ### init : List String -> unit
    def __init__(self, *args):
        self.fields = list(args)
        super(pop,self).__init__()
        
    def eval(self, pkt):
        return {pkt.popmany(self.fields)}

    def __repr__(self):
        return "pop:\n%s" % util.repr_plus(self.fields)

    
class copy(PrimitivePolicy):
    """copy(field1='field2') pushes the value stored at the top of 
    the header field2 stack unto header field1 stack"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)
        super(copy,self).__init__()
       
    def eval(self, pkt):
        pushes = {}
        for (dstfield, srcfield) in self.map.iteritems():
            pushes[dstfield] = pkt[srcfield]
        return {pkt.pushmany(pushes)}
        
    def __repr__(self):
        return "copy:\n%s" % util.repr_plus(self.map.items())


################################################################################
# Combinator Policies                                                          #
################################################################################

class CombinatorPolicy(StaticPolicy):
    """Abstract class for policy combinators.
    A policy combinator takes one or more policies and produces a new 
    policy with the specified semantics."""
    ### init : List Policy -> unit
    def __init__(self, policies):
        self.policies = list(policies)
        super(CombinatorPolicy,self).__init__()

    def set_network(self, network):
        super(CombinatorPolicy,self).set_network(network)
        for policy in self.policies:
            policy.set_network(network) 

    def __repr__(self):
        return "%s:\n%s" % (self.name(),util.repr_plus(self.policies))


class difference(CombinatorPolicy):
    def eval(self, pkt):
        return self.policies[0].eval(pkt) - self.policies[1].eval(pkt)

    def track_eval(self, pkt, dry):
        eval_trace = EvalTrace(self)
        (results1,trace1) = self.policies[0].track_eval(pkt,dry)
        (results2,trace2) = self.policies[1].track_eval(pkt,dry)
        eval_trace.add_trace(trace1)
        eval_trace.add_trace(trace2)
        return (results1 - results2, eval_trace)


class parallel(CombinatorPolicy):
    """parallel(policies) evaluates to the set union of the evaluation
    of each policy in policies."""
    def __add__(self, pol):
        if isinstance(pol,parallel):
            return parallel(self.policies + pol.policies)
        else:
            return parallel(self.policies + [pol])

    def eval(self, pkt):
        output = set()
        for policy in self.policies:
            output |= policy.eval(pkt)
        return output

    def track_eval(self, pkt, dry):
        eval_trace = EvalTrace(self)
        output = set()
        for policy in self.policies:
            (results,trace) = policy.track_eval(pkt,dry)
            output |= results
            eval_trace.add_trace(trace)
        return (output,eval_trace)
    

class sequential(CombinatorPolicy):
    """sequential(policies) evaluates the set union of each policy in policies 
    on each packet in the output of previous policy."""
    def __rshift__(self, pol):
        if isinstance(pol,sequential):
            return sequential(self.policies + pol.policies)
        else:
            return sequential(self.policies + [pol])

    def eval(self, pkt):
        prev_output = {pkt}
        output = prev_output
        for policy in self.policies:
            if not prev_output:
                return set()
            if policy == identity:
                continue
            if policy == none:
                return set()
            output = set()
            for p in prev_output:
                output |= policy.eval(p)
            prev_output = output
        return output

    def track_eval(self, pkt, dry):
        eval_trace = EvalTrace(self)
        prev_output = {pkt}
        output = prev_output
        for policy in self.policies:
            if not prev_output:
                return (set(),eval_trace)
            if policy == identity:
                eval_trace.add_trace(EvalTrace(policy))
                continue
            if policy == none:
                eval_trace.add_trace(EvalTrace(policy))
                return (set(),eval_trace)
            output = set()
            for p in prev_output:
                (results,trace) = policy.track_eval(p,dry)
                output |= results
                eval_trace.add_trace(trace)
            prev_output = output
        return (output,eval_trace)
  

################################################################################
# Derived Policies                                                             #
################################################################################
        
class DerivedPolicy(Policy):
    """Abstract class for policies derived from other policies."""
    def __init__(self, policy=passthrough):
        self.policy = policy
        super(DerivedPolicy,self).__init__()

    def set_network(self, network):
        super(DerivedPolicy,self).set_network(network)            
        self.policy.set_network(network) 

    def eval(self, pkt):
        tmp = self.policy.eval(pkt)
        return tmp

    def track_eval(self, pkt, dry):
        eval_trace = EvalTrace(self)
        (results,trace) = self.policy.track_eval(pkt,dry)
        eval_trace.add_trace(trace)
        return (results,eval_trace)


class negate(DerivedPolicy):
    def __init__(self, policy_to_negate):
        self.policy_to_negate = policy_to_negate
        super(negate,self).__init__(identity - policy_to_negate)

    def __repr__(self):
        return "negate:\n%s" % util.repr_plus([self.policy_to_negate])


class modify(DerivedPolicy):
    """modify(field=value) is equivalent to
    pop('field') >> push(field=value)"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)
        super(modify,self).__init__(pop(*[k for k in self.map.keys()]) >>
                                    push(**self.map))

    def __repr__(self):
        return "modify:\n%s" % util.repr_plus(self.map.items())

        
class move(DerivedPolicy):
    """move(field1='field2') is equivalent to 
    copy(field1='field2') >> pop('field2')"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)
        super(move,self).__init__(copy(**self.map) >>
                                  pop(*[k for k in self.map.values()]))
  
    def __repr__(self):
        return "move:\n%s" % util.repr_plus(self.map.items())


class if_(DerivedPolicy):
    """if predicate holds, t_branch, otherwise f_branch."""
    ### init : Policy -> Policy -> Policy -> unit
    def __init__(self, pred, t_branch, f_branch=passthrough):
        self.pred = pred
        self.t_branch = t_branch
        self.f_branch = f_branch
        super(if_,self).__init__((self.pred & self.t_branch) + 
                                 ((~self.pred) & self.f_branch))

    def __repr__(self):
        return "if\n%s\nthen\n%s\nelse\n%s" % (util.repr_plus([self.pred]),
                                               util.repr_plus([self.t_branch]),
                                               util.repr_plus([self.f_branch]))


class fwd(DerivedPolicy):
    """fwd(port) is equivalent to pushing port onto the top of the outport
    stack, unless the topmost outport stack value is placeholder -1 
    (in which case we first pop, then push).""" 
    ### init : int -> unit
    def __init__(self, outport):
        self.outport = outport
        super(fwd,self).__init__(if_(match(outport=-1),pop('outport')) 
                                 >> push(outport=self.outport))

    def __repr__(self):
        return "fwd %s" % self.outport


class xfwd(DerivedPolicy):
    """xfwd(outport) is equivalent to fwd(outport), except when inport=outport.
    (The same semantics as OpenFlow's fwd action)"""
    def __init__(self, outport):
        self.outport = outport    
        super(xfwd,self).__init__((~match(inport=outport)) >> fwd(outport))

    def __repr__(self):
        return "xfwd %s" % self.outport


class recurse(DerivedPolicy):
    """A policy that can refer to itself w/o causing the runtime/compiler to die."""
    def set_network(self, network):
        if network == self.policy._network:
            return
        super(recurse,self).set_network(network)

    def __repr__(self):
        return "[recurse]:\n%s" % repr(self.policy)


################################################################################
# Dynamic Policies                                                             #
################################################################################

class DynamicPolicy(DerivedPolicy):
    """Abstact class for dynamic policies.
    The behavior of a dynamic policy changes each time its internal property
    named 'policy' is reassigned."""
    ### init : unit -> unit
    def __init__(self,policy=drop):
        self._policy = policy
        self.notify = None
        super(DerivedPolicy,self).__init__()

    def attach(self,notify):
        self.notify = notify

    def detach(self):
        self.notify = None

    def changed(self,changed,old,new):
        if self.notify:
            self.notify(changed,old,new)

    @property
    def policy(self):
        return self._policy
        
    @policy.setter
    def policy(self, policy):
        prev_policy = self._policy
        self._policy = policy
        if self.network:
            if (not self._policy.network or 
                (self.network.topology != self._policy.network.topology)):
                self._policy.set_network(self.network)
        self.changed(self,prev_policy,policy)

    def __repr__(self):
        return "[DynamicPolicy]\n%s" % repr(self.policy)

        
# dynamic : (DecoratedPolicy ->  unit) -> DecoratedPolicy
def dynamic(fn):
    """Decorator for dynamic policies.
    Will initialize a dynamic policy based on the input function (fn)
    and return a new dynamic policy class whose name is identical to that of fn.
    Calling the constructor of the returned policy class creates an instance which
    can then be used like any other policy."""
    class DecoratedDynamicPolicy(DynamicPolicy):
        def __init__(self, *args, **kwargs):
            # THIS CALL WORKS BY SETTING THE BEHAVIOR OF MEMBERS OF SELF.
            # IN PARICULAR, THE register_callback FUNCTION RETURNED BY self.query 
            # (ITSELF A MEMBER OF A queries_base CREATED BY self.query)
            # THIS ALLOWS FOR DECORATED POLICIES TO EVOLVE ACCORDING TO 
            # FUNCTION REGISTERED FOR CALLBACK EACH TIME A NEW EVENT OCCURS
            DynamicPolicy.__init__(self)
            fn(self, *args, **kwargs)

        def __repr__(self):
            return "[dynamic(%s)]\n%s" % (self.name(), repr(self.policy))
        
    # SET THE NAME OF THE DECORATED POLICY RETURNED TO BE THAT OF THE INPUT FUNCTION
    DecoratedDynamicPolicy.__name__ = fn.__name__
    return DecoratedDynamicPolicy


class flood(DynamicPolicy):
    """Policy that floods packets on a minimum spanning tree, recalculated 
    every time the network is updated (set_network)."""
    def __init__(self):
        self.mst = None
        super(flood,self).__init__()
        
    def set_network(self, network):
        changed = False
        super(flood,self).set_network(network) 
        if not network is None:
            updated_mst = Topology.minimum_spanning_tree(network.topology)
            if not self.mst is None:
                if self.mst != updated_mst:
                    self.mst = updated_mst
                    changed = True
            else:
                self.mst = updated_mst
                changed = True
        if changed:
            self.policy = parallel([
                    match(switch=switch) >>
                        parallel(map(xfwd,attrs['ports'].keys()))
                    for switch,attrs in self.mst.nodes(data=True)])

    def __repr__(self):
        try: 
            return "flood on:\n%s" % self.mst
        except:
            return "flood"


class ingress_network(DynamicPolicy):
    """Returns True if a packet is located at a (switch,inport) pair entering
    the network, False otherwise."""
    def __init__(self):
        self.egresses = None
        super(ingress_network,self).__init__()

    def set_network(self, network):
        super(ingress_network,self).set_network(network)
        updated_egresses = network.topology.egress_locations()
        if not self.egresses == updated_egresses:
            self.egresses = updated_egresses
            self.policy = parallel([match(switch=l.switch,
                                       inport=l.port_no) 
                                 for l in self.egresses])

    def __repr__(self):
        return "ingress_network"

        
class egress_network(DynamicPolicy):
    """Returns True if a packet is located at a (switch,outport) pair leaving
    the network, False otherwise."""
    def __init__(self):
        self.egresses = None
        super(egress_network,self).__init__()
    
    def set_network(self, network):
        super(egress_network,self).set_network(network)
        updated_egresses = network.topology.egress_locations()
        if not self.egresses == updated_egresses:
            self.egresses = updated_egresses
            self.policy = parallel([match(switch=l.switch,
                                       outport=l.port_no) 
                                 for l in self.egresses])

    def __repr__(self):
        return "egress_network"


################################################################################
# Query Policies                                                               #
################################################################################

class FwdBucket(StaticPolicy):
    """Abstract class representing a data structure 
    into which packets (conceptually) go and with which callbacks can register.
    """
    ### init : unit -> unit
    def __init__(self):
        self.callbacks = []
        super(FwdBucket,self).__init__()

    def eval(self, pkt):
        for callback in self.callbacks:
            callback(pkt)
        return set()

    ### register_callback : (Packet -> X) -> unit 
    def register_callback(self, fn):
        self.callbacks.append(fn)


class packets(DynamicPolicy):
    """Effectively a FwdBucket which calls back all registered routines on each 
    packet evaluated.
    A positive integer limit will cause callback to cease after limit packets of
    a given group have been seen.  group_by defines the set of headers used for 
    grouping - two packets are in the same group if they match on all headers in the
    group_by.  If no group_by is specified, the default is to match on all available
    headers."""
    class BoolWrappedFwdBucket(Policy):
        def __init__(self,limit=None,group_by=[]):
            self.limit = limit
            self.group_by = group_by
            self.seen = {}
            self.fwd_bucket = FwdBucket()
            self.register_callback = self.fwd_bucket.register_callback
            super(packets.BoolWrappedFwdBucket,self).__init__()

        def eval(self,pkt):
            if not self.limit is None:
                if self.group_by:    # MATCH ON PROVIDED GROUP_BY
                    pred = match([(field,pkt[field]) for field in self.group_by])
                else:              # OTHERWISE, MATCH ON ALL AVAILABLE GROUP_BY
                    pred = match([(field,pkt[field]) 
                                  for field in pkt.available_group_by()])
                # INCREMENT THE NUMBER OF TIMES MATCHING PKT SEEN
                try:
                    self.seen[pred] += 1
                except KeyError:
                    self.seen[pred] = 1

                if self.seen[pred] > self.limit:
                    return set()
            self.fwd_bucket.eval(pkt)
            return {pkt}
        
    def __init__(self,limit=None,group_by=[]):
        self.limit = limit
        self.seen = {}
        self.group_by = group_by
        self.pwfb = self.BoolWrappedFwdBucket(limit,group_by)
        self.register_callback = self.pwfb.register_callback
        super(packets,self).__init__(all_packets)

    def eval(self,pkt):
        """Don't look any more such packets"""
        if self.policy.eval(pkt) and not self.pwfb.eval(pkt):
            val = {h : pkt[h] for h in self.group_by}
            self.policy = ~match(val) & self.policy
        return set()

    def track_eval(self,pkt,dry):
        """Don't look any more such packets"""
        eval_trace = EvalTrace(self)
        (results,trace) = self.policy.track_eval(pkt,dry)
        eval_trace.add_trace(trace)
        if results: 
            if not dry:
                (results,trace) = self.pwfb.track_eval(pkt,dry)
                eval_trace.add_trace(trace)
                if not results:
                    val = {h : pkt[h] for h in self.group_by}
                    self.policy = ~match(val) & self.policy
            else:
                eval_trace.add_trace(EvalTrace(self.pwfb))
        return (set(),eval_trace)

    def __repr__(self):
        return "packets\n%s" % repr(self.policy)
        

class AggregateFwdBucket(FwdBucket):
    """An abstract FwdBucket which calls back all registered routines every interval
    seconds (can take positive fractional values) with an aggregate value/dict.
    If group_by is empty, registered routines are called back with a single aggregate
    value.  Otherwise, group_by defines the set of headers used to group counts which
    are then returned as a dictionary."""
    ### init : int -> List String
    def __init__(self, interval, group_by=[]):
        FwdBucket.__init__(self)
        self.interval = interval
        self.group_by = group_by
        if group_by:
            self.aggregate = {}
        else:
            self.aggregate = 0
        import threading
        import pyretic.core.runtime
        self.query_thread = threading.Thread(target=self.report_count)
        self.query_thread.daemon = True
        self.query_thread.start()

    def report_count(self):
        while(True):
            for callback in self.callbacks:
                callback(self.aggregate)
            time.sleep(self.interval)

    def aggregator(self,aggregate,pkt):
        raise NotImplementedError

    ### update : Packet -> unit
    def update_aggregate(self,pkt):
        if self.group_by:
            from pyretic.core.language import match
            groups = set(self.group_by) & set(pkt.available_fields())
            pred = match([(field,pkt[field]) for field in groups])
            try:
                self.aggregate[pred] = self.aggregator(self.aggregate[pred],pkt)
            except KeyError:
                self.aggregate[pred] = self.aggregator(0,pkt)
        else:
            self.aggregate = self.aggregator(self.aggregate,pkt)

    def eval(self, pkt):
        self.update_aggregate(pkt)
        return set()

    def track_eval(self, pkt, dry):
        if dry:
            return (set(), EvalTrace(self))
        else:
            return (self.eval(pkt), EvalTrace(self))


class counts(AggregateFwdBucket):
    """AggregateFwdBucket that calls back with aggregate count of packets."""
    def aggregator(self,aggregate,pkt):
        return aggregate + 1


class sizes(AggregateFwdBucket):
    """AggregateFwdBucket that calls back with aggregate bytesize of packets."""
    def aggregator(self,aggregate,pkt):
        return aggregate + pkt['header_len'] + pkt['payload_len']
