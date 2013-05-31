
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

class NetworkEvaluated(object):
    """An abstract class whose direct decendants are Predicate and Policy"""
    def __init__(self):
        self._network = None
        self.parents = set()
        self.callback_on_change = set()

    @property
    def network(self):
        return self._network
        
    def set_network(self, network):
        self._network = network

    def set_parent(self,parent):
        self.parents.add(parent)

    def attach(self,parent):
        self.set_parent(parent)

    def unset_parent(self,parent):
        try:
            self.parents.remove(parent)
        except:
            pass

    def detach(self,parent):
        self.unset_parent(parent)

    def eval(self, packet):
        raise NotImplementedError        

    def track_eval(self, packet):
        return (self.eval(packet), EvalTrace(self))

    def on_change_do(self,fn):
        self.callback_on_change.add(fn)

    def changed(self, pathlist=[]):
        for parent in self.parents:
            parent.changed([self] + pathlist)
        for callback in self.callback_on_change:
            callback([self] + pathlist)

    def name(self):
        return self.__class__.__name__

    ### repr : unit -> String
    def __repr__(self):
        return "%s : %d" % (self.name(),id(self))


class EvalTrace(object):
    def __init__(self,ne,trace=None):
        self.ne = ne
        if trace is None:
            self.traces = []
        else:
            self.traces = [trace]

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

    
################################################################################
# Predicates                                                                   #
################################################################################

class Predicate(NetworkEvaluated):
    """Top-level abstract class for predicates.
    All Pyretic predicates evaluate on a single packet and return either True 
    or False."""
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

    ### eval : Packet -> bool
    def __eval__(self, packet):
        raise NotImplementedError


################################################################################
# Primitive Predicates                                                         #
################################################################################

class PrimitivePredicate(Predicate):
    """Abstact class for primitive (static) predicates.
    The behavior of a primite predicate never changes."""
    pass

        
@singleton
class all_packets(PrimitivePredicate):
    """The always-true predicate."""
    def eval(self, packet):
        return True

    def __repr__(self):
        return "all packets"
        
        
@singleton
class no_packets(PrimitivePredicate):
    """The always-false predicate."""
    def eval(self, packet):
        return False

    def __repr__(self):
        return "no packets"

                
class match(PrimitivePredicate):
    """A set of field matches on a packet (one per field)."""
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
        super(match,self).__init__()

    ### hash : unit -> int
    def __hash__(self):
        return hash(self.map)
    
    ### eq : PrimitivePredicate -> bool
    def __eq__(self, other):
        try:
            return self.map == other.map
        except:
            return False

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

    def __repr__(self):
        return "match:\n%s" % util.repr_plus(self.map.items())


################################################################################
# Combinator Predicates                                                        #
################################################################################

class CombinatorPredicate(Predicate):
    """Abstract class for predicate combinators.
    A predicate combinator takes one or more predicates and produces a new 
    predicate with the specified semantics."""
    pass


class negate(CombinatorPredicate):
    """Boolean negation of input predicate."""
    def __init__(self, predicate):
        self.predicate = predicate
        self.predicate.set_parent(self)
        super(negate,self).__init__()

    def set_network(self, network):
        super(negate,self).set_network(network)
        self.predicate.set_network(network)

    def attach(self,parent):
        self.predicate.attach(self)
        super(negate,self).attach(parent)

    def detach(self,parent):
        self.predicate.detach(self)
        super(negate,self).detach(parent)

    def eval(self, packet):
        return not self.predicate.eval(packet)
        
    def track_eval(self,packet):
        (result,eval_trace) = self.predicate.track_eval(packet)
        return (not result,EvalTrace(self,eval_trace))

    def __repr__(self):
        return "negate:\n%s" % util.repr_plus([self.predicate])

        
class union(CombinatorPredicate):
    """Boolean union over list of predicates."""
    ### init : List PrimitivePredicate -> unit
    def __init__(self, predicates):
        self.predicates = list(predicates)
        for predicate in self.predicates:
            predicate.set_parent(self)
        super(union,self).__init__()        

    def set_network(self, network):
        super(union,self).set_network(network)
        for pred in self.predicates:
            pred.set_network(network)

    def attach(self,parent):
        for predicate in self.predicates:
            predicate.attach(self)
        super(union,self).attach(parent)

    def detach(self,parent):
        for predicate in self.predicates:
            predicate.detach(self)
        super(union,self).detach(parent)

    def eval(self, packet):
        return any(predicate.eval(packet) for predicate in self.predicates)

    def track_eval(self, packet):
        eval_trace = EvalTrace(self)
        for predicate in self.predicates:
            (result,trace) = predicate.track_eval(packet)
            eval_trace.add_trace(trace)
            if result:
                return (True,eval_trace)
        return (False,eval_trace)

    def __repr__(self):
        return "union:\n%s" % util.repr_plus(self.predicates)

        
class intersect(CombinatorPredicate):
    """Boolean intersection over list of predicates."""
    ### init : List PrimitivePredicate -> unit
    def __init__(self, predicates):
        self.predicates = list(predicates)
        for predicate in self.predicates:
            predicate.set_parent(self)
        super(intersect,self).__init__()
                
    def set_network(self, network):
        super(intersect,self).set_network(network)
        for pred in self.predicates:
            pred.set_network(network)

    def attach(self,parent):
        for predicate in self.predicates:
            predicate.attach(self)
        super(intersect,self).attach(parent)

    def detach(self,parent):
        for predicate in self.predicates:
            predicate.detach(self)
        super(intersect,self).detach(parent)

    def eval(self, packet):
        return all(predicate.eval(packet) for predicate in self.predicates)

    def track_eval(self, packet):
        eval_trace = EvalTrace(self)
        for predicate in self.predicates:
            (result,trace) = predicate.track_eval(packet)
            eval_trace.add_trace(trace)
            if not result:
                return (False,eval_trace)
        return (True,eval_trace)

    def __repr__(self):
        return "intersect:\n%s" % util.repr_plus(self.predicates)


################################################################################
# Derived Predicates                                                           #
################################################################################

class DerivedPredicate(Predicate):
    """Abstract class for predicates derived from other predicates."""
    ### init : PrimitivePredicate -> unit
    def __init__(self, predicate):
        self.predicate = predicate
        self.predicate.set_parent(self)
        super(DerivedPredicate,self).__init__()

    def set_network(self, network):
        super(DerivedPredicate,self).set_network(network)
        self.predicate.set_network(network)

    def attach(self,parent):
        self.predicate.attach(self)
        super(DerivedPredicate,self).attach(parent)

    def detach(self,parent):
        self.predicate.detach(self)
        super(DerivedPredicate,self).detach(parent)

    def eval(self, packet):
        return self.predicate.eval(packet)

    def track_eval(self,packet):
        (result,trace) = self.predicate.track_eval(packet)
        return (result,EvalTrace(self,trace))


class difference(DerivedPredicate):
    """The Boolean difference of two predicates."""
    ### init : Predicate -> Predicate -> unit
    def __init__(self,pred1,pred2):
        self.pred1 = pred1
        self.pred2 = pred1
        super(difference,self).__init__((~pred2) & pred1)
        
    ### repr : unit -> String
    def __repr__(self):
        return "difference:\n%s" % util.repr_plus([self.pred1,
                                                   self.pred2])

        
################################################################################
# Policies                                                                     #
################################################################################

class Policy(NetworkEvaluated):
    """Top-level abstract class for policies.
    All Pyretic policies evaluate on a single packet and return a set of packets.
    """
    ### sub : Predicate -> Policy
    def __sub__(self, pred):
        return remove(self, pred)

    ### and : Predicate -> Policy
    def __and__(self, pred):
        return restrict(self, pred)

    ### add : Policy -> Policy
    def __add__(self, other):
        return parallel([self, other])
        
    ### rshift : Policy -> Policy
    def __rshift__(self, pol):
        return sequential([self, pol])

    ### eq : Policy -> bool
    def __eq__(self, other):
        raise NotImplementedError

    ### eval : Packet -> Set Packet
    def __eval__(self, packet):
        raise NotImplementedError


################################################################################
# Primitive Policies                                                           #
################################################################################

class PrimitivePolicy(Policy):
    """Abstact class for primitive (static) policies.
    The behavior of a primite policy never changes."""
    pass
        

@singleton
class passthrough(PrimitivePolicy):
    """The identity policy"""
    def eval(self, packet):
        return {packet}

    def __repr__(self):
        return "passthrough"

        
@singleton
class drop(PrimitivePolicy):
    """The policy that drops a packet"""
    def eval(self, packet):
        return set()

    def __repr__(self):
        return "drop"


class push(PrimitivePolicy):
    """push(field=value) pushes value onto header field stack."""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)
        super(push,self).__init__()
        
    def eval(self, packet):
        packet = packet.pushmany(self.map)
        return {packet}

    def __repr__(self):
        return "push:\n%s" % util.repr_plus(self.map.items())

        
class pop(PrimitivePolicy):
    """pop('field') pops value off header field stack"""
    ### init : List String -> unit
    def __init__(self, *args):
        self.fields = list(args)
        super(pop,self).__init__()
        
    def eval(self, packet):
        packet = packet.popmany(self.fields)
        return {packet}

    def __repr__(self):
        return "pop:\n%s" % util.repr_plus(self.fields)


class copy(PrimitivePolicy):
    """copy(field1='field2') pushes the value stored at the top of 
    the header field2 stack unto header field1 stack"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)
        super(copy,self).__init__()

    def eval(self, packet):
        pushes = {}
        for (dstfield, srcfield) in self.map.iteritems():
            pushes[dstfield] = packet[srcfield]
        packet = packet.pushmany(pushes)
        return {packet}
        
    def __repr__(self):
        return "copy:\n%s" % util.repr_plus(self.map.items())


################################################################################
# Combinator Policies                                                          #
################################################################################

class CombinatorPolicy(Policy):
    """Abstract class for policy combinators.
    A policy combinator takes one or more policies and produces a new 
    policy with the specified semantics."""
    pass

    
class restrict(CombinatorPolicy):
    """restrict(policy,predicate) evaluates to policy if predicate evaluates to
    True, drop if predicate evalutes to False."""
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, predicate):
        self.policy = policy
        self.predicate = predicate
        self.policy.set_parent(self)
        self.predicate.set_parent(self)
        super(restrict,self).__init__() 

    def set_network(self, network):
        super(restrict,self).set_network(network)
        self.policy.set_network(network) 
        self.predicate.set_network(network)

    def detach(self,parent):
        self.predicate.detach(self)
        self.policy.detach(self)
        super(restrict,self).detach(parent)

    def attach(self,parent):
        self.predicate.attach(self)
        self.policy.attach(self)
        super(restrict,self).attach(parent)

    def eval(self, packet):
        if self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return set()

    def track_eval(self, packet):
        (result,trace) = self.predicate.track_eval(packet)
        eval_trace = EvalTrace(self,trace)
        if result:
            (result,trace) = self.policy.track_eval(packet)
            eval_trace.add_trace(trace)
            return (result,eval_trace)
        else:
            return (set(),eval_trace)

    def __repr__(self):
        return "restrict:\n%s" % util.repr_plus([self.predicate,
                                                 self.policy])

                    
class parallel(CombinatorPolicy):
    """parallel(policies) evaluates to the set union of the evaluation
    of each policy in policies."""
    ### init : List Policy -> unit
    def __init__(self, policies):
        self.policies = list(policies)
        for policy in self.policies:
            policy.set_parent(self)
        super(parallel,self).__init__()

    def set_network(self, network):
        super(parallel,self).set_network(network)
        for policy in self.policies:
            policy.set_network(network) 

    def attach(self,parent):
        for policy in self.policies:
            policy.attach(self)
        super(parallel,self).attach(parent)

    def detach(self,parent):
        for policy in self.policies:
            policy.detach(self)
        super(parallel,self).detach(parent)

    def eval(self, packet):
        output = set()
        for policy in self.policies:
            output |= policy.eval(packet)
        return output

    def track_eval(self, packet):
        eval_trace = EvalTrace(self)
        output = set()
        for policy in self.policies:
            (result,trace) = policy.track_eval(packet)
            eval_trace.add_trace(trace)
            output |= result
        return (output,eval_trace)
    
    def __repr__(self):
        return "parallel:\n%s" % util.repr_plus(self.policies)
        

class sequential(CombinatorPolicy):
    """sequential(policies) evaluates the set union of each policy in policies 
    on each packet in the output of previous policy."""
    ### init : List Policy -> unit
    def __init__(self, policies):
        self.policies = list(policies)
        for policy in self.policies:
            policy.set_parent(self)
        super(sequential,self).__init__()

    def set_network(self, network):
        super(sequential,self).set_network(network)
        for policy in self.policies:
            policy.set_network(network) 

    def attach(self,parent):
        for policy in self.policies:
            policy.attach(self)
        super(sequential,self).attach(parent)

    def detach(self,parent):
        for policy in self.policies:
            policy.detach(self)
        super(sequential,self).detach(parent)

    def eval(self, packet):
        input_set = {packet}
        for policy in self.policies:
            output_set = set()
            for packet in input_set:
                output_set |= policy.eval(packet)
            input_set = output_set
        return output_set

    def track_eval(self, packet):
        eval_trace = EvalTrace(self)
        input_set = {packet}
        for policy in self.policies:
            output_set = set()
            for packet in input_set:
                (result,trace) = policy.track_eval(packet)
                eval_trace.add_trace(trace)
                output_set |= result
            input_set = output_set
        return (output_set,eval_trace)
    
    def __repr__(self):
        return "sequential:\n%s" % util.repr_plus(self.policies)
  

################################################################################
# Derived Policies                                                             #
################################################################################
        
class DerivedPolicy(Policy):
    """Abstract class for policies derived from other policies."""
    def __init__(self, policy):
        self.policy = policy
        self.policy.set_parent(self)
        super(DerivedPolicy,self).__init__()

    def set_network(self, network):
        super(DerivedPolicy,self).set_network(network)            
        if not self.policy is None:
            self.policy.set_network(network) 

    def attach(self,parent):
        self.policy.attach(self)
        super(DerivedPolicy,self).attach(parent)

    def detach(self,parent):
        self.policy.detach(self)
        super(DerivedPolicy,self).detach(parent)

    def eval(self, packet):
        return self.policy.eval(packet)

    def track_eval(self, packet):
        (result,trace) = self.policy.track_eval(packet)
        return (result,EvalTrace(self,trace))


class remove(DerivedPolicy):
    """remove(policy,predicate) is equivalent to (~predicate)[policy]."""
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, predicate):
        self.policy = policy
        self.predicate = predicate
        super(remove,self).__init__((~predicate)[policy])

    def __repr__(self):
        return "remove:\n%s" % util.repr_plus([self.predicate, self.policy])


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
        super(xfwd,self).__init__(fwd(outport) - match(inport=outport))

    def __repr__(self):
        return "xfwd %s" % self.outport


class if_(DerivedPolicy):
    """if(predicate,pol1,pol2) - evaluates pol1 if predicate evaluates to True,
    pol2 if predicate evalutes to False."""
    ### init : Predicate -> Policy -> Policy -> unit
    def __init__(self, pred, t_branch, f_branch=passthrough):
        self.pred = pred
        self.t_branch = t_branch
        self.f_branch = f_branch
        super(if_,self).__init__(self.pred[self.t_branch] + 
                                 (~self.pred)[self.f_branch])

    def __repr__(self):
        return "if\n%s\nthen\n%s\nelse\n%s" % (util.repr_plus([self.pred]),
                                               util.repr_plus([self.t_branch]),
                                               util.repr_plus([self.f_branch]))


class recurse(DerivedPolicy):
    """A policy that can refer to itself w/o causing the runtime/compiler to die."""
    def set_network(self, network):
        if network == self.policy._network:
            return
        super(recurse,self).set_network(network)

    def changed(self, pathlist=[]):
        for parent in self.parents:
            if id(parent) in map(id,pathlist):
                continue
            parent.changed([self] + pathlist)
        for callback in self.callback_on_change:
            callback([self] + pathlist)

    def attach(self,parent):
        super(DerivedPolicy,self).attach(parent)

    def detach(self,parent):
        super(DerivedPolicy,self).detach(parent)

    def __repr__(self):
        return "[recurse]:\n%s" % repr(self.policy)


################################################################################
# Dynamic Predicates and Policies                                              #
################################################################################

class DynamicPredicate(DerivedPredicate):
    """Abstact class for dynamic predicates.
    The behavior of a dynamic predicate changes each time its internal property
    named 'predicate' is reassigned."""
    ### init : unit -> unit
    def __init__(self):
        self._predicate = drop
        self._predicate.set_parent(self)
        super(DerivedPredicate,self).__init__()
        
    @property
    def predicate(self):
        return self._predicate
        
    @predicate.setter
    def predicate(self, predicate):
        self._predicate.detach(self)
        self._predicate = predicate
        self._predicate.attach(self)
        if self.network:
            self._predicate.set_network(self.network)
        self.changed()

    def attach(self,parent):
        self._predicate.attach(self)
        self.set_parent(parent)
        super(DynamicPredicate,self).attach(parent)

    def detach(self,parent):
        self._predicate.detach(self)
        self.unset_parent(parent)
        super(DynamicPredicate,self).detach(parent)

    def __repr__(self):
        return "[DynamicPredicate]\n%s" % repr(self.predicate)


class ingress_network(DynamicPredicate):
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
            self.predicate = union([match(switch=l.switch,
                                       inport=l.port_no) 
                                 for l in self.egresses])
            self.changed()

    def attach(self,parent):
        self.set_parent(parent)
        
    def detach(self,parent):
        self.unset_parent(parent)
            
    def __repr__(self):
        return "ingress_network"

        
class egress_network(DynamicPredicate):
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
            self.predicate = union([match(switch=l.switch,
                                       outport=l.port_no) 
                                 for l in self.egresses])
            self.changed()

    def attach(self,parent):
        self.set_parent(parent)

    def detach(self,parent):
        self.unset_parent(parent)
 
    def __repr__(self):
        return "egress_network"


class DynamicPolicy(DerivedPolicy):
    """Abstact class for dynamic policies.
    The behavior of a dynamic policy changes each time its internal property
    named 'policy' is reassigned."""
    ### init : unit -> unit
    def __init__(self):
        self._policy = drop
        self._policy.set_parent(self)
        super(DerivedPolicy,self).__init__()
        
    @property
    def policy(self):
        return self._policy
        
    @policy.setter
    def policy(self, policy):
        self._policy.detach(self)
        self._policy = policy
        self._policy.attach(self)
        if self.network:
            self._policy.set_network(self.network)
        self.changed()

    def attach(self,parent):
        self._policy.attach(self)
        self.set_parent(parent)
        super(DynamicPolicy,self).attach(parent)

    def detach(self,parent):
        self._policy.detach(self)
        self.unset_parent(parent)
        super(DynamicPolicy,self).detach(parent)

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
                    match(switch=switch)[
                        parallel(map(xfwd,attrs['ports'].keys()))]
                    for switch,attrs in self.mst.nodes(data=True)])

    def __repr__(self):
        try: 
            return "flood on:\n%s" % self.mst
        except:
            return "flood"


################################################################################
# Query Policies                                                               #
################################################################################

class FwdBucket(Policy):
    """Abstract class representing a data structure 
    into which packets (conceptually) go and with which callbacks can register.
    """
    ### init : unit -> unit
    def __init__(self):
        self.callbacks = []
        super(FwdBucket,self).__init__()

    def eval(self, packet):
        for callback in self.callbacks:
            callback(packet)
        return set()

    ### register_callback : (Packet -> X) -> unit 
    def register_callback(self, fn):
        self.callbacks.append(fn)


class packets(Policy):
    """Effectively a FwdBucket which calls back all registered routines on each 
    packet evaluated.
    A positive integer limit will cause callback to cease after limit packets of
    a given group have been seen.  group_by defines the set of headers used for 
    grouping - two packets are in the same group if they match on all headers in the
    group_by.  If no group_by is specified, the default is to match on all available
    headers."""
    class PredicateWrappedFwdBucket(Predicate):
        def __init__(self,limit=None,group_by=[]):
            self.limit = limit
            self.group_by = group_by
            self.seen = {}
            self.fwd_bucket = FwdBucket()
            self.register_callback = self.fwd_bucket.register_callback
            super(packets.PredicateWrappedFwdBucket,self).__init__()

        def eval(self,packet):
            if not self.limit is None:
                if self.group_by:    # MATCH ON PROVIDED GROUP_BY
                    pred = match([(field,packet[field]) for field in self.group_by])
                else:              # OTHERWISE, MATCH ON ALL AVAILABLE GROUP_BY
                    pred = match([(field,packet[field]) 
                                  for field in packet.available_group_by()])
                # INCREMENT THE NUMBER OF TIMES MATCHING PACKET SEEN
                try:
                    self.seen[pred] += 1
                except KeyError:
                    self.seen[pred] = 1

                if self.seen[pred] > self.limit:
                    return False
            self.fwd_bucket.eval(packet)
            return True
        
    def __init__(self,limit=None,group_by=[]):
        self.limit = limit
        self.seen = {}
        self.group_by = group_by
        self.pwfb = self.PredicateWrappedFwdBucket(limit,group_by)
        self.register_callback = self.pwfb.register_callback
        self.predicate = all_packets
        self.predicate.set_parent(self)
        super(packets,self).__init__()

    def set_network(self, network):
        super(packets,self).set_network(network)
        self.pwfb.set_network(network)
        self.predicate.set_network(network)

    def attach(self,parent):
        self.set_parent(parent)
        super(packets,self).attach(parent)

    def detach(self,parent):
        self.unset_parent(parent)
        super(packets,self).detach(parent)

    def eval(self,pkt):
        """Don't look any more such packets"""
        if self.predicate.eval(pkt) and not self.pwfb.eval(pkt):
            val = {h : pkt[h] for h in self.group_by}
            self.predicate = ~match(val) & self.predicate
            self.predicate.set_network(self.network)
            self.predicate.set_parent(self)
            self.changed()
        return set()

    def track_eval(self,pkt):
        """Don't look any more such packets"""
        (result,trace) = self.predicate.track_eval(pkt)
        eval_trace = EvalTrace(self,trace)
        if result:
            (result,trace) = self.pwfb.track_eval(pkt)
            eval_trace.add_trace(trace)
            if not result:
                val = {h : pkt[h] for h in self.group_by}
                self.predicate = ~match(val) & self.predicate
                self.predicate.set_network(self.network)
                self.predicate.set_parent(self)
                self.changed()
        return (set(),eval_trace)
        

class AggregateFwdBucket(FwdBucket):
    """An abstract FwdBucket which calls back all registered routines every interval
    seconds (can take positive fractional values) with an aggregate value/dict.
    If group_by is empty, registered routines are called back with a single aggregate
    value.  Otherwise, group_by defines the set of headers used to group counts which
    are then returned as a dictionary."""
    ### init : int -> List String
    def __init__(self, interval, group_by=[]):
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
        FwdBucket.__init__(self)

    def report_count(self):
        while(True):
            FwdBucket.eval(self, self.aggregate)
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

    def eval(self, packet):
        self.update_aggregate(packet)
        return set()


class counts(AggregateFwdBucket):
    """AggregateFwdBucket that calls back with aggregate count of packets."""
    def aggregator(self,aggregate,pkt):
        return aggregate + 1


class sizes(AggregateFwdBucket):
    """AggregateFwdBucket that calls back with aggregate bytesize of packets."""
    def aggregator(self,aggregate,pkt):
        return aggregate + pkt['header_len'] + pkt['payload_len']
