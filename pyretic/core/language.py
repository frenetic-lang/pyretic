
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
        return (self.eval(packet),[self])

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

    
################################################################################
# Predicates                                                                   #
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

    ### eval : Packet -> bool
    def __eval__(self, packet):
        raise NotImplementedError


################################################################################
# Primitive Predicates                                                         #
################################################################################

class PrimitivePredicate(Predicate):
    """Abstract class for primitive predicates."""
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

        
class ingress_network(PrimitivePredicate):
    def __init__(self):
        self.egresses = None
        super(ingress_network,self).__init__()

    def set_network(self, network):
        super(ingress_network,self).set_network(network)
        updated_egresses = network.topology.egress_locations()
        if not self.egresses == updated_egresses:
            self.egresses = updated_egresses
            self.changed()

    def attach(self,parent):
        self.set_parent(parent)

    def detach(self,parent):
        self.unset_parent(parent)
    
    def eval(self, packet):
        switch = packet["switch"]
        port_no = packet["inport"]
        return Location(switch,port_no) in self.egresses

    def __repr__(self):
        return "ingress_network"

        
class egress_network(PrimitivePredicate):
    def __init__(self):
        self.egresses = None
        super(egress_network,self).__init__()
    
    def set_network(self, network):
        super(egress_network,self).set_network(network)
        updated_egresses = network.topology.egress_locations()
        if not self.egresses == updated_egresses:
            self.egresses = updated_egresses
            self.changed()

    def attach(self,parent):
        self.set_parent(parent)

    def detach(self,parent):
        self.unset_parent(parent)
 
    def eval(self, packet):
        switch = packet["switch"]
        try:
            port_no = packet["outport"]
        except:
            return False
        return Location(switch,port_no) in self.egresses

    def __repr__(self):
        return "egress_network"

        
class match(PrimitivePredicate):
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
    """Abstract class for predicate combinators."""
    pass


class negate(CombinatorPredicate):
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
        (result,traversed) = self.predicate.track_eval(packet)
        return (not result,[self,traversed])

    def __repr__(self):
        return "negate:\n%s" % util.repr_plus([self.predicate])

        
class union(CombinatorPredicate):
    """A predicate representing the union of a list of predicates."""
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
        traversed = list()
        for predicate in self.predicates:
            (result,ptraversed) = predicate.track_eval(packet)
            traversed.append(ptraversed)
            if result:
                return (True,[self,traversed])
        return (False,[self,traversed])

    def __repr__(self):
        return "union:\n%s" % util.repr_plus(self.predicates)

        
class intersect(CombinatorPredicate):
    """A predicate representing the intersection of a list of predicates."""
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
        traversed = list()
        for predicate in self.predicates:
            (result,ptraversed) = predicate.track_eval(packet)
            traversed.append(ptraversed)
            if not result:
                return (False,[self,traversed])
        return (True,[self,traversed])

    def __repr__(self):
        return "intersect:\n%s" % util.repr_plus(self.predicates)


################################################################################
# Derived Predicates                                                           #
################################################################################

class DerivedPredicate(Predicate):
    """Abstract class for predicates derived from primitive predicates and combinators."""
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
        (result,traversed) = self.predicate.track_eval(packet)
        return (result,[self,traversed])


class difference(DerivedPredicate):
    """A predicate representing the difference of two predicates."""
    ### init : Predicate -> Predicate -> unit
    def __init__(self,pred1,pred2):
        self.pred1 = pred1
        self.pred2 = pred1
        self.pred1.set_parent(self)
        self.pred2.set_parent(self)
        super(difference,self).__init__((~pred2) & pred1)
        
    ### repr : unit -> String
    def __repr__(self):
        return "difference:\n%s" % util.repr_plus([self.pred1,
                                                   self.pred2])

        
################################################################################
# Policies                                                                     #
################################################################################

class Policy(NetworkEvaluated):
    """Top-level abstract description of a policy."""
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
    """Top-level abstract description of a primitive static policy."""
        

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

        
class flood(PrimitivePolicy):
    """The policy that floods packets on a minimum spanning tree"""
    def __init__(self):
        self.egresses = None
        self.mst = None
        super(flood,self).__init__()

    def set_network(self, network):
        changed = False
        super(flood,self).set_network(network) 
        if not network is None:
            updated_egresses = network.topology.egress_locations()
            if not self.egresses == updated_egresses:
                self.egresses = updated_egresses
                changed = True
            updated_mst = Topology.minimum_spanning_tree(network.topology)
            if not self.mst is None:
                if self.mst != updated_mst:
                    self.mst = updated_mst
                    changed = True
            else:
                self.mst = updated_mst
                changed = True
        if changed:
            self.changed()

    def attach(self,parent):
        self.set_parent(parent)

    def detach(self,parent):
        self.unset_parent(parent)
        
    def eval(self, packet):
        if self.network is None:
            return set()
        
        switch = packet["switch"]
        inport = packet["inport"]
        if switch in self.mst:
            port_nos = {loc.port_no 
                        for loc in self.egresses if loc.switch == switch}
            for sw in self.mst.neighbors(switch):
                port_no = self.mst[switch][sw][switch]
                port_nos.add(port_no)
            try:
                if packet["outport"] == -1:
                    packets = {packet.modify(outport=port_no) 
                               for port_no in port_nos 
                               if port_no != inport}
                else:
                    packets = {packet.push(outport=port_no) 
                               for port_no in port_nos 
                               if port_no != inport}
            except:
                packets = {packet.push(outport=port_no) 
                           for port_no in port_nos 
                           if port_no != inport}
            return packets
        else:
            return set()

    def __repr__(self):
        try: 
            return "flood on:\n%s" % self.mst
        except:
            return "flood"

        
class push(PrimitivePolicy):
    """push(field=value) pushes value onto header field stack"""
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
    """pop('field') pops value off field stack"""
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
    the field2 stack unto the field1 stack"""
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
    pass


class remove(CombinatorPolicy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy, predicate):
        self.policy = policy
        self.predicate = predicate
        self.policy.set_parent(self)
        self.predicate.set_parent(self)
        super(remove,self).__init__()

    def set_network(self, network):
        super(remove,self).set_network(network)
        self.policy.set_network(network) 
        self.predicate.set_network(network)

    def attach(self,parent):
        self.predicate.attach(self)
        self.policy.attach(self)
        super(remove,self).attach(parent)

    def detach(self,parent):
        self.predicate.detach(self)
        self.policy.detach(self)
        super(remove,self).detach(parent)

    def eval(self, packet):
        if not self.predicate.eval(packet):
            return self.policy.eval(packet)
        else:
            return set()

    def track_eval(self, packet):
        (result1,traversed1) = self.predicate.track_eval(packet)
        if not result1:
            (result2,traversed2) = self.policy.track_eval(packet)
            return (result2,[self,traversed1,traversed2])
        else:
            return (set(),[self,traversed1])

    def __repr__(self):
        return "remove:\n%s" % util.repr_plus([self.predicate, self.policy])

    
class restrict(CombinatorPolicy):
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
        (result1,traversed1) = self.predicate.track_eval(packet)
        if result1:
            (result2,traversed2) = self.policy.track_eval(packet)
            return (result2,[self,traversed1,traversed2])
        else:
            return (set(),[self,traversed1])

    def __repr__(self):
        return "restrict:\n%s" % util.repr_plus([self.predicate,
                                                 self.policy])

                    
class parallel(CombinatorPolicy):
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
        traversed = list()
        output = set()
        for policy in self.policies:
            (p_output,p_traversed) = policy.track_eval(packet)
            traversed.append(p_traversed)
            output |= p_output
        return (output,[self,traversed])
    
    def __repr__(self):
        return "parallel:\n%s" % util.repr_plus(self.policies)
        

class sequential(CombinatorPolicy):
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
        traversed = list()
        input_set = {packet}
        for policy in self.policies:
            output_set = set()
            for packet in input_set:
                (p_output_set,p_traversed) = policy.track_eval(packet)
                traversed.append(p_traversed)
                output_set |= p_output_set
            input_set = output_set
        return (output_set,[self,traversed])
    
    def __repr__(self):
        return "sequential:\n%s" % util.repr_plus(self.policies)
  

################################################################################
# Derived Policies                                                             #
################################################################################
        
class DerivedPolicy(Policy):
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
        (result,traversed) = self.policy.track_eval(packet)
        return (result,[self,traversed])


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
       super(modify,self).__init__()

    def eval(self, packet):
        packet = packet.modifymany(self.map)
        return {packet}

    def __repr__(self):
        return "modify:\n%s" % util.repr_plus(self.map.items())

        
class move(Policy):
    """move(field1='field2') is equivalent to 
    copy(field1='field2') >> pop('field2')"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)
        super(move,self).__init__()
  
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
        return {packet}

    def __repr__(self):
        return "move:\n%s" % util.repr_plus(self.map.items())


class fwd(DerivedPolicy):
    ### init : int -> unit
    def __init__(self, outport):
        self.outport = outport
        super(fwd,self).__init__(if_(match(outport=-1),pop('outport')) 
                                 >> push(outport=self.outport))

    def __repr__(self):
        return "fwd %s" % self.outport
    

class if_(DerivedPolicy):
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
# Query Policies                                                               #
################################################################################

class FwdBucket(Policy):
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
    class PredicateWrappedFwdBucket(Predicate):
        def __init__(self,limit=None,fields=[]):
            self.limit = limit
            self.fields = fields
            self.seen = {}
            self.fwd_bucket = FwdBucket()
            self.register_callback = self.fwd_bucket.register_callback
            super(packets.PredicateWrappedFwdBucket,self).__init__()

        def eval(self,packet):
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
                    return False
            self.fwd_bucket.eval(packet)
            return True
        
    def __init__(self,limit=None,fields=[]):
        self.limit = limit
        self.seen = {}
        self.fields = fields
        self.pwfb = self.PredicateWrappedFwdBucket(limit,fields)
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
            val = {h : pkt[h] for h in self.fields}
            self.predicate = ~match(val) & self.predicate
            self.predicate.set_network(self.network)
            self.predicate.set_parent(self)
            self.changed()
        return set()

    def track_eval(self,pkt):
        """Don't look any more such packets"""
        (result,traversed) = self.predicate.track_eval(pkt)
        if result:
            (result,traversed2) = self.pwfb.track_eval(pkt)
            traversed += traversed2
            if not result:
                val = {h : pkt[h] for h in self.fields}
                self.predicate = ~match(val) & self.predicate
                self.predicate.set_network(self.network)
                self.predicate.set_parent(self)
                self.changed()
        return (set(),[self,traversed])
        

class AggregateFwdBucket(FwdBucket):
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
    def aggregator(self,aggregate,pkt):
        return aggregate + 1


class sizes(AggregateFwdBucket):
    def aggregator(self,aggregate,pkt):
        return aggregate + pkt['header_len'] + pkt['payload_len']


################################################################################
# Dynamic Policies                                                             #
################################################################################

class DynamicPolicy(DerivedPolicy):
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
