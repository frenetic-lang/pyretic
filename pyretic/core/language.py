
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

basic_headers = ["srcmac", "dstmac", "srcip", "dstip", "tos", "srcport", "dstport",
                 "ethtype", "protocol"]
tagging_headers = ["vlan_id", "vlan_pcp"]
native_headers = basic_headers + tagging_headers
location_headers = ["switch", "inport", "outport"]
compilable_headers = native_headers + location_headers
content_headers = [ "raw", "header_len", "payload_len"]

################################################################################
# Policy Language                                                              #
################################################################################

class Policy(object):
    """Top-level abstract class for policies.
    All Pyretic policies evaluate on a single packet and return a set of packets.
    """
    def __init__(self):
        self._network = None
        self._classifier = None
        
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
        
    ### rshift : Policy -> Policy
    def __rshift__(self, pol):
        if isinstance(pol,sequential):
            return sequential([self] + pol.policies)
        else:
            return sequential([self, pol])

    ### eq : Policy -> bool
    def __eq__(self,pol):
        return id(self) == id(pol)

    ### eval : Packet -> Set Packet
    def __eval__(self, pkt):
        raise NotImplementedError

    def track_eval(self, pkt, dry):
        return (self.eval(pkt), EvalTrace(self))

    def compile(self):
        raise NotImplementedError

    def name(self):
        return self.__class__.__name__

    ### repr : unit -> String
    def __repr__(self):
        return "%s : %d" % (self.name(),id(self))


class Filter(Policy):
    """Abstact class for filter policies."""
    ### or : Filter -> Filter
    def __or__(self, pol):
        if isinstance(pol,Filter):
            return union((self + pol).policies)
        else:
            raise TypeError

    ### and : Filter -> Filter
    def __and__(self, pol):
        if isinstance(pol,Filter):
            return intersection((self >> pol).policies)
        else:
            raise TypeError

    ### sub : Filter -> Filter
    def __sub__(self, pol):
        if isinstance(pol,Filter):
            return difference([self, pol])
        else:
            raise TypeError
    
    ### invert : unit -> Filter
    def __invert__(self):
        return negate([self])

    
class Rule(object):

    # Matches m should be of the match class.  Actions acts should be a list of
    # either modify, identity, or drop policies.
    def __init__(self,m,acts):
        self.match = m
        self.actions = acts

    def __str__(self):
        return str(self.match) + '\tactions:\t' + str(self.actions)

    def __repr__(self):
        return str(self)


class Classifier(object):
    def __init__(self):
        self.rules = []

    def __len__(self):
        return len(self.rules)

    def __str__(self):
        return '\n'.join(map(str,self.rules))

    def __add__(self,c2):
        c1 = self
        if c2 is None:
            return None
        c = Classifier()
        # TODO (cole): make classifiers iterable
        for r1 in c1.rules:
            for r2 in c2.rules:
                intersection = r1.match.intersect(r2.match)
                if intersection != none:
                    # TODO (josh) logic for detecting when sets of actions can't be combined
                    # e.g., [modify(dstip='10.0.0.1'),fwd(1)] + [modify(srcip='10.0.0.2'),fwd(2)]
                    actions = r1.actions + r2.actions
                    actions = filter(lambda a: a != none,actions)
                    if len(actions) == 0:
                        actions = [none]
                    c.rules.append(Rule(intersection, actions))
        for r1 in c1.rules:
            c.rules.append(r1)
        for r2 in c2.rules:
            c.rules.append(r2)
        return c.optimize()

    def __rshift__(self,c2):

        # Helper function: commute the match from a right-hand-side rule to the
        # left.
        # Returns: a new match for r1 >> r2.
        def _specialize(r1, r2):
            assert(len(r1.actions) == 1)
            a1 = r1.actions[0]
            a1 = a1.simplify()
            if a1 == identity:
                return r1.match.intersect(r2.match)
            elif a1 == none:  # if we drop, then later matches don't matter
                return r1.match
            elif a1 == Controller:
                return r1.match
            elif isinstance(a1, modify):
                new_match_dict = {}
                for f, v in r2.match.map.iteritems():
                    if f in a1.map and a1.map[f] == v:
                        continue
                    elif f in a1.map and a1.map[f] != v:
                        return none
                    else:
                        new_match_dict[f] = v
                return match(**new_match_dict)
            else:
                # TODO (cole) use compile error.
                raise TypeError

        # Helper function: sequentially compose actions.  a1 must be a single
        # action.
        def _sequence_actions(as1, as2):
            assert(len(as1) == 1)
            a1 = as1[0]
            new_actions = []
            if a1 == none:
                return [none]
            elif a1 == identity:
                return as2
            elif a1 == Controller:
                return as1 + as2
            elif isinstance(a1, modify):
                for a2 in as2:
                    new_a1 = modify(**a1.map.copy())
                    if a2 == none:
                        new_actions.append(none)
                    elif a2 == Controller:
                        new_actions.append(a2)
                    elif a2 == identity:
                        new_actions.append(new_a1)
                    elif isinstance(a2, modify):
                        new_a1.map.update(a2.map)
                        new_actions.append(new_a1)
                    else:
                        raise TypeError
                return new_actions
            else:
                raise TypeError

        def _compile_rule_rule(r1, r2):
            assert(len(r1.actions) == 1)
            m = _specialize(r1, r2)
            alist = _sequence_actions(r1.actions, r2.actions)
            return Rule(m, alist)

        def _compile_tinyrule_classifier(r1, c2):
            assert(len(r1.actions) == 1)
            rules = [_compile_rule_rule(r1, r2) for r2 in c2.rules]
            c = Classifier()
            c.rules = filter(lambda r: r.match != none, rules)
            return c

        def _compile_rule_classifier(r1, c2):
            rules = [Rule(r1.match, [act]) for act in r1.actions]
            cs = [_compile_tinyrule_classifier(r, c2) for r in rules]
            return reduce(lambda acc, c: acc + c, cs)

        c = Classifier()
        for r1 in self.rules:
            c.rules = c.rules + _compile_rule_classifier(r1, c2).rules
        c.rules.append(Rule(match(), [drop]))
        return c.optimize()

    def optimize(self):
        return self.remove_shadowed_cover_single()

    def remove_shadowed_exact_single(self):
        # Eliminate every rule exactly matched by some higher priority rule
        opt_c = Classifier()
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or 
                          new_r.match == r.match, 
                          opt_c.rules, 
                          False):
                opt_c.rules.append(r)
        return opt_c

    def remove_shadowed_cover_single(self):
        # Eliminate every rule completely covered by some higher priority rule
        opt_c = Classifier()
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or 
                          new_r.match.covers(r.match), 
                          opt_c.rules, 
                          False):
                opt_c.rules.append(r)
        return opt_c


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
    def simplify(self):
        return self

@singleton
class identity(PrimitivePolicy,Filter):
    """The identity policy"""
    def eval(self, pkt):
        return {pkt}

    def compile(self):
        r = Rule(match(),[modify()])
        self._classifier = Classifier()
        self._classifier.rules.append(r)
        return self._classifier

    def __repr__(self):
        return "identity"
passthrough = identity   # Imperative alias
true = identity          # Logic alias
all_packets = identity   # Matching alias

        
@singleton
class none(PrimitivePolicy,Filter):
    """The policy that drops a pkt"""
    def eval(self, pkt):
        return set()

    def compile(self):
        r = Rule(match(),[drop])
        self._classifier = Classifier()
        self._classifier.rules.append(r)
        return self._classifier

    def __repr__(self):
        return "none"
drop = none              # Imperative alias
false = none             # Logic alias
no_packets = identity    # Matching alias


class match(PrimitivePolicy,Filter):
    """A set of field matches on a packet (one per field)."""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = util.frozendict(dict(*args, **kwargs))
        super(match,self).__init__()

    def intersect(self, pol):
        if not isinstance(pol,match):
            raise TypeError
        fs1 = set(self.map.keys())
        fs2 = set(pol.map.keys())
        shared = fs1 & fs2
        for f in shared:
            if self.map[f] != pol.map[f]:
                return none
        d = self.map.update(pol.map)
        return match(**d)

    def __and__(self,pol):
        if isinstance(pol,match):
            return self.intersect(pol)
        else:
            return super(match,self).__and__(pol)

    ### hash : unit -> int
    def __hash__(self):
        return hash(self.map)
    
    ### eq : PrimitivePolicy -> bool
    def __eq__(self, other):
        try:
            return self.map == other.map
        except:
            return False

    def covers(self,other):
        # if self is specific on any field that other lacks
        if set(self.map.keys()) - set(other.map.keys()):
            return False
        for (f,v) in self.map.items():
            if v != other.map[f]:
                return False
        return True

    def eval(self, pkt):
        for field, pattern in self.map.iteritems():
            try:
                v = pkt[field]
                if pattern is None or pattern != v:
                    return set()
            except:
                if pattern is not None:
                    return set()
        return {pkt}

    def compile(self):
        r1 = Rule(self,[modify()])
        r2 = Rule(match(),[drop])
        self._classifier = Classifier()
        self._classifier.rules.append(r1)
        self._classifier.rules.append(r2)
        return self._classifier

    def __repr__(self):
        return "match: %s" % ' '.join(map(str,self.map.items()))

    def __eq__(self, other):
        if isinstance(other, match):
            return self.map == other.map
        else:
            return False

    def simplify(self):
        if len(self.map):
            return self
        else:
            return identity

        
@singleton
class Controller(PrimitivePolicy):
    def __repr__(self):
        return "Controller"


class modify(PrimitivePolicy):
    """modify(field=value)"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        self.map = dict(*args, **kwargs)
        self.has_virtual_headers = not \
            reduce(lambda acc, f: 
                   acc and (f in compilable_headers),
                   self.map.keys(),
                   True)
        super(modify,self).__init__()

    def eval(self, pkt):
        return {pkt.modifymany(self.map)}

    def compile(self):
        if self.has_virtual_headers:
            r = Rule(match(),[Controller])
        else:
            r = Rule(match(),[self])
        self._classifier = Classifier()
        self._classifier.rules.append(r)
        return self._classifier

    def __repr__(self):
        return "modify: %s" % ' '.join(map(str,self.map.items()))

    def __eq__(self, other):
        if isinstance(other, modify):
            return self.map == other.map
        else:
            return False

    def simplify(self):
        if len(self.map):
            return self
        else:
            return identity
    

class FwdBucket(PrimitivePolicy):
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

    def compile(self):
        r = Rule(match(),[Controller])
        self._classifier = Classifier()
        self._classifier.rules.append(r)
        return self._classifier

    ### register_callback : (Packet -> X) -> unit 
    def register_callback(self, fn):
        self.callbacks.append(fn)


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


class negate(CombinatorPolicy,Filter):
    def eval(self, pkt):
        if self.policies[0].eval(pkt):
            return set()
        else:
            return {pkt}

    def track_eval(self, pkt, dry):
        eval_trace = EvalTrace(self)
        (results,trace) = self.policies[0].track_eval(pkt,dry)
        eval_trace.add_trace(trace)
        if results:
            return (set(),eval_trace)
        else:
            return ({pkt},eval_trace)

    def compile(self):
        inner_classifier = self.policies[0].compile()
        self._classifier = Classifier()
        for r in inner_classifier.rules:
            action = r.actions[0].simplify()
            if action == identity:
                self._classifier.rules.append(Rule(r.match,[drop]))
            elif action == drop:
                self._classifier.rules.append(Rule(r.match,[modify()]))
            else:
                raise TypeError  # TODO MAKE A CompileError TYPE
        return self._classifier 


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

    def compile(self):
        if len(self.policies) == 0:  # EMPTY PARALLEL IS A DROP
            return drop.compile()
        classifiers = map(lambda p: p.compile(), self.policies)
        self._classifier = reduce(lambda acc, c: acc + c, classifiers)
        return self._classifier
            

class union(parallel,Filter):
    pass


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

    def compile(self):
        assert(len(self.policies) > 0)
        classifiers = map(lambda p: p.compile(),self.policies)
        for c in classifiers:
            assert(c is not None)
        return reduce(lambda acc, c: acc >> c, classifiers)
  

class intersection(sequential,Filter):
    pass


class dropped_by(CombinatorPolicy,Filter):
    def __init__(self, dropper):
        super(dropped_by,self).__init__([dropper])

    def eval(self, pkt):
        if self.policies[0].eval(pkt):
            return set()
        else:
            return {pkt}

    def track_eval(self, pkt, dry):
        eval_trace = EvalTrace(self)
        (results,trace) = self.policies[0].track_eval(pkt,dry)
        eval_trace.add_trace(trace)
        if results:
            return (set(),eval_trace)
        else:
            return ({pkt},eval_trace)

    def compile(self):
        r = Rule(match(),[Controller])
        self._classifier = Classifier()
        self._classifier.rules.append(r)
        return self._classifier


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
        return self.policy.eval(pkt)

    def track_eval(self, pkt, dry):
        eval_trace = EvalTrace(self)
        (results,trace) = self.policy.track_eval(pkt,dry)
        eval_trace.add_trace(trace)
        return (results,eval_trace)

    def compile(self):
        self._classifier = self.policy.compile()
        return self._classifier

    def __repr__(self):
        return "[DerivedPolicy]\n%s" % repr(self.policy)


class difference(DerivedPolicy,Filter):
    def __init__(self, f1, f2):
       self.f1 = f1
       self.f2 = f2
       super(difference,self).__init__(~f2 & f1)

    def __repr__(self):
        return "difference:\n%s" % util.repr_plus([self.f1,self.f2])


class match_modify(DerivedPolicy):
    def __init__(self, field, match_val, mod_val):
        self.field = field
        self.match_val = match_val
        self.mod_val = mod_val
        super(match_modify,self).__init__(match(field=match_val) >>
                                          modify(field=mod_val))
        
class if_(DerivedPolicy):
    """if predicate holds, t_branch, otherwise f_branch."""
    ### init : Policy -> Policy -> Policy -> unit
    def __init__(self, pred, t_branch, f_branch=passthrough):
        self.pred = pred
        self.t_branch = t_branch
        self.f_branch = f_branch
        super(if_,self).__init__((self.pred >> self.t_branch) + 
                                 ((~self.pred) >> self.f_branch))

    def eval(self, pkt):
        if self.pred.eval(pkt):
            return self.t_branch.eval(pkt)
        else:
            return self.f_branch.eval(pkt)

    def track_eval(self, pkt, dry):
        eval_trace = EvalTrace(self)
        (results,trace) = self.pred.track_eval(pkt,dry)
        eval_trace.add_trace(trace)
        if results:
            (results,trace) = self.t_branch.track_eval(pkt,dry)
        else:
            (results,trace) = self.f_branch.track_eval(pkt,dry)
        eval_trace.add_trace(trace)
        return (results,eval_trace)

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
        super(fwd,self).__init__(modify(outport=self.outport))

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


class DynamicFilter(DynamicPolicy,Filter):
    pass

        
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


class ingress_network(DynamicFilter):
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

        
class egress_network(DynamicFilter):
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
