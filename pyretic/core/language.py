
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
# author: Cole Schlesinger (cschlesi@cs.princeton.edu)                         #
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
from ipaddr import IPv4Network
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
    def __rshift__(self, other):
        if isinstance(other,sequential):
            return sequential([self] + other.policies)
        else:
            return sequential([self, other])

    ### eq : Policy -> bool
    def __eq__(self, other):
        '''Syntactic equality.'''
        raise NotImplementedError

    ### ne : Policy -> bool
    def __ne__(self,other):
        '''Syntactic inequality.'''
        return not (self == other)

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
            return union([self, pol])
        else:
            raise TypeError

    ### and : Filter -> Filter
    def __and__(self, pol):
        if isinstance(pol,Filter):
            return intersection([self, pol])
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


def _intersect_ip(ipfx, opfx):
    most_specific = None
    if (IPv4Network(ipfx) in IPv4Network(opfx)):
        most_specific = ipfx
    elif (IPv4Network(opfx) in IPv4Network(ipfx)): 
        most_specific = opfx
    return most_specific


class match(Filter):
    """A set of field matches on a packet (one per field)."""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
        self.map = util.frozendict(dict(*args, **kwargs))
        super(match,self).__init__()

    def __eq__(self, other):
        return ( (isinstance(other, match) and self.map == other.map)
            or (other == true and len(self.map) == 0) )

    def intersect(self, pol):
        if pol == true:
            return self
        elif pol == false:
            return false
        elif not isinstance(pol,match):
            raise TypeError
        fs1 = set(self.map.keys())
        fs2 = set(pol.map.keys())
        shared = fs1 & fs2
        most_specific_src = None
        most_specific_dst = None

        for f in shared:
            if (f=='srcip'):
                most_specific_src = _intersect_ip(self.map[f], pol.map[f])
                if most_specific_src is None:
                    return None
            elif (f=='dstip'):
                most_specific_dst = _intersect_ip(self.map[f], pol.map[f])
                if most_specific_dst is None:
                    return None
            elif (self.map[f] != pol.map[f]):
                return none

        d = self.map.update(pol.map)

        if most_specific_src is not None:
            d = d.update({'srcip' : most_specific_src})
        if most_specific_dst is not None:
            d = d.update({'dstip' : most_specific_dst})

        return match(**d)

    def __and__(self,pol):
        if isinstance(pol,match):
            return self.intersect(pol)
        else:
            return super(match,self).__and__(pol)

    ### hash : unit -> int
    def __hash__(self):
        return hash(self.map)

    def covers(self,other):
        # Return true if self matches every packet that other matches (and maybe more).
        # eg. if other is specific on any field that self lacks.
        if other == true and len(self.map.keys()) > 0:
            return False
        elif other == true:
            return True
        elif other == false:
            return True
        if set(self.map.keys()) - set(other.map.keys()):
            return False
        for (f,v) in self.map.items():
            if (f=='srcip' or f=='dstip'):
                if(IPv4Network(v) != IPv4Network(other.map[f])):
                    if(not IPv4Network(other.map[f]) in IPv4Network(v)):
                        return False
            elif v != other.map[f]:
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
        r1 = Rule(self,[identity])
        r2 = Rule(true,[drop])
        return Classifier([r1, r2])

    def __repr__(self):
        return "match: %s" % ' '.join(map(str,self.map.items()))

@singleton
class identity(Filter):
    def __repr__(self):
        return "identity"

    def compile(self):
        return Classifier([Rule(identity, [identity])])

    def intersect(self, other):
        return other

    def covers(self, other):
        return True

    def eval(self, pkt):
        return {pkt}

    def __eq__(self, other):
        return ( id(self) == id(other)
            or ( isinstance(other, match) and len(other.map) == 0) )

passthrough = identity   # Imperative alias
true = identity          # Logic alias
all_packets = identity   # Matching alias


@singleton
class drop(Filter):
    def __repr__(self):
        return "drop"

    def compile(self):
        return Classifier([Rule(identity, [drop])])

    def intersect(self, other):
        return self

    def covers(self, other):
        return False

    def eval(self, pkt):
        return set()

    def __eq__(self, other):
        return id(self) == id(other)

none = drop
false = drop             # Logic alias
no_packets = drop        # Matching alias


class modify(Policy):
    """modify(field=value)"""
    ### init : List (String * FieldVal) -> List KeywordArg -> unit
    def __init__(self, *args, **kwargs):
        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
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
            r = Rule(identity,[Controller])
        else:
            r = Rule(identity,[self])
        return Classifier([r])

    def __repr__(self):
        return "modify: %s" % ' '.join(map(str,self.map.items()))

    def __eq__(self, other):
        return ( isinstance(other, modify)
           and (self.map == other.map) )

@singleton
class Controller(Policy):
    def __repr__(self):
        return "Controller"
    
    def eval(self, pkt):
        return set()
    
    def compile(self):
        r = Rule(identity, [Controller])
        self._classifier = Classifier([r])
        return self._classifier

    def __eq__(self, other):
        return id(self) == id(other)

# FIXME: Srinivas =).
class Query(Policy):
    """Abstract class representing a data structure
    into which packets (conceptually) go and with which callbacks can register.
    """
    ### init : unit -> unit
    def __init__(self):
        self.callbacks = []
        super(Query,self).__init__()
        
    def __repr__(self):
        return "Query"

    def eval(self, pkt):
        for callback in self.callbacks:
            callback(pkt)
        return set()

    def compile(self):
        raise NotImplementedError

    ### register_callback : (Packet -> X) -> unit
    def register_callback(self, fn):
        self.callbacks.append(fn)


class FwdBucket(Query):
    """Class for registering callbacks on individual packets sent to
    the controller.
    """
    def compile(self):
        r = Rule(identity,[Controller])
        return Classifier([r])
    
    def __repr__(self):
        return "FwdBucket"

    def __eq__(self, other):
        # TODO: if buckets eventually have names, equality should
        # be on names.
        return isinstance(other, FwdBucket)


class CountBucket(Query):
    """Class for registering callbacks on counts of packets sent to
    the controller.
    """
    def __init__(self):
        super(CountBucket, self).__init__()
        self.matches = set([])
        
    def __repr__(self):
        return "CountBucket"

    def compile(self):
        r = Rule(identity,[self])
        return Classifier([r])
        
    def add_match(self, m):
        """Add a match m to list of classifier rules to be queried for
        counts."""
        assert(isinstance(m, match))
        if not m in self.matches:
            self.matches.add(m)

    def __eq__(self, other):
        # TODO: if buckets eventually have names, equality should
        # be on names.
        return isinstance(other, CountBucket)

################################################################################
# Combinator Policies                                                          #
################################################################################

class CombinatorPolicy(Policy):
    """Abstract class for policy combinators.
    A policy combinator takes one or more policies and produces a new
    policy with the specified semantics."""
    ### init : List Policy -> unit
    def __init__(self, policies=[]):
        self.policies = list(policies)
        super(CombinatorPolicy,self).__init__()

    def set_network(self, network):
        super(CombinatorPolicy,self).set_network(network)
        for policy in self.policies:
            policy.set_network(network)

    def __repr__(self):
        return "%s:\n%s" % (self.name(),util.repr_plus(self.policies))

    def __eq__(self, other):
        return ( self.__class__ == other.__class__
           and   self.policies == other.policies )


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
        classifier = Classifier([])
        for r in inner_classifier.rules:
            action = r.actions[0]
            if action == identity:
                classifier.rules.append(Rule(r.match,[drop]))
            elif action == drop:
                classifier.rules.append(Rule(r.match,[identity]))
            else:
                raise TypeError  # TODO MAKE A CompileError TYPE
        return classifier


class parallel(CombinatorPolicy):
    """parallel(policies) evaluates to the set union of the evaluation
    of each policy in policies."""
    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return drop
        else:
            rv = super(parallel, self).__new__(parallel, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(parallel, self).__init__(policies)

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
        return reduce(lambda acc, c: acc + c, classifiers)


class union(parallel,Filter):
    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return drop
        else:
            rv = super(parallel, self).__new__(union, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(union, self).__init__(policies)

    ### or : Filter -> Filter
    def __or__(self, pol):
        if isinstance(pol,union):
            return union(self.policies + pol.policies)
        elif isinstance(pol,Filter):
            return union(self.policies + [pol])
        else:
            raise TypeError


class sequential(CombinatorPolicy):
    """sequential(policies) evaluates the set union of each policy in policies
    on each packet in the output of previous policy."""
    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return identity
        else:
            rv = super(sequential, self).__new__(sequential, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(sequential, self).__init__(policies)

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
    def __new__(self, policies=[]):
        # Hackety hack.
        if len(policies) == 0:
            return identity
        else:
            rv = super(sequential, self).__new__(intersection, policies)
            rv.__init__(policies)
            return rv

    def __init__(self, policies=[]):
        if len(policies) == 0:
            raise TypeError
        super(intersection, self).__init__(policies)

    ### and : Filter -> Filter
    def __and__(self, pol):
        if isinstance(pol,intersection):
            return intersection(self.policies + pol.policies)
        elif isinstance(pol,Filter):
            return intersection(self.policies + [pol])
        else:
            raise TypeError


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
        r = Rule(identity,[Controller])
        return Classifier([r])


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
        return self.policy.compile()

    def __repr__(self):
        return "[DerivedPolicy]\n%s" % repr(self.policy)

    def __eq__(self, other):
        return ( self.__class__ == other.__class__
           and ( self.policy == other.policy ) )


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


###############################################################################
# Classifiers
# an intermediate representation for proactive compilation.

class Rule(object):
    '''A rule contains a filter and the parallel composition of zero or more
    Pyretic actions.'''

    # Matches m should be of the match class.  Actions acts should be a list of
    # either modify, identity, or drop policies.
    def __init__(self,m,acts):
        self.match = m
        self.actions = acts

    def __str__(self):
        return str(self.match) + '\tactions:\t' + str(self.actions)

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        '''Based on syntactic equality of policies.'''
        return ( id(self) == id(other)
            or ( self.match == other.match
                 and self.actions == other.actions ) )

    def __ne__(self, other):
        '''Based on syntactic equality of policies.'''
        return not (self == other)

    def eval(self, in_pkt):
        '''If this rule matches the packet, then return the union of the sets
        of packets produced by the actions.  Otherwise, return None.'''
        filtered_pkt = self.match.eval(in_pkt)
        if len(filtered_pkt) == 0:
            return None
        rv = set()
        for pkt in filtered_pkt:
            for act in self.actions:
                rv |= act.eval(pkt)
        return rv


class Classifier(object):
    '''A classifier contains a list of rules, where the order of the list implies
    the relative priorities of the rules.  Semantically, classifiers are
    functions from packets to sets of packets, similar to OpenFlow flow
    tables.'''

    def __init__(self, new_rules=[]):
        import types
        if isinstance(new_rules, types.GeneratorType):
            self.rules = [r for r in new_rules]
        elif isinstance(new_rules,list):
            self.rules = new_rules
        else:
            raise TypeError

    def __len__(self):
        return len(self.rules)

    def __str__(self):
        return '\n'.join(map(str,self.rules))

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        '''Based on syntactic equality of policies.'''
        return ( id(self) == id(other)
            or ( self.rules == other.rules ) )

    def __ne__(self, other):
        '''Based on syntactic equality of policies.'''
        return not (self == other)

    def __add__(self,c2):
        c1 = self
        if c2 is None:
            return None
        c = Classifier([])
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

    # Helper function for rshift: given a test b and an action p, return a test
    # b' such that p >> b == b' >> p.
    def _commute_test(self, act, pkts):
        while isinstance(act, DerivedPolicy):
            act = act.policy
        if act == identity:
            return pkts
        elif act == none:
            return false
        elif act == Controller or isinstance(act, CountBucket):
            return true
        elif isinstance(act, modify):
            new_match_dict = {}
            if pkts == true:
                return true
            elif pkts == false:
                return false
            for f, v in pkts.map.iteritems():
                if f in act.map and act.map[f] == v:
                    continue
                elif f in act.map and act.map[f] != v:
                    return false
                else:
                    new_match_dict[f] = v
            if len(new_match_dict) == 0:
                return true
            return match(**new_match_dict)
        else:
            # TODO (cole) use compile error.
            # TODO (cole) what actions are allowable?
            raise TypeError

    # Helper function for rshift: sequentially compose actions.  a1 must be a
    # single action.  Returns a list of actions.
    def _sequence_actions(self, a1, as2):
        while isinstance(a1, DerivedPolicy):
            a1 = a1.policy
        # TODO: be uniform about returning copied or modified objects.
        new_actions = []
        if a1 == none:
            return [none]
        elif a1 == identity:
            return as2
        elif a1 == Controller or isinstance(a1, CountBucket):
            return [a1]
        elif isinstance(a1, modify):
            for a2 in as2:
                while isinstance(a2, DerivedPolicy):
                    a2 = a2.policy
                new_a1 = modify(**a1.map.copy())
                if a2 == none:
                    new_actions.append(none)
                elif a2 == Controller or isinstance(a2, CountBucket): 
                    new_actions.append(a2)
                elif a2 == identity:
                    new_actions.append(new_a1)
                elif isinstance(a2, modify):
                    new_a1.map.update(a2.map)
                    new_actions.append(new_a1)
                elif isinstance(a2, fwd):
                    new_a1.map['outport'] = a2.outport
                    new_actions.append(new_a1)
                else:
                    raise TypeError
            return new_actions
        else:
            raise TypeError

    # Returns a classifier.
    def _sequence_action_classifier(self, act, c):
        # TODO (cole): make classifiers easier to use w.r.t. adding/removing
        # rules.
        if len(c.rules) == 0:
            return Classifier([Rule(identity, [drop])])
        new_rules = []
        for rule in c.rules:
            pkts = self._commute_test(act, rule.match)
            if pkts == true:
                acts = self._sequence_actions(act, rule.actions)
                new_rules += [Rule(identity, acts)]
                break
            elif pkts == false:
                continue
            else:
                acts = self._sequence_actions(act, rule.actions)
                new_rules += [Rule(pkts, acts)]
        if new_rules == []:
            return Classifier([Rule(identity, [drop])])
        else:
            return Classifier(new_rules)
                
    def _sequence_actions_classifier(self, acts, c):
        empty_classifier = Classifier([Rule(identity, [drop])])
        if acts == []:
            # Treat the empty list of actions as drop.
            return empty_classifier
        acc = empty_classifier
        for act in acts:
            acc = acc + self._sequence_action_classifier(act, c)
        return acc

    def _sequence_rule_classifier(self, r, c):
        c2 = self._sequence_actions_classifier(r.actions, c)
        for rule in c2.rules:
            rule.match = rule.match.intersect(r.match)
        c2.rules = [r2 for r2 in c2.rules if r2.match != drop]
        return c2.optimize()

    def __rshift__(self, c2):
        new_rules = []
        for rule in self.rules:
            c3 = self._sequence_rule_classifier(rule, c2)
            new_rules = new_rules + c3.rules
        rv = Classifier(new_rules)
        return rv.optimize()

    def optimize(self):
        return self.remove_shadowed_cover_single()

    def remove_shadowed_exact_single(self):
        # Eliminate every rule exactly matched by some higher priority rule
        opt_c = Classifier([])
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or
                          new_r.match == r.match,
                          opt_c.rules,
                          False):
                opt_c.rules.append(r)
        return opt_c

    def remove_shadowed_cover_single(self):
        # Eliminate every rule completely covered by some higher priority rule
        opt_c = Classifier([])
        for r in self.rules:
            if not reduce(lambda acc, new_r: acc or
                          new_r.match.covers(r.match),
                          opt_c.rules,
                          False):
                opt_c.rules.append(r)
        return opt_c

    def eval(self, in_pkt):
        '''Evaluate against each rule in the classifier, starting with the
        highest priority.  Return the set of packets resulting from applying
        the actions of the first rule that matches.'''
        for rule in self.rules:
            pkts = rule.eval(in_pkt)
            if pkts is not None:
                return pkts
        raise TypeError('Classifier is not total.')


###############################################################################
# Run time helpers
#

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

