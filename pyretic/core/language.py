
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
from pyretic.core.classifier import Rule, Classifier
from pyretic.core.util import frozendict, singleton

from multiprocessing import Condition

NO_CACHE=False

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
    """
    Top-level abstract class for policies.
    All Pyretic policies have methods for

    - evaluating on a single packet.
    - compilation to a switch Classifier
    """
    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        raise NotImplementedError

    def invalidate_classifier(self):
        self._classifier = None

    def compile(self):
        """
        Produce a Classifier for this policy

        :rtype: Classifier
        """
        if NO_CACHE: 
            self._classifier = self.generate_classifier()
        return self._classifier

    def __add__(self, pol):
        """
        The parallel composition operator.

        :param pol: the Policy to the right of the operator
        :type pol: Policy
        :rtype: Parallel
        """
        if isinstance(pol,parallel):
            return parallel([self] + pol.policies)
        else:
            return parallel([self, pol])

    def __rshift__(self, other):
        """
        The sequential composition operator.

        :param pol: the Policy to the right of the operator
        :type pol: Policy
        :rtype: Sequential
        """
        if isinstance(other,sequential):
            return sequential([self] + other.policies)
        else:
            return sequential([self, other])

    def __eq__(self, other):
        """Syntactic equality."""
        raise NotImplementedError

    def __ne__(self,other):
        """Syntactic inequality."""
        return not (self == other)

    def name(self):
        return self.__class__.__name__

    def __repr__(self):
        return "%s : %d" % (self.name(),id(self))


class Filter(Policy):
    """
    Abstact class for filter policies.
    A filter Policy will always either 

    - pass packets through unchanged
    - drop them

    No packets will ever be modified by a Filter.
    """
    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        raise NotImplementedError

    def __or__(self, pol):
        """
        The Boolean OR operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: Union
        """
        if isinstance(pol,Filter):
            return union([self, pol])
        else:
            raise TypeError

    def __and__(self, pol):
        """
        The Boolean AND operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: Intersection
        """
        if isinstance(pol,Filter):
            return intersection([self, pol])
        else:
            raise TypeError

    def __sub__(self, pol):
        """
        The Boolean subtraction operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: Difference
        """
        if isinstance(pol,Filter):
            return difference(self, pol)
        else:
            raise TypeError

    def __invert__(self):
        """
        The Boolean negation operator.

        :param pol: the filter Policy to the right of the operator
        :type pol: Filter
        :rtype: negate
        """
        return negate([self])


class Singleton(Filter):
    """Abstract policy from which Singletons descend"""

    _classifier = None

    def compile(self):
        """
        Produce a Classifier for this policy

        :rtype: Classifier
        """
        if NO_CACHE: 
            self.__class__._classifier = self.generate_classifier()
        if self.__class__._classifier is None:
            self.__class__._classifier = self.generate_classifier()
        return self.__class__._classifier

    def generate_classifier(self):
        return Classifier([Rule(identity, {self})])


@singleton
class identity(Singleton):
    """The identity policy, leaves all packets unchanged."""
    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        return {pkt}

    def intersect(self, other):
        return other

    def covers(self, other):
        return True

    def __eq__(self, other):
        return ( id(self) == id(other)
            or ( isinstance(other, match) and len(other.map) == 0) )

    def __repr__(self):
        return "identity"

passthrough = identity   # Imperative alias
true = identity          # Logic alias
all_packets = identity   # Matching alias


@singleton
class drop(Singleton):
    """The drop policy, produces the empty set of packets."""
    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        return set()

    def generate_classifier(self):
        return Classifier([Rule(identity,set())])

    def intersect(self, other):
        return self

    def covers(self, other):
        return False

    def __eq__(self, other):
        return id(self) == id(other)

    def __repr__(self):
        return "drop"

none = drop
false = drop             # Logic alias
no_packets = drop        # Matching alias


@singleton
class Controller(Singleton):
    def eval(self, pkt):
        return set()

    def __eq__(self, other):
        return id(self) == id(other)

    def __repr__(self):
        return "Controller"
    

class match(Filter):
    """
    Match on all specified fields.
    Matched packets are kept, non-matched packets are dropped.

    :param *args: field matches in argument format
    :param **kwargs: field matches in keyword-argument format
    """
    def __init__(self, *args, **kwargs):
        if len(args) == 0 and len(kwargs) == 0:
            raise TypeError
        self.map = util.frozendict(dict(*args, **kwargs))
        self._classifier = self.generate_classifier()
        super(match,self).__init__()

    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """

        for field, pattern in self.map.iteritems():
            try:
                v = pkt[field]
                if pattern is None or pattern != v:
                    return set()
            except:
                if pattern is not None:
                    return set()
        return {pkt}

    def generate_classifier(self):
        r1 = Rule(self,{identity})
        r2 = Rule(identity,set())
        return Classifier([r1, r2])

    def __eq__(self, other):
        return ( (isinstance(other, match) and self.map == other.map)
            or (other == identity and len(self.map) == 0) )

    def intersect(self, pol):

        def _intersect_ip(ipfx, opfx):
            most_specific = None
            if (IPv4Network(ipfx) in IPv4Network(opfx)):
                most_specific = ipfx
            elif (IPv4Network(opfx) in IPv4Network(ipfx)): 
                most_specific = opfx
            return most_specific

        if pol == identity:
            return self
        elif pol == drop:
            return drop
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
                    return drop
            elif (f=='dstip'):
                most_specific_dst = _intersect_ip(self.map[f], pol.map[f])
                if most_specific_dst is None:
                    return drop
            elif (self.map[f] != pol.map[f]):
                return drop

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
        # Return identity if self matches every packet that other matches (and maybe more).
        # eg. if other is specific on any field that self lacks.
        if other == identity and len(self.map.keys()) > 0:
            return False
        elif other == identity:
            return True
        elif other == drop:
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

    def __repr__(self):
        return "match: %s" % ' '.join(map(str,self.map.items()))


class modify(Policy):
    """
    Modify on all specified fields to specified values.

    :param *args: field assignments in argument format
    :param **kwargs: field assignments in keyword-argument format
    """
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
        self._classifier = self.generate_classifier()
        super(modify,self).__init__()

    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        return {pkt.modifymany(self.map)}

    def generate_classifier(self):
        if self.has_virtual_headers:
            r = Rule(identity,{Controller})
        else:
            r = Rule(identity,{self})
        return Classifier([r])

    def __repr__(self):
        return "modify: %s" % ' '.join(map(str,self.map.items()))

    def __eq__(self, other):
        return ( isinstance(other, modify)
           and (self.map == other.map) )


# FIXME: Srinivas =).
class Query(Filter):
    """
    Abstract class representing a data structure
    into which packets (conceptually) go and with which callbacks can register.
    """
    ### init : unit -> unit
    def __init__(self):
        from multiprocessing import Lock
        self.callbacks = []
        self.bucket = set()
        self.bucket_lock = Lock()
        super(Query,self).__init__()

    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        with self.bucket_lock:
            self.bucket.add(pkt)
        return set()
        
    ### register_callback : (Packet -> X) -> unit
    def register_callback(self, fn):
        self.callbacks.append(fn)

    def __repr__(self):
        return "Query"


class FwdBucket(Query):
    """
    Class for registering callbacks on individual packets sent to
    the controller.
    """
    def __init__(self):
        self._classifier = self.generate_classifier()
        super(FwdBucket,self).__init__()

    def generate_classifier(self):
        return Classifier([Rule(identity,{Controller})])

    def apply(self):
        with self.bucket_lock:
            for pkt in self.bucket:
                for callback in self.callbacks:
                    callback(pkt)
            self.bucket.clear()
    
    def __repr__(self):
        return "FwdBucket"

    def __eq__(self, other):
        # TODO: if buckets eventually have names, equality should
        # be on names.
        return isinstance(other, FwdBucket)


class CountBucket(Query):
    """
    Class for registering callbacks on counts of packets sent to
    the controller.
    """
    def __init__(self):
        super(CountBucket, self).__init__()
        self.matches = set([])
        self.runtime_stats_query_fun = None
        self.outstanding_switches = []
        self.packet_count = 0
        self.byte_count = 0
        self.packet_count_persistent = 0
        self.byte_count_persistent = 0
        self.in_update_cv = Condition()
        self.in_update = False
        self._classifier = self.generate_classifier()
        
    def __repr__(self):
        return "CountBucket"

    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        return set()

    def generate_classifier(self):
        return Classifier([Rule(identity,{self})])

    def apply(self):
        with self.bucket_lock:
            for pkt in self.bucket:
                self.packet_count_persistent += 1
                self.byte_count_persistent += pkt['header_len'] + pkt['payload_len']
            self.bucket.clear()

    def start_update(self):
        """
        Use a condition variable to mediate access to bucket state as it is
        being updated.

        Why condition variables and not locks? The main reason is that the state
        update doesn't happen in just a single function call here, since the
        runtime processes the classifier rule by rule and buckets may be touched
        in arbitrary order depending on the policy. They're not all updated in a
        single function call. In that case,

        (1) Holding locks *across* function calls seems dangerous and
        non-modular (in my opinion), since we need to be aware of this across a
        large function, and acquiring locks in different orders at different
        points in the code can result in tricky deadlocks (there is another lock
        involved in protecting bucket updates in runtime).

        (2) The "with" semantics in python is clean, and splitting that into
        lock.acquire() and lock.release() calls results in possibly replicated
        failure handling code that is boilerplate.

        """
        with self.in_update_cv:
            self.in_update = True
            self.matches = set([])
            self.runtime_stats_query_fun = None
            self.outstanding_switches = []

    def finish_update(self):
        with self.in_update_cv:
            self.in_update = False
            self.in_update_cv.notify_all()
        
    def add_match(self, m):
        """
        Add a match m to list of classifier rules to be queried for
        counts.
        """
        if not m in self.matches:
            self.matches.add(m)

    def add_pull_stats(self, fun):
        """
        Point to function that issues stats queries in the
        runtime.
        """
        if not self.runtime_stats_query_fun:
            self.runtime_stats_query_fun = fun

    def pull_stats(self):
        """Issue stats queries from the runtime"""
        queries_issued = False
        with self.in_update_cv:
            while self.in_update: # ensure buckets not updated concurrently
                self.in_update_cv.wait()
            if not self.runtime_stats_query_fun is None:
                self.outstanding_switches = []
                queries_issued = True
                self.runtime_stats_query_fun()
        # If no queries were issued, then no matches, so just call userland
        # registered callback routines
        if not queries_issued:
            self.packet_count = self.packet_count_persistent
            self.byte_count = self.byte_count_persistent
            for f in self.callbacks:
                f([self.packet_count, self.byte_count])

    def add_outstanding_switch_query(self,switch):
        self.outstanding_switches.append(switch)

    def handle_flow_stats_reply(self,switch,flow_stats):
        """
        Given a flow_stats_reply from switch s, collect only those
        counts which are relevant to this bucket.

        Very simple processing for now: just collect all packet and
        byte counts from rules that have a match that is in the set of
        matches this bucket is interested in.
        """
        def stat_in_bucket(flow_stat, s):
            table_match = match(f['match']).intersect(match(switch=s))
            network_match = match(f['match'])
            if table_match in self.matches or network_match in self.matches:
                return True
            return False

        with self.in_update_cv:
            while self.in_update:
                self.in_update_cv.wait()
            self.packet_count = self.packet_count_persistent
            self.byte_count = self.byte_count_persistent
            if switch in self.outstanding_switches:
                for f in flow_stats:
                    if 'match' in f:
                        if stat_in_bucket(f, switch):
                            self.packet_count += f['packet_count']
                            self.byte_count   += f['byte_count']
                self.outstanding_switches.remove(switch)
        # If have all necessary data, call user-land registered callbacks
        if not self.outstanding_switches:
            for f in self.callbacks:
                f([self.packet_count, self.byte_count])

    def __eq__(self, other):
        # TODO: if buckets eventually have names, equality should
        # be on names.
        return isinstance(other, CountBucket)

################################################################################
# Combinator Policies                                                          #
################################################################################

class CombinatorPolicy(Policy):
    """
    Abstract class for policy combinators.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """
    ### init : List Policy -> unit
    def __init__(self, policies=[]):
        self.policies = list(policies)
        self._classifier = None
        super(CombinatorPolicy,self).__init__()

    def compile(self):
        """
        Produce a Classifier for this policy

        :rtype: Classifier
        """
        if NO_CACHE: 
            self._classifier = self.generate_classifier()
        if not self._classifier:
            self._classifier = self.generate_classifier()
        return self._classifier

    def __repr__(self):
        return "%s:\n%s" % (self.name(),util.repr_plus(self.policies))

    def __eq__(self, other):
        return ( self.__class__ == other.__class__
           and   self.policies == other.policies )


class negate(CombinatorPolicy,Filter):
    """
    Combinator that negates the input policy.

    :param policies: the policies to be negated.
    :type policies: list Filter
    """
    def eval(self, pkt):
        """
        evaluate this policy on a single packet

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        if self.policies[0].eval(pkt):
            return set()
        else:
            return {pkt}

    def generate_classifier(self):
        inner_classifier = self.policies[0].compile()
        return ~inner_classifier


class parallel(CombinatorPolicy):
    """
    Combinator for several policies in parallel.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """
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
        """
        evaluates to the set union of the evaluation
        of self.policies on pkt

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        output = set()
        for policy in self.policies:
            output |= policy.eval(pkt)
        return output

    def generate_classifier(self):
        if len(self.policies) == 0:  # EMPTY PARALLEL IS A DROP
            return drop.compile()
        classifiers = map(lambda p: p.compile(), self.policies)
        return reduce(lambda acc, c: acc + c, classifiers)


class union(parallel,Filter):
    """
    Combinator for several filter policies in parallel.

    :param policies: the policies to be combined.
    :type policies: list Filter
    """
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
    """
    Combinator for several policies in sequence.

    :param policies: the policies to be combined.
    :type policies: list Policy
    """
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
        """
        evaluates to the set union of each policy in 
        self.policies on each packet in the output of the 
        previous.  The first policy in self.policies is 
        evaled on pkt.

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        prev_output = {pkt}
        output = prev_output
        for policy in self.policies:
            if not prev_output:
                return set()
            if policy == identity:
                continue
            if policy == drop:
                return set()
            output = set()
            for p in prev_output:
                output |= policy.eval(p)
            prev_output = output
        return output

    def generate_classifier(self):
        assert(len(self.policies) > 0)
        classifiers = map(lambda p: p.compile(),self.policies)
        for c in classifiers:
            assert(c is not None)
        return reduce(lambda acc, c: acc >> c, classifiers)
        

class intersection(sequential,Filter):
    """
    Combinator for several filter policies in sequence.

    :param policies: the policies to be combined.
    :type policies: list Filter
    """
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


################################################################################
# Derived Policies                                                             #
################################################################################

class DerivedPolicy(Policy):
    """
    Abstract class for a policy derived from another policy.

    :param policy: the internal policy (assigned to self.policy)
    :type policy: Policy
    """
    def __init__(self, policy=identity):
        self.policy = policy
        self._classifier = None
        super(DerivedPolicy,self).__init__()

    def eval(self, pkt):
        """
        evaluates to the output of self.policy.

        :param pkt: the packet on which to be evaluated
        :type pkt: Packet
        :rtype: set Packet
        """
        return self.policy.eval(pkt)

    def compile(self):
        """
        Produce a Classifier for this policy

        :rtype: Classifier
        """
        if NO_CACHE: 
            self._classifier = self.generate_classifier()
        if not self._classifier:
            self._classifier = self.generate_classifier()
        return self._classifier

    def generate_classifier(self):
        return self.policy.compile()

    def __repr__(self):
        return "[DerivedPolicy]\n%s" % repr(self.policy)

    def __eq__(self, other):
        return ( self.__class__ == other.__class__
           and ( self.policy == other.policy ) )


class difference(DerivedPolicy,Filter):
    """
    The difference between two filter policies..

    :param f1: the minuend
    :type f1: Filter
    :param f2: the subtrahend
    :type f2: Filter
    """
    def __init__(self, f1, f2):
       self.f1 = f1
       self.f2 = f2
       super(difference,self).__init__(~f2 & f1)

    def __repr__(self):
        return "difference:\n%s" % util.repr_plus([self.f1,self.f2])


class if_(DerivedPolicy):
    """
    if pred holds, t_branch, otherwise f_branch.

    :param pred: the predicate
    :type pred: Filter
    :param t_branch: the true branch policy
    :type pred: Policy
    :param f_branch: the false branch policy
    :type pred: Policy
    """
    def __init__(self, pred, t_branch, f_branch=identity):
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

    def __repr__(self):
        return "if\n%s\nthen\n%s\nelse\n%s" % (util.repr_plus([self.pred]),
                                               util.repr_plus([self.t_branch]),
                                               util.repr_plus([self.f_branch]))


class fwd(DerivedPolicy):
    """
    fwd out a specified port.

    :param outport: the port on which to forward.
    :type outport: int
    """
    def __init__(self, outport):
        self.outport = outport
        super(fwd,self).__init__(modify(outport=self.outport))

    def __repr__(self):
        return "fwd %s" % self.outport


class xfwd(DerivedPolicy):
    """
    fwd out a specified port, unless the packet came in on that same port.
    (Semantically equivalent to OpenFlow's forward action

    :param outport: the port on which to forward.
    :type outport: int
    """
    def __init__(self, outport):
        self.outport = outport
        super(xfwd,self).__init__((~match(inport=outport)) >> fwd(outport))

    def __repr__(self):
        return "xfwd %s" % self.outport


################################################################################
# Dynamic Policies                                                             #
################################################################################

class DynamicPolicy(DerivedPolicy):
    """
    Abstact class for dynamic policies.
    The behavior of a dynamic policy changes each time self.policy is reassigned.
    """
    ### init : unit -> unit
    def __init__(self,policy=drop):
        self._policy = policy
        self.notify = None
        self._classifier = None
        super(DerivedPolicy,self).__init__()

    def set_network(self, network):
        pass

    def attach(self,notify):
        self.notify = notify

    def detach(self):
        self.notify = None

    def changed(self):
        if self.notify:
            self.notify(self)

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, policy):
        prev_policy = self._policy
        self._policy = policy
        self.changed()

    def __repr__(self):
        return "[DynamicPolicy]\n%s" % repr(self.policy)


class DynamicFilter(DynamicPolicy,Filter):
    """
    Abstact class for dynamic filter policies.
    The behavior of a dynamic filter policy changes each time self.policy is reassigned.
    """
    pass


class flood(DynamicPolicy):
    """
    Policy that floods packets on a minimum spanning tree, recalculated
    every time the network is updated (set_network).
    """
    def __init__(self):
        self.mst = None
        super(flood,self).__init__()

    def set_network(self, network):
        changed = False
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
    """
    Returns True if a packet is located at a (switch,inport) pair entering
    the network, False otherwise.
    """
    def __init__(self):
        self.egresses = None
        super(ingress_network,self).__init__()

    def set_network(self, network):
        updated_egresses = network.topology.egress_locations()
        if not self.egresses == updated_egresses:
            self.egresses = updated_egresses
            self.policy = parallel([match(switch=l.switch,
                                       inport=l.port_no)
                                 for l in self.egresses])

    def __repr__(self):
        return "ingress_network"


class egress_network(DynamicFilter):
    """
    Returns True if a packet is located at a (switch,outport) pair leaving
    the network, False otherwise.
    """
    def __init__(self):
        self.egresses = None
        super(egress_network,self).__init__()

    def set_network(self, network):
        updated_egresses = network.topology.egress_locations()
        if not self.egresses == updated_egresses:
            self.egresses = updated_egresses
            self.policy = parallel([match(switch=l.switch,
                                       outport=l.port_no)
                                 for l in self.egresses])

    def __repr__(self):
        return "egress_network"
