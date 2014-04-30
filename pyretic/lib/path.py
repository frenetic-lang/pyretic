################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
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

from pyretic.core.language import identity, egress_network, Filter, drop, match
from pyretic.core.language import modify, Query, FwdBucket, CountBucket
from pyretic.core.language import PathBucket

from pyretic.lib.query import counts, packets
from pyretic.core.runtime import virtual_field

from pyretic.lib.re import *

import subprocess
import pyretic.vendor
import pydot
import copy

TOKEN_START_VALUE = 48 # start with printable ASCII for visual inspection ;)
# token type definitions
TOK_INGRESS = "ingress"
TOK_EGRESS = "egress"
TOK_DROP = "drop"
TOK_END_PATH = "end_path"
TOK_HOOK = "ingress_hook"

#############################################################################
###             Utilities to map predicates to characters                 ###
#############################################################################

class classifier_utils(object):
    """ Utilities related to analysis of classifiers, that come in handy to do
    various manipulations on policies.
    """
    @classmethod
    def __get_classifier__(cls, p):
        # Hackety hack
        if p._classifier:
            return p._classifier
        try:
            return p.generate_classifier()
        except:
            p.compile()
            return p._classifier

    @classmethod
    def __is_not_drop_classifier__(cls, c):
        for rule in c.rules:
            if not drop in rule.actions:
                return True
        return False

    @classmethod
    def is_not_drop(cls, p):
        """ Return true if policy p is effectively a drop. """
        p_class = cls.__get_classifier__(p)
        return cls.__is_not_drop_classifier__(p_class)

    @classmethod
    def has_nonempty_intersection(cls, p1, p2):
        """Return True if policies p1, p2 have an intesection which is
        drop. Works by generating the classifiers for the intersection of the
        policies, and checking if there are anything other than drop rules.
        """
        return cls.is_not_drop(p1 & p2)

    @classmethod
    def get_overlap_mode(cls, pred, new_pred):
        """ Returns a tuple (is_equal, is_superset, is_subset, intersects) of
        booleans, depending on whether pred is equal, is a superset of, is a subset
        of, or just intersects new_pred.
        """
        assert isinstance(new_pred, Filter) and isinstance(pred, Filter)
        ne_inters = cls.has_nonempty_intersection
        (is_equal,is_superset,is_subset,intersects) = (False,False,False,False)
        if  (not ne_inters( pred, ~new_pred) and
             not ne_inters(~pred,  new_pred)):
            is_equal = True
        elif not ne_inters(~pred,  new_pred):
            is_superset = True
        elif not ne_inters( pred, ~new_pred):
            is_subset = True
        elif ne_inters(pred, new_pred):
            intersects = True
        else:
            pass
        return (is_equal, is_superset, is_subset, intersects)

    @classmethod
    def get_dropped_packets(cls, p):
        """For an arbitrary policy p, return the set of packets (as a filter
        policy) that are dropped by it.
        """
        pol_classifier = cls.__get_classifier__(p)
        matched_packets = drop
        for rule in pol_classifier.rules:
            fwd_actions = filter(lambda a: (isinstance(a, modify)
                                         and a['outport'] != OFPP_CONTROLLER),
                              rule.actions)
            if len(fwd_actions) > 0:
                matched_packets += rule.match
        return ~matched_packets


class re_tree_gen(object):
    """ A class that provides utilities to book-keep "leaf-level" predicates in
    a regular expression abstract syntax tree (AST), and return new re_deriv
    trees for new predicates.
    """
    token = TOKEN_START_VALUE
    # Invariants: pred is always a leaf-level predicate in the re AST of some
    # path query.
    pred_to_symbol = {}
    pred_to_atoms  = {}

    @classmethod
    def repr_state(cls):
        assert (sorted(cls.pred_to_symbol.keys()) ==
                sorted(cls.pred_to_atoms.keys()))
        output = ''
        for pred in cls.pred_to_symbol:
            output += repr(pred) + ":\n"
            output += '  symbol: ' + repr(cls.pred_to_symbol[pred]) + '\n'
            try:
                output += '  atoms: ' + repr(cls.pred_to_atoms[pred] ) + '\n'
            except:
                pass
        return output

    @classmethod
    def __add_pred__(cls, pred, symbol, atoms):
        """ Add a new predicate to the global state. """
        assert not pred in cls.pred_to_symbol
        assert not pred in cls.pred_to_atoms
        cls.pred_to_symbol[pred] = symbol
        cls.pred_to_atoms[pred] = atoms

    @classmethod
    def __del_pred__(cls, pred):
        """ Remove a predicate from existing global state of leaf-level
        predicates. """
        del cls.pred_to_symbol[pred]
        del cls.pred_to_atoms[pred]

    @classmethod
    def __new_symbol__(cls):
        """ Returns a new token/symbol for a leaf-level predicate. """
        cls.token += 1
        try:
            return chr(cls.token)
        except:
            return unichr(cls.token)

    @classmethod
    def __replace_pred__(cls, old_pred, new_preds):
        """ Replace the re symbol corresponding to `old_pred` with an
        alternation of predicates in `new_preds`. The metadata from the
        old_pred's re symbol is copied over to all leaf nodes of its new re AST.
        """
        def new_metadata_tree(m, re_tree):
            """ Return a new tree which has a given metadata m on all nodes in
            the given re_tree."""
            if isinstance(re_tree, re_symbol):
                assert re_tree.metadata == []
                return re_symbol(re_tree.char, metadata=m, lst=False)
            elif isinstance(re_tree, re_alter):
                new_re = re_empty()
                for re in re_tree.re_list:
                    new_re = new_re | new_metadata_tree(m, re)
                return new_re
            else:
                raise TypeError("Trees are only allowed to have alternation!")

        def replace_node(old_re_tree, new_re_tree, old_sym):
            """ Replace all nodes in the provided re_tree, which correspond to a
            symbol `old_sym`, with the re tree `new_re_tree`. Also retain the
            original metadata that was in the respective old node."""
            if isinstance(old_re_tree, re_symbol):
                if old_re_tree.char == old_sym:
                    # replace with metadata!
                    return new_metadata_tree(old_re_tree.metadata, new_re_tree)
                else:
                    return old_re_tree
            elif isinstance(old_re_tree, re_alter):
                new_re = re_empty()
                for re in old_re_tree.re_list:
                    new_re = new_re | replace_node(re, new_re_tree, old_sym)
                return new_re
            else:
                raise TypeError("Trees are only allowed to have alternation!")

        assert old_pred in cls.pred_to_symbol and old_pred in cls.pred_to_atoms
        old_sym = cls.pred_to_symbol[old_pred]
        new_re_tree = re_empty()
        # Construct replacement tree (without metadata first)
        for pred in new_preds:
            assert pred in cls.pred_to_symbol
            assert pred in cls.pred_to_atoms
            new_sym = cls.pred_to_symbol[pred]
            new_re_tree = new_re_tree | re_symbol(new_sym)
        # For each atom containing old_pred, replace re leaf by new tree.
        for at in cls.pred_to_atoms[old_pred]:
            new_atom_re_tree = replace_node(at.re_tree, new_re_tree, old_sym)
            at.re_tree = new_atom_re_tree # change the atom objects themselves!

    @classmethod
    def get_re_tree(cls, new_pred, at):
        """ Deal with existing leaf-level predicates, taking different actions
        based on whether the existing predicates are equal, superset, subset, or
        just intersecting, the new predicate.
        """
        assert isinstance(at, atom)
        assert isinstance(new_pred, Filter)

        ne_inters   = classifier_utils.has_nonempty_intersection
        is_not_drop = classifier_utils.is_not_drop
        add_pred = cls.__add_pred__
        new_sym  = cls.__new_symbol__
        del_pred = cls.__del_pred__
        replace_pred = cls.__replace_pred__
        ovlap = classifier_utils.get_overlap_mode

        re_tree = re_empty()
        pred_list = cls.pred_to_symbol.keys()

        for pred in pred_list:
            assert pred in cls.pred_to_atoms
            pred_atoms = cls.pred_to_atoms[pred]
            pred_symbol = cls.pred_to_symbol[pred]
            (is_equal,is_superset,is_subset,intersects) = ovlap(pred, new_pred)
            if is_equal:
                pred_atoms.append(at)
                re_tree |= re_symbol(pred_symbol, metadata=at)
                return re_tree
            elif is_superset:
                add_pred(pred & ~new_pred, new_sym(), pred_atoms)
                add_pred(new_pred, new_sym(), pred_atoms + [at])
                replace_pred(pred, [pred & ~new_pred, new_pred])
                del_pred(pred)
                added_sym = cls.pred_to_symbol[new_pred]
                re_tree |= re_symbol(added_sym, metadata=at)
                return re_tree
            elif is_subset:
                new_pred = new_pred & ~pred
                pred_atoms.append(at)
                re_tree |= re_symbol(pred_symbol, metadata=at)
            elif intersects:
                add_pred(pred & ~new_pred, new_sym(), pred_atoms)
                add_pred(pred &  new_pred, new_sym(), pred_atoms + [at])
                replace_pred(pred, [pred & ~new_pred, pred & new_pred])
                del_pred(pred)
                added_sym = cls.pred_to_symbol[pred & new_pred]
                re_tree |= re_symbol(added_sym, metadata=at)
                new_pred = new_pred & ~pred
            else:
                pass

        if is_not_drop(new_pred):
            add_pred(new_pred, new_sym(), [at])
            added_sym = cls.pred_to_symbol[new_pred]
            re_tree |= re_symbol(added_sym, metadata=at)

        return re_tree

    @classmethod
    def clear(cls):
        cls.token = TOKEN_START_VALUE
        cls.pred_to_symbol = {}
        cls.pred_to_atoms   = {}

    @classmethod
    def get_symlist(cls):
        """ Get a list of symbols which are leaf-level predicates """
        return cls.pred_to_symbol.values()

#############################################################################
###               Path query language components                          ###
#############################################################################

class path(Query):
    """A way to query packets or traffic volumes satisfying regular expressions
    denoting paths of located packets.

    :param a: path atom used to construct this path element
    :type atom: atom
    """
    def __init__(self, a=None, paths=None):
        if a:
            assert isinstance(a, abstract_atom)
            self.atom = a
            self.re_tree = re_tree_gen.get_re_tree(a.policy, a)
        elif paths:
            self.paths = paths
        else:
            raise RuntimeError
        super(path, self).__init__()
        self.bucket_instance = FwdBucket() # default bucket type

    @property
    def expr(self):
        return self.re_tree.re_string_repr()

    def get_bucket(self):
        return self.bucket_instance

    def set_bucket(self, bucket_instance):
        self.bucket_instance = bucket_instance

    def register_callback(self, f):
        self.bucket_instance.register_callback(f)

    def __repr__(self):
        return '[path expr: ' + self.expr + ' id: ' + str(id(self)) + ']'

    def __xor__(self, other):
        """Implementation of the path concatenation operator ('^')"""
        assert isinstance(other, path)
        return path_concat([self, other])

    def __or__(self, other):
        """Implementation of the path alternation operator ('|')"""
        assert isinstance(other, path)
        return path_alternate([self, other])

    def __pos__(self):
        """Implementation of the Kleene star operator.
        """
        return path_star(self)

    def __invert__(self):
        """ Implementation of the path negation operator ('~') """
        return path_negate(self)

    def __and__(self, other):
        """ Implementation of the path intersection operator ('&') """
        assert isinstance(other, path)
        return path_inters([self, other])


class abstract_atom(path, Filter):
    """A single atomic match in a path expression. This is an abstract class
    where the token isn't initialized.

    :param m: a Filter (or match) object used to initialize the path atom.
    :type match: Filter
    """
    def __init__(self, m):
        assert isinstance(m, Filter)
        self.policy = m
        super(abstract_atom, self).__init__(a=self)

    def __and__(self, other):
        assert isinstance(other, type(self))
        return type(self)(self.policy & other.policy)

    def __or__(self, other):
        if isinstance(other, abstract_atom):
            assert isinstance(other, type(self))
            return type(self)(self.policy | other.policy)
        elif isinstance(other, path):
            return super(abstract_atom, self).__or__(other)
        else:
            raise TypeError

    def __sub__(self, other):
        assert isinstance(other, type(self))
        return type(self)((~other.policy) & self.policy)

    def __invert__(self):
        return type(self)(~(self.policy))


class atom(abstract_atom):
    """A concrete "ingress" match atom."""
    def __init__(self, m):
        super(atom, self).__init__(m)


class egress_atom(abstract_atom):
    """An atom that denotes a match on a packet after the forwarding decision
    has been made. It can always be substituted by a normal ("ingress") atom at
    the next hop, unless the packet is egressing the network. Hence, it may be
    noted that this is only necessary (apart from expressive power, of course)
    to match on packets that egress the network.
    """
    def __init__(self, m):
        super(egress_atom, self).__init__(m)


class drop_atom(abstract_atom):
    """An atom that matches on packets that were dropped by the forwarding
    policy.
    """
    def __init__(self, m):
        super(drop_atom, self).__init__(m)

class end_path(abstract_atom):
    def __init__(self, m):
        super(end_path, self).__init__(m)


class hook(abstract_atom):
    """A hook is essentially like an atom, but has a notion of "grouping"
    associated with it. Whenever a packet arrives into this hook, we group them
    by the values of the fields specified in the groupby=... argument of the
    constructor.
    """
    def __init__(self, m, groupby=[]):
        assert groupby and len(groupby) > 0
        self.groupby = groupby
        super(hook, self).__init__(m)

    def __and__(self, other):
        assert isinstance(other, hook)
        assert self.groupby == other.groupby
        return hook(self.policy & other.policy, self.groupby)

    def __or__(self, other):
        assert isinstance(other, hook)
        assert self.groupby == other.groupby
        return hook(self.policy | other.policy, self.groupby)

    def __sub__(self, other):
        assert isinstance(other, hook)
        assert self.groupby == other.groupby
        return hook((~other.policy) & self.policy, self.groupby)

    def __invert__(self):
        return hook(~(self.policy), self.groupby)


### Path combinator classes ###

class path_alternate(path):
    """ Alternation of paths. """
    def __init__(self, paths_list):
        self.__check_type(paths_list)
        super(path_alternate, self).__init__(paths=paths_list)

    def __check_type(self, paths):
        for p in paths:
            assert isinstance(p, path)

    @property
    def re_tree(self):
        tree = re_empty()
        for p in self.paths:
            tree = tree | p.re_tree
        return tree

class path_star(path):
    """ Kleene star on a path. """
    def __init__(self, p):
        self.__check_type(p)
        super(path_star, self).__init__(paths=[p])

    def __check_type(self, p):
        assert isinstance(p, path)

    @property
    def re_tree(self):
        p = self.paths[0]
        return +(p.re_tree)


class path_concat(path):
    """ Concatenation of paths. """
    def __init__(self, paths_list):
        self.__check_type(paths_list)
        super(path_concat, self).__init__(paths=paths_list)

    def __check_type(self, paths):
        for p in paths:
            assert isinstance(p, path)

    @property
    def re_tree(self):
        tree = re_epsilon()
        for p in self.paths:
            tree = tree ^ p.re_tree
        return tree


class path_negate(path):
    """ Negation of paths. """
    def __init__(self, p):
        self.__check_type(p)
        super(path_negate, self).__init__(paths=[p])

    def __check_type(self, p):
        assert isinstance(p, path)

    @property
    def re_tree(self):
        p = self.paths[0]
        return ~(p.re_tree)


class path_inters(path):
    """ Intersection of paths. """
    def __init__(self, paths_list):
        self.__check_type(paths_list)
        super(path_inters, self).__init__(paths=paths_list)

    def __check_type(self, paths):
        for p in paths:
            assert isinstance(p, path)

    @property
    def re_tree(self):
        tree = ~re_empty()
        for p in self.paths:
            tree = tree & p.re_tree
        return tree


#############################################################################
###                      Path query compilation                           ###
#############################################################################

class pathcomp(object):
    """ Functionality related to actual compilation of path queries. """
    @classmethod
    def __get_pred__(cls, edge_atoms_list):
        prev_pred = None
        pred = None
        for m in edge_atoms_list:
            for a in m:
                pred = a.policy
                if not prev_pred:
                    prev_pred = pred
                assert pred == prev_pred
                prev_pred = pred
        assert pred
        return pred

    @classmethod
    def __set_tag__(cls, d, q):
        val = dfa_utils.get_state_index(q)
        if int(val) == 0:
            return modify(path_tag=None)
        else:
            return modify(path_tag=int(val))

    @classmethod
    def __match_tag__(cls, d, q):
        val = dfa_utils.get_state_index(q)
        if int(val) == 0:
            return match(path_tag=None)
        else:
            return match(path_tag=int(val))

    @classmethod
    def compile(cls, path_list, fwding):
        """ Compile the list of paths along with the forwarding policy `fwding`
        into a single classifier to be installed on switches.
        """
        du = dfa_utils

        re_list = map(lambda x: x.re_tree, path_list)
        dfa = du.regexes_to_dfa(re_list)
        tagging = drop
        capture = drop
        match_tag = lambda q: cls.__match_tag__(dfa, q)
        set_tag   = lambda q: cls.__set_tag__(dfa, q)

        edges = du.get_edges()
        for e in edges:
            src = du.get_edge_src(dfa, edge)
            dst = du.get_edge_dst(dfa, edge)
            atoms = du.get_edge_atoms(dfa, edge)
            pred = cls.__get_pred__(atoms)
            tagging += ((match_tag(src) & pred) >> set_tag(dst))

            if du.is_accepting(dst, dfa):
                ords = du.get_accepting_exps(dfa, dst)
                for i in ords:
                    bucket = path_list[i].get_bucket()
                    capture += ((match_tag(src) & pred) >> bucket)

        return (tagging >> fwding) + capture

    class policy_frags:
        def __init__(self):
            self.tagging = drop
            self.untagging = drop
            self.counting = drop
            self.endpath = drop
            self.dropping = drop
            self.hooks = drop

        def set_tagging(self, pol):
            self.tagging = pol

        def set_untagging(self, pol):
            self.untagging = pol

        def set_counting(self, pol):
            self.counting = pol

        def set_endpath(self, pol):
            self.endpath = pol

        def set_dropping(self, pol):
            self.dropping = pol

        def set_hooks(self, pol):
            self.hooks = pol

        def get_tagging(self):
            return self.tagging

        def get_untagging(self):
            return self.untagging

        def get_counting(self):
            return self.counting

        def get_endpath(self):
            return self.endpath

        def get_dropping(self):
            return self.dropping

        def get_hooks(self):
            return self.hooks

    # XXX: use hints for hooks compilation, egress atom compilation, ... here.
    @classmethod
    def get_policy_fragments(cls):
        """Generates tagging and counting policy fragments to use with the
        returned general network policy.
        """
        du = ml_ulex_dfa_utils
        cg = CharacterGenerator
        dfa = du.regexes_to_dfa(cls.re_list, '/tmp/pyretic-regexes.txt')
        
        # initialize virtual fields
        virtual_field(name="path_tag", values=range(0, du.get_num_states(dfa)),
                      type="integer")

        def get_hook_atoms(edge_label):
            hook_atoms = []
            for c in edge_label:
                tok = cg.get_token_from_char(c)
                hook_atoms += cg.get_atoms_from_token(tok, TOK_HOOK)
            return hook_atoms

        def build_hook_state(tag, hook_atoms):
            if tag in hooks_map:
                hooks_map[tag] += hook_atoms
            else:
                hooks_map[tag] = hook_atoms

        # policies to apply on packet in the critical path
        tagging_policy = drop
        untagged_packets = identity
        # policies involving packet/count capture (parallelly composed)
        capture_policy = {}
        # hook policy to capture packets whose grouping must be known
        hooks_policy = drop
        hooks_bucket = PathBucket(require_original_pkt=True)
        hooks_map = {} # tag -> [hooks]

        edge_list = du.get_edges(dfa)
        for edge in edge_list:
            # generate tagging fragment
            src = du.get_state_id(du.get_edge_src(edge, dfa))
            dst = du.get_state_id(du.get_edge_dst(edge, dfa))
            [edge_label, negated] = du.get_edge_label(edge)
            transit_match_map = cg.get_filter_from_edge_label(edge_label,
                                                              negated)
            if TOK_INGRESS in transit_match_map:
                transit_match = transit_match_map[TOK_INGRESS]
                tagging_match = cls.match_tag(src) & transit_match
                tagging_policy += (tagging_match >> cls.set_tag(dst))
                untagged_packets = untagged_packets & ~tagging_match

            # generate hooking fragment for data plane grouping
            if TOK_HOOK in transit_match_map:
                if not negated:
                    hook_atoms = get_hook_atoms(edge_label)
                    build_hook_state(src, hook_atoms)
                    if hooks_policy != drop:
                        hooks_policy += cls.match_tag(src)
                    else:
                        hooks_policy = cls.match_tag(src)

            # generate counting fragment, if accepting state.
            dst_state = du.get_edge_dst(edge, dfa)
            if du.is_accepting(dst_state):
                accepted_token = du.get_accepted_token(dst_state)
                paths = cls.paths_list[accepted_token]
                for p in paths:
                    bucket = cls.path_to_bucket[p]
                    for toktype in [TOK_INGRESS, TOK_END_PATH, TOK_DROP]:
                        if toktype in transit_match_map:
                            transit_match = transit_match_map[toktype]
                            capture_fragment = ((cls.match_tag(src) &
                                                 transit_match)
                                                >> bucket)
                            if toktype in capture_policy:
                                capture_policy[toktype] += capture_fragment
                            else:
                                capture_policy[toktype] = capture_fragment

        # preserve untagged packets as is for forwarding.
        tagging_policy += untagged_packets

        # remove all tags before passing on to hosts.
        untagging_policy = ((egress_network() >>
                             modify(path_tag=None)) +
                            (~egress_network()))

        for toktype in [TOK_INGRESS, TOK_END_PATH, TOK_DROP]:
            if not toktype in capture_policy:
                capture_policy[toktype] = drop

        hooks_policy = hooks_policy >> hooks_bucket
        hooks_bucket.register_callback(cls.set_up_hooks_callback(hooks_map,
                                                                 tagging_policy))

        frags = pathcomp.policy_frags()
        frags.set_tagging(tagging_policy)
        frags.set_untagging(untagging_policy)
        frags.set_counting(capture_policy[TOK_INGRESS])
        frags.set_endpath(capture_policy[TOK_END_PATH])
        frags.set_dropping(capture_policy[TOK_DROP])
        frags.set_hooks(hooks_policy)

        return frags

    # XXX: use hints to stitch compiled fragments from other atom types here.
    @classmethod
    def stitch(cls, fwding, path_pol_fragments):
        """Stitch together the "single packet policy" and "path policy" and
        return the globally effective network policy.
        """
        frags = path_pol_fragments
        tagging = frags.get_tagging()
        untagging = frags.get_untagging()
        counting = frags.get_counting()
        endpath = frags.get_endpath()
        dropping = frags.get_dropping()
        hooks = frags.get_hooks()

        # TODO(ngsrinivas) There has to be a way of constructing the "dropped by
        # forwarding" policy while only relying on the structure of the
        # forwarding policy. Any technique which goes through its classifier is
        # necessarily incorrect -- unless it re-constructs the stitched policy
        # each time the policy is re-installed on the network. There are
        # (arguably minor) problems with this latter approach as well,
        # however. In particular, information about the path policies and
        # distinct handling of single packet and path policies will percolate
        # into multiple places in the runtime.

        # dropped_by_fwding = CharacterGenerator.get_dropped_packets(fwding)

        return ((tagging >> fwding) + # critical path
                (counting) + # capture when match at ingress
                (tagging >> fwding >> egress_network() >> endpath) + # endpath
                (tagging >> hooks)) # grouping inference
                # TODO(ngsrinivas): drop atoms are not stitched in as of now
                # + (tagging >> dropped_by_fwding >> dropping)) # capture when
                                                            # dropped

    # XXX: hooks state management and callback setup forthcoming.
    @classmethod
    def set_up_hooks_callback(cls, hooks_map, tagging):
        # 1. get path_tag from the packet (not direct as of now)
        # 2. use tag value and hooks_map to get hook objects
        # 3. get hook=value list for each path in paths
        # 4. instantiate a new path
        # 5. deal with base path changes needed
        # 6. recompile/update data plane with totally new set of paths
        def get_path_tag(pkt, hooks_map):
            """An essentially circular way of getting the path_tag value from a
            packet, since interpreted mode packets can't access the virtual
            headers on them through direct key reference."""
            for tag in hooks_map.keys():
                pkts = cls.match_tag(tag).eval(pkt)
                if len(pkts) > 0:
                    return tag
            return None

        def get_hook_projection(pkt_path, hooks_map, tagging):
            """The projection of a packet trajectory in terms of its hooks is
            just the list of group value assignments for the hooks, whenever it
            is encountered along the packet trajectory."""
            groups_list = []
            for pkt in pkt_path:
                curr_group = {}
                tagged_pkt = list(tagging.eval(pkt))[0]
                tag = get_path_tag(tagged_pkt, hooks_map)
                if tag in hooks_map:
                    curr_group = {}
                    hooks_list = hooks_map[tag]
                    for h in hooks_list:
                        curr_group[h] = [pkt[field] for field in h.groupby]
                    groups_list.append(curr_group)
            return groups_list

        def actual_callback(pkt, paths):
            print "Projected list of groups:"
            for p in paths:
                proj = get_hook_projection(p, hooks_map, tagging)
                for p in proj:
                    for hook in p.keys():
                        print hook.groupby, '=', p[hook]

        return actual_callback


#############################################################################
###        Utilities to get data into ml-ulex, and out into DFA           ###
#############################################################################

class dfa_utils(object):
    @classmethod
    def print_dfa(cls, d):
        """ Print a DFA object d. """
        assert isinstance(d, dfa_base)
        return repr(d)

    @classmethod
    def get_edges(cls, d):
        assert isinstance(d, dfa_base)
        """ The output has the form
        (src_state_re, dst_state_re, symbol) list
        """
        return d.transition_table.get_transitions()

    @classmethod
    def get_edge_src(cls, d, tt_entry):
        """ tt_entry here is one of the elements of the output of
        dfa_transition_table.get_transitions(), and hence has the form
        (source_state_re, dst_state_re, symbol)
        """
        assert isinstance(d, dfa_base)
        assert isinstance(tt_entry, tuple) and len(tt_entry) == 3
        src = tt_entry[0]
        return d.all_states.get_index(src)

    @classmethod
    def get_edge_dst(cls, d, tt_entry):
        assert isinstance(d, dfa_base)
        assert isinstance(tt_entry, tuple) and len(tt_entry) == 3
        dst = tt_entry[1]
        return d.all_states.get_index(dst)

    @classmethod
    def get_edge_label(cls, tt_entry):
        assert isinstance(tt_entry, tuple) and len(tt_entry) == 3
        return tt_entry[2]

    @classmethod
    def get_edge_atoms(cls, d, tt_entry):
        q = cls.get_edge_src(d, tt_entry)
        c = cls.get_edge_label(tt_entry)
        return d.transition_table.get_metadata(q, c)

    @classmethod
    def get_state_index(cls, d, q):
        assert isinstance(d, dfa_base)
        return d.all_states.get_index(q)

    @classmethod
    def get_num_states(cls, d):
        assert isinstance(d, dfa_base)
        return d.all_states.get_num_states()

    @classmethod
    def get_num_transitions(cls, d):
        assert isinstance(d, dfa_base)
        return d.transition_table.get_num_transitions()

    @classmethod
    def is_accepting(cls, d, q):
        assert isinstance(d, dfa_base)
        return d.all_states.is_accepting(q)

    @classmethod
    def get_accepting_exps(cls, d, q):
        assert isinstance(d, dfa_base) # dfa object
        assert isinstance(d.all_states, re_vector_state_table)
        assert cls.is_accepting(q)
        return d.all_states.get_accepting_exps_ordinal(q)

    @classmethod
    def get_num_accepting_states(cls, d):
        assert isinstance(d, dfa_base)
        return d.final_states.get_num_states()

    @classmethod
    def get_symlist(re_exps):
        """ Given a list of re expressions, get the list of symbols at the
        leaf-level. """
        def get_symlist_single_re(r):
            assert isinstance(r, re_deriv)
            lst = []
            if isinstance(r, re_symbol):
                lst = [r.char]
            elif isinstance(r, re_epsilon) or isinstance(r, re_empty):
                lst = []
            elif isinstance(r, re_combinator):
                lst = reduce(lambda acc, x: acc + get_symlist_single_re(x),
                             r.re_list, [])
            else:
                raise TypeError
            return lst

        symlist = set([])
        for r in re_exps:
            syms_r = get_symlist_single_re(r)
            reduce(lambda acc, x: acc.add(x), syms_r, symlist)
        return list(symlist)

    @classmethod
    def regexes_to_dfa(cls, re_exps, symlist=None):
        """ Convert a list of regular expressions to a DFA. """
        assert reduce(lambda acc, x: acc and isinstance(x, re_deriv),
                      re_exps, True)
        if not symlist:
            symlist = re_tree_gen.get_symlist()
        return makeDFA_vector(re_exps, symlist)
