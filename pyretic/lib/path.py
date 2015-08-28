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

from pyretic.core.language import identity, egress_network, Filter, drop, match, Policy
from pyretic.core.language import modify, Query, FwdBucket, CountBucket
from pyretic.core.language import PathBucket, DynamicFilter
from pyretic.core.language_tools import ast_fold as policy_ast_fold
from pyretic.core.language_tools import add_dynamic_sub_pols

from pyretic.lib.query import counts, packets
from pyretic.core.runtime import virtual_field

from pyretic.lib.re import *

import subprocess
import pyretic.vendor
import pydot
import copy

from pyretic.core.language import Controller, fwd, CombinatorPolicy
from pyretic.core.language import negate, union, intersection
from pyretic.core import util
import pickle
from pyretic.evaluations.stat import Stat
from netaddr import IPNetwork, cidr_merge
import time
import logging

from collections import Counter

TOKEN_START_VALUE = 0 # start with printable ASCII for visual inspection ;)
TOKEN_END_VALUE = 0xFFFFFFFF 
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
    def __set_init_vars__(cls, match_enabled):
        cls.match_enabled = match_enabled
        cls.intersect_called = 0
        cls.overlap_called = 0 
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
        return reduce(lambda a, r: a or len(r.actions) > 0, c.rules, False)

    @classmethod
    def is_not_drop(cls, p):
        """ Return true if policy p is effectively a drop.

        :param p: policy
        :type p: Policy
        """
        p_class = cls.__get_classifier__(p)
        res = cls.__is_not_drop_classifier__(p_class)
        return res
        

    @classmethod
    def has_nonempty_intersection(cls, p1, p2):
        """Return True if policies p1, p2 have an intesection which is
        drop. Works by generating the classifiers for the intersection of the
        policies, and checking if there are anything other than drop rules.

        :param p1: Policy
        :type p1: Policy
        :param p2: Policy
        :type p2: Policy
        """
        return cls.is_not_drop(p1 & p2) 
           
    @classmethod
    def get_overlap_mode(cls, pred, pred_neg, new_pred, new_pred_neg):
        """ Returns a tuple (is_equal, is_superset, is_subset, intersects) of
        booleans, depending on whether pred is equal, is a superset of, is a subset
        of, or just intersects new_pred.

        :param pred: reference predicate
        :type pred: Filter
        :param new_pred: new predicate investigated
        :type new_pred: Filter
        """
        assert isinstance(new_pred, Filter) and isinstance(pred, Filter) and isinstance(pred_neg, Filter) and isinstance(new_pred_neg, Filter)
        ne_inters = cls.has_nonempty_intersection
        (is_equal,is_superset,is_subset,intersects) = (False,False,False,False)

        not_new_and_pred = ne_inters(pred, new_pred_neg)
        new_and_not_pred = ne_inters(pred_neg, new_pred)
        if  (not not_new_and_pred and
             not new_and_not_pred):
            is_equal = True
        elif not new_and_not_pred:
            is_superset = True
        elif not not_new_and_pred:
            is_subset = True
        elif ne_inters(pred, new_pred):
            intersects = True
        else:
            pass

        return (is_equal, is_superset, is_subset, intersects, new_and_not_pred, not_new_and_pred)

    @classmethod
    def get_dropped_packets(cls, p):
        """For an arbitrary policy p, return the set of packets (as a filter
        policy) that are dropped by it.

        :param p: policy
        :type p: Policy
        """
        pol_classifier = cls.__get_classifier__(p)
        matched_packets = drop
        for rule in pol_classifier.rules:
            fwd_actions = filter(lambda a: (isinstance(a, modify)
                                         and a['port'] != OFPP_CONTROLLER),
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
    in_cg_list = []
    out_cg_list = []

    def __init__(self, switch_cnt = None, 
                    cache_enabled = False, partition_enabled = False):
        if switch_cnt is None or not partition_enabled:
            self.simple = True
        else:
            self.simple = False
        
        self.switch_cnt = switch_cnt
        self.cache_enabled = cache_enabled
    
        # Invariants: pred is always a leaf-level predicate in the re AST of some
        # path query.
        self.pred_to_symbol = {}
        self.pred_to_atoms  = {}
        self.symbol_to_pred = {}
        self.part_symbol_to_pred = {}
        self.pred_to_neg = {}
        self.dyn_preds      = []
        self.cache = {}
    
    @classmethod
    def global_sym_list(cls):
        res = []
        for cg in cls.in_cg_list + cls.out_cg_list:
            res.extend(cg.symbol_to_pred.keys())
        return res

    @classmethod
    def global_dyn_list(cls):
        res = []
        for cg in cls.in_cg_list + cls.out_cg_list:
            res.extend(cg.get_dyn_preds())
        return res

    class dyn_pred_obj(object):
        """ A dynamic predicate occuring as a sub-policy in a bigger predicate."""
        def __init__(self, pred, pol):
            self.pred = pred
            self.pol  = pol

        def __hash__(self):
            return id(self.pred) * id(self.pol)

        def __eq__(self, other):
            return (isinstance(other, re_tree_gen.dyn_pred_obj) and
                    id(self.pred) == id(other.pred) and
                    id(self.pol)  == id(other.pol))

    def repr_state(self):
        if self.simple:
            pred_to_symbol = [self.pred_to_symbol]
            pred_to_atoms = [self.pred_to_atoms]
        else:
            ''' based on the assumptions that: 
            If items(), keys(), values() are called with no intervening modifications 
            to the dictionary, the lists will directly correspond.'''
            pred_to_symbol = self.pred_to_symbol.values()
            pred_to_atoms = self.pred_to_symbol.values()
        
        output = ''
        for (pred_sym, pred_atom) in zip(pred_to_symbol, pred_to_atoms):
            assert (sorted(pred_sym.keys()) ==
                sorted(pred_atom.keys()))

            for pred in pred_sym:
                output += repr(pred) + ":\n"
                output += '  symbol: ' + repr(pred_sym[pred]) + '\n'
                try:
                    output += '  atoms: ' + repr(pred_atom[pred] ) + '\n'
                except:
                    pass

        return output

    
    def __add_pred__(self, pred, symbol, atoms, pred_neg, partition=None):
        """ Add a new predicate to the global state. """
        if self.simple:
            pred_to_sym = self.pred_to_symbol
            pred_to_atoms = self.pred_to_atoms
            pred_to_neg = self.pred_to_neg
            sym_to_pred = self.symbol_to_pred
        else:
            pred_to_sym = self.pred_to_symbol[partition]
            pred_to_atoms = self.pred_to_atoms[partition]
            pred_to_neg = self.pred_to_neg[partition]
            sym_to_pred = self.part_symbol_to_pred[partition]

        assert not pred in pred_to_sym
        assert not pred in pred_to_atoms
        assert not pred in pred_to_neg
        
        pred_to_sym[pred] = symbol
        sym_to_pred[symbol] = pred
        pred_to_atoms[pred] = atoms
        pred_to_neg[pred] = pred_neg

        if not self.simple:
            self.symbol_to_pred[symbol] = pred
    
    def __add_dyn_preds__(self, preds, atom_pol):
        """ Add each predicate in `preds` to list of dynamic predicates, with
        the corresponding `atom`. """
        for pred in preds:
            dyn_obj = self.dyn_pred_obj(pred, atom_pol)
            self.dyn_preds.append(dyn_obj)
    
    def __del_pred__(self, pred, partition=None):
        """ Remove a predicate from existing global state of leaf-level
        predicates. """
        
        if self.simple:
            pred_sym = self.pred_to_symbol
            pred_atoms = self.pred_to_atoms
            pred_neg = self.pred_to_neg
            sym_pred = self.symbol_to_pred
        else:
            pred_sym = self.pred_to_symbol[partition]
            pred_atoms = self.pred_to_atoms[partition]
            pred_neg = self.pred_to_neg[partition]
            sym_pred = self.part_symbol_to_pred[partition]

        symbol = pred_sym[pred]

        del pred_sym[pred]
        del sym_pred[symbol]
        del pred_atoms[pred]
        del pred_neg[pred]

        if not self.simple:
            del self.symbol_to_pred[symbol]

    def __new_token__(self):
        re_tree_gen.token += 2
        if re_tree_gen.token > TOKEN_END_VALUE:
            re_tree_gen.token = re_tree_gen.token_start

    def __new_symbol__(self):
        """ Returns a new token/symbol for a leaf-level predicate. """
        self.__new_token__()
        sym_list = re_tree_gen.global_sym_list()
        while re_tree_gen.token in sym_list:
            self.__new_token__()

        return re_tree_gen.token

    def __replace_pred__(self, old_pred, new_preds, partition=None):
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
       
        if self.simple:
            pred_sym = self.pred_to_symbol
            pred_atoms = self.pred_to_atoms
        else:
            pred_sym = self.pred_to_symbol[partition]
            pred_atoms = self.pred_to_atoms[partition]
 
        assert old_pred in pred_sym and old_pred in pred_atoms
        old_sym = pred_sym[old_pred]
        new_re_tree = re_empty()
        # Construct replacement tree (without metadata first)
        for pred in new_preds:
            assert pred in pred_sym
            assert pred in pred_atoms
            new_sym = pred_sym[pred]
            new_re_tree = new_re_tree | re_symbol(new_sym)
        # For each atom containing old_pred, replace re leaf by new tree.
        for at in pred_atoms[old_pred]:
            new_atom_re_tree = replace_node(at.gen_re_tree(self), new_re_tree, old_sym)
            at.re_tree = new_atom_re_tree # change the atom objects themselves!

    
    def get_re_tree(self, new_pred, at):
        assert isinstance(at, abstract_atom)
        assert isinstance(new_pred, Filter)
        
        def update_dicts(sym, at):
            if self.simple:
                symbol_to_pred = [self.symbol_to_pred]
                pred_to_atoms = [self.pred_to_atoms]
            else:
                symbol_to_pred = self.part_symbol_to_pred.values()
                pred_to_atoms = self.pred_to_atoms.values()
            
            ''' based on the assumptions that: 
            If items(), keys(), values() are called with no intervening modifications 
            to the dictionary, the lists will directly correspond.'''
            for (sym_pred, pred_atom) in zip(symbol_to_pred, pred_to_atoms):               
                if sym in sym_pred:
                    pred = sym_pred[sym]
                    pred_atom[pred].append(at)
                    break

        def create_re_tree(eq_re_tree, at):
            if isinstance(eq_re_tree, re_symbol):
                sym = eq_re_tree.char
                update_dicts(sym, at)
                return re_symbol(sym, metadata = at)
            elif isinstance(eq_re_tree, re_alter):
                res = re_empty()
                for sym in eq_re_tree.re_list:
                    res |= create_re_tree(sym, at)
                return res
            else:
                print type(eq_re_tree)
                raise TypeError
        
        if self.cache_enabled:
            if new_pred in self.cache:
                new_re_tree = create_re_tree(self.cache[new_pred].gen_re_tree(self), at)
                return new_re_tree

        if self.simple:
            re_tree = self.get_re_tree_core(new_pred, at)
        else:
            re_tree = re_empty()
            for i in range(1, self.switch_cnt + 1):
                part_pred = match(switch = i) & new_pred
                inters = classifier_utils.is_not_drop(part_pred)
                if inters:
                    res_tree = self.get_re_tree_core(part_pred, at, i)
                    if res_tree != re_empty():
                        re_tree |= res_tree
       
        if self.cache_enabled:
            self.cache[new_pred] = at
        elif len(self.cache) == 0 and new_pred == identity:
            self.cache[new_pred] = at

        return re_tree

    def get_re_tree_core(self, new_pred, at, partition=None):
        """ Deal with existing leaf-level predicates, taking different actions
        based on whether the existing predicates are equal, superset, subset, or
        just intersecting, the new predicate.
        """

        if self.simple:
            pred_to_symbol = self.pred_to_symbol
            pred_to_atoms = self.pred_to_atoms
            pred_to_neg = self.pred_to_neg
        else:
            pred_to_symbol = self.pred_to_symbol[partition]
            pred_to_atoms = self.pred_to_atoms[partition]
            pred_to_neg = self.pred_to_neg[partition]

        ne_inters   = classifier_utils.has_nonempty_intersection
        is_not_drop = classifier_utils.is_not_drop
        add_pred = self.__add_pred__
        new_sym  = self.__new_symbol__
        del_pred = self.__del_pred__
        replace_pred = self.__replace_pred__
        ovlap = classifier_utils.get_overlap_mode

        re_tree = re_empty()
        pred_list = pred_to_symbol.keys()

        """ Record dynamic predicates separately for update purposes."""
        dyn_pols = path_policy_utils.get_dyn_pols(new_pred)
        if dyn_pols:
            """ If new_pred contains a dynamic predicate, it must be remembered
            explicitly to set up recompilation routines in the runtime."""
            self.__add_dyn_preds__(dyn_pols, at.policy)
        new_pred_neg = ~new_pred

        """ For each case of overlap between new and existing predicates, do
        actions that will only retain and keep track of non-overlapping
        pieces. """
        for pred in pred_list:
            assert pred in pred_to_atoms
            pred_atoms = pred_to_atoms[pred]
            pred_symbol = pred_to_symbol[pred]
            pred_neg = pred_to_neg[pred]
            (is_equal,is_superset,is_subset,intersects, new_and_not_pred, not_new_and_pred) = ovlap(pred, pred_neg, new_pred, new_pred_neg)
            if not is_not_drop(new_pred):
                """ i.e., new_pred empty """
                re_tree |= re_empty()
                return re_tree
            if is_equal:
                pred_atoms.append(at)
                re_tree |= re_symbol(pred_symbol, metadata=at)
                return re_tree
            elif is_superset:
                inter = pred & new_pred_neg
                inter_neg = ~inter
                add_pred(pred & new_pred_neg, new_sym(), pred_atoms, inter_neg, partition)
                add_pred(new_pred, new_sym(), pred_atoms + [at], new_pred_neg, partition)
                replace_pred(pred, [inter, new_pred], partition)
                del_pred(pred, partition)
                added_sym = pred_to_symbol[new_pred]
                re_tree |= re_symbol(added_sym, metadata=at)
                return re_tree
            elif is_subset:
                new_pred = new_pred & pred_neg
                #new_pred_not_drop = new_and_not_pred
                new_pred_neg = ~new_pred
                pred_atoms.append(at)
                re_tree |= re_symbol(pred_symbol, metadata=at)
            elif intersects:
                inter = pred & new_pred_neg
                inter_neg = ~inter
                inter_p = pred & new_pred
                inter_p_neg = ~inter_p
                add_pred(inter, new_sym(), pred_atoms, inter_neg, partition)
                add_pred(inter_p, new_sym(), pred_atoms + [at], inter_p_neg, partition)
                replace_pred(pred, [inter, inter_p], partition)
                del_pred(pred, partition)
                added_sym = pred_to_symbol[inter_p]
                re_tree |= re_symbol(added_sym, metadata=at)
                new_pred = new_pred & pred_neg
                #new_pred_not_drop = new_and_not_pred
                new_pred_neg = ~new_pred
            else:
                pass
        if is_not_drop(new_pred):
            """ The new predicate should be added if some part of it doesn't
            intersect any existing predicate, i.e., new_pred is not drop.
            """
            add_pred(new_pred, new_sym(), [at], new_pred_neg, partition)
            added_sym = pred_to_symbol[new_pred]
            re_tree |= re_symbol(added_sym, metadata=at)
        
        return re_tree

    def clear(self):
        """ Completely reset character generating structures. """
        self.pred_to_atoms = {}
        self.pred_to_symbol = {}
        self.symbol_to_pred = {}
        self.pred_to_neg = {}
        self.dyn_preds = []
        self.cache = {}
        
        if not self.simple:
            self.part_symbol_to_pred = {}
            for i in range(1, self.switch_cnt + 1):
               self.pred_to_symbol[i] = {}
               self.pred_to_atoms[i] = {}
               self.part_symbol_to_pred[i] = {}
               self.pred_to_neg[i] = {}


    def get_symlist(self):
        """ Get a list of symbols which are leaf-level predicates """
        return self.symbol_to_pred.keys()

    def get_leaf_preds(self):
        """ Get a string representation of all leaf-level predicates in the
        structure. """
        output = ''
        for sym in self.symbol_to_pred:
            pred = self.symbol_to_pred[sym]
            output += (str(sym) + ': ' + repr(pred) + '\n')
        return output


    def get_dyn_preds(self):
        return self.dyn_preds

    def get_predlist(self):
        if self.simple:
            pred_to_symbol = [self.pred_to_symbol]
        else:
            pred_to_symbol = self.pred_to_symbol.values()

        res = []
        for pred_sym in pred_to_symbol:
            res.extend(pred_sym.keys())
        return res

    def get_unaffected_pred(self):
        """ Predicate that covers packets unaffected by query predicates. """
        pred_list = self.get_predlist()
        if len(pred_list) >= 1:
            return ~(reduce(lambda a,x: a | x, pred_list))
        else:
            return identity

""" Character generator classes belonging to "ingress" and "egress" matching
predicates, respectively. """
class __in_re_tree_gen__(re_tree_gen):
    """ Character generator for in_atom matches. """
    def __init__(self, switch_cnt = None, 
                    cache_enabled = False, partition_enabled = False):
        super(__in_re_tree_gen__, self).__init__(switch_cnt, cache_enabled,
                                                    partition_enabled)
        re_tree_gen.in_cg_list.append(self)
class __out_re_tree_gen__(re_tree_gen):
    """ Character generator for out_atom matches. """
    def __init__(self, switch_cnt = None, 
                    cache_enabled = False, partition_enabled = False):

        super(__out_re_tree_gen__, self).__init__(switch_cnt, cache_enabled,
                                                    partition_enabled)
        re_tree_gen.out_cg_list.append(self)


#############################################################################
###               Path query language components                          ###
#############################################################################

class path_policy(object):
    def __init__(self, p, q):
        """ Defines a "path policy" object, which is a combination of a path
        function (trajectory -> {pkt}), and a policy function (pkt -> {pkt}),
        used in sequential composition. The action of the path policy on the
        packet is written as

        p >> q

        which is a function that takes a trajectory as input, and produces a set
        of packets as output.

        :param p: a predicate on the trajectory of a packet
        :type p: path
        :param q: policy to apply after acceptance by path
        :type q: Policy
        """
        super(path_policy, self).__init__()
        self.path = p
        self.piped_policy = q

    def get_policy(self):
        return self.piped_policy

    def set_policy(self, pol):
        self.piped_policy = pol

    @property
    def expr(self):
        return self.path.expr

    def __repr_pretty__(self, pre_spaces=''):
        """ Pretty printing. """
        extra_ind = '    '
        out  = pre_spaces +'[path policy]\n'
        out += pre_spaces + extra_ind + repr(self.path) + '\n'
        out += pre_spaces + extra_ind + '>>>\n'
        out += '%s%s%s\n' % (pre_spaces, extra_ind, repr(self.piped_policy))
        return out

    def __repr__(self):
        return self.__repr_pretty__()

    def __add__(self, ppol):
        """ Implements the '+' operator for path policies, producing a
        collection of path predicates and corresponding piped policies."""
        assert isinstance(ppol, path_policy)
        if isinstance(ppol, path_policy_union):
            return ppol + self
        else:
            return path_policy_union([self, ppol])

    def __eq__(self, other):
        if isinstance(other, path_policy):
            return ((self.path == other.path) and
                    (self.piped_policy == other.piped_policy))
        else:
            return False

    def __hash__(self):
        return id(self)

class path_policy_union(path_policy):
    def __init__(self, ppols):
        """ Class that denotes a collection of path policies in an AST of '+'
        operators. """
        assert len(ppols) > 1
        self.path_policies = ppols
        for p in ppols:
            assert not isinstance(p, path_policy_union)
        super(path_policy_union, self).__init__(path_empty, drop)

    def __repr_pretty__(self, pre_spaces=''):
        extra_ind = '    '
        out  = pre_spaces + "[path policy union]\n"
        for ppol in self.path_policies:
            out += ppol.__repr_pretty__(pre_spaces + extra_ind)
        return out

    def __add__(self,ppols):
        if isinstance(ppols, path_policy_union):
            return path_policy_union(self.path_policies + ppols.path_policies)
        return path_policy_union(self.path_policies + [ppols])
    def __repr__(self):
        return self.__repr_pretty__()


class dynamic_path_policy(path_policy):
    def __init__(self, path_pol):
        """ Dynamic path object. The self.path_policy object denotes the
        internal representation of the path policy at any given point, similar
        to the self.policy of a DynamicPolicy."""
        self._path_policy = path_pol
        self.path_notify = None
        super(dynamic_path_policy, self).__init__(path_pol.path, path_pol.piped_policy)

    def __repr_pretty__(self, pre_spaces=''):
        extra_ind = '    '
        out  = pre_spaces + '[dynamic path policy]\n'
        out += pre_spaces + extra_ind
        out += self._path_policy.__repr_pretty__(pre_spaces + extra_ind)
        return out

    def __repr__(self):
        return self.__repr_pretty__()

    def path_attach(self, path_notify):
        """ Allows the runtime to attach a function that is notified whenever
        the path policy changes its internal policy. """
        self.path_notify = path_notify

    def path_detach(self):
        """ Detach the runtime notification function. """
        self.path_notify = None

    def path_changed(self):
        """ Function that is called whenever the internal representation of the
        path policy changes. """
        if self.path_notify:
            self.path_notify()

    @property
    def path_policy(self):
        return self._path_policy

    @path_policy.setter
    def path_policy(self, path_pol):
        self._path_policy = path_pol
        self.path_changed()


class path_policy_utils(object):
    """ Utilities to manipulate path policy ASTs. """
    @classmethod
    def path_policy_ast_fold(cls, ast, fold_f, acc, in_cg=None, out_cg=None):
        """ Fold the AST with a function fold_f, which also takes a default
        value.

        :param ast: path_policy
        :param fold_f: 'a -> path_policy -> 'a
        :param default: 'a
        """
        if isinstance(ast, path_policy_union):
            acc = fold_f(acc, ast, in_cg, out_cg)
            for pp in ast.path_policies:
                acc = cls.path_policy_ast_fold(pp, fold_f, acc, in_cg, out_cg)
            return acc
        elif isinstance(ast, dynamic_path_policy):
            acc = fold_f(acc, ast, in_cg, out_cg)
            return cls.path_policy_ast_fold(ast.path_policy, fold_f, acc, in_cg, out_cg)
        elif isinstance(ast, path_policy):
            return fold_f(acc, ast, in_cg, out_cg)
        else:
            print type(ast)
            raise TypeError("Can only fold path_policy objects!")

    @classmethod
    def path_ast_fold(cls, ast, fold_f, acc):
        """ Fold a path AST with a function fold_f, which also takes a default
        value.

        :param ast: path
        :param fold_f: 'a -> path -> 'a
        :param default: 'a
        """
        if (isinstance(ast, path_epsilon) or
            isinstance(ast, path_empty) or
            isinstance(ast, in_out_atom)):
            return fold_f(acc, ast)
        elif isinstance(ast, path_combinator):
            acc = fold_f(acc, ast)
            for p in ast.paths:
                acc = cls.path_ast_fold(p, fold_f, acc)
            return acc
        else:
            raise TypeError("Can only fold path objects!")

    @classmethod
    def path_ast_map(cls, ast, map_f):
        """ Apply a map function `map_f` to a path AST, returning a tree with
        the same structure.

        :param ast: path
        :param map_f: path -> path
        """
        if (isinstance(ast, path_epsilon) or
            isinstance(ast, path_empty) or
            isinstance(ast, in_out_atom)):
            return map_f(ast)
        elif isinstance(ast, path_combinator):
            res_paths = []
            for p in ast.paths:
                res_paths.append(cls.path_ast_map(p, map_f))
            comb_typ = type(ast)
            return map_f(comb_typ(res_paths))
        else:
            raise TypeError("Can only fold path objects!")

    @classmethod
    def get_dyn_pols(cls, p):
        """ Get the dynamic sub policies from a policy p. """
        return policy_ast_fold(add_dynamic_sub_pols, list(), p)

    @classmethod
    def add_dynamic_filters(cls, acc, at):
        """ Collect all DynamicFilters that are part of atoms in paths. """
        if isinstance(at, in_out_atom):
            p_in  = at.in_atom.policy
            p_out = at.out_atom.policy
            in_set = map(lambda x: (x, p_in), cls.get_dyn_pols(p_in))
            out_set = map(lambda x: (x, p_out), cls.get_dyn_pols(p_out))
            return acc | set(in_set) | set(out_set)
        elif isinstance(at, path):
            return acc
        else:
            raise TypeError("Can only operate on path objects!")

    @classmethod
    def add_dynamic_path_pols(cls, acc, pp, in_cg, out_cg):
        """ Fold function that can be used to get all dynamic sub path policies
        from a path policy pp. """
        if isinstance(pp, dynamic_path_policy):
            return acc | set([pp])
        elif isinstance(pp, path_policy_union):
            return acc
        elif isinstance(pp, path_policy):
            return acc
        else:
            raise TypeError("Can only act on path_policy objects!")


class path(path_policy):
    MEASURE_LOC_UPSTREAM = 1
    MEASURE_LOC_DOWNSTREAM = 2

    def __init__(self):
        """A way to select packets or count traffic volumes satisfying regular
        expressions denoting paths of located packets.

        :param a: path atom used to construct this path element
        :type atom: atom
        """
        super(path, self).__init__(self, FwdBucket())
        self.measure_loc = path.MEASURE_LOC_DOWNSTREAM

    @property
    def expr(self):
        """ The self.expr of a path object denotes its string representation
        constructed from the AST of predicate symbols. """
        return self.re_tree.re_string_repr()

    def get_bucket(self):
        """ Get the bucket associated with a path object, which is its default
        piped policy as part of the path policy. """
        return self.get_policy()

    def set_bucket(self, bucket):
        """ Set the bucket associated with the path. """
        self.set_policy(bucket)

    def register_callback(self, f):
        self.get_policy().register_callback(f)

    def __repr__(self):
        return '[path expr: ' + self.expr + ' id: ' + str(id(self)) + ']'

    def __xor__(self, other):
        """Implementation of the path concatenation operator ('^')"""
        assert isinstance(other, path)
        return path_concat.smart_concat([self, other])

    def __pow__(self, other):
        """ Implementation of the 'concatenate anytime later' operator ('**').

        x ** y is just a shorthand for x ^ identity* ^ y.
        """
        assert isinstance(other, path)
        return path_concat.smart_concat([self, +in_atom(identity), other])

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

    def measure_upstream(self):
        """ Instruct the runtime to measure packets satisfying this query
        upstream. """
        self.measure_loc = path.MEASURE_LOC_UPSTREAM

    def measure_downstream(self):
        """ Instruct the runtime to measure packets satisfying this query
        upstream. """
        self.measure_loc = path.MEASURE_LOC_DOWNSTREAM

class path_epsilon(path):
    """ Path of length 0. """
    def __init__(self):
        self.re_tree = re_epsilon()
        super(path_epsilon, self).__init__()

    def __eq__(self, other):
        if isinstance(other, path_epsilon):
            return True
        else:
            return False

    def __repr__(self):
        return "path_epsilon"


class path_empty(path):
    """ Empty path object. """
    def __init__(self):
        self.re_tree = re_empty()
        super(path_empty, self).__init__()

    def __eq__(self, other):
        if isinstance(other, path_empty):
            return True
        else:
            return False

    def __repr__(self):
        return "path_empty"

    def gen_re_tree(self, in_cg, out_cg):
        return re_empty()


class abstract_atom(object):
    """A single atomic match in a path expression. This is an abstract class
    where the token isn't initialized.

    :param m: a Filter (or match) object used to initialize the path atom.
    :type match: Filter
    """
    def __init__(self, m, re_tree_class=re_tree_gen):
        assert isinstance(m, Filter)
        self.policy = m
        self._re_tree = None
        self.tree_counter = 0 # diagnostic; counts each time re_tree is set
        self.re_tree_class = re_tree_class

    def gen_re_tree(self, cg):
        """ The internal representation of an abstract atom in terms of the
        constituent leaf-level predicates. """
        if not self._re_tree:
            self.tree_counter += 1
            self._re_tree = cg.get_re_tree(self.policy, self)
            assert self.tree_counter <= 1
        return self._re_tree

    @property
    def re_tree(self):
        return self._re_tree

    @re_tree.setter
    def re_tree(self, rt):
        self._re_tree = rt
        self.tree_counter += 1

    def invalidate_re_tree(self):
        """ Invalidate the internal representation in terms of regular
        expressions, for example, during recompilation. """
        self._re_tree = None
        self.tree_counter = 0

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.policy == other.policy)

    def __repr__(self):
        return repr(self.policy) + '; expression: ' + self.expr

    @property
    def expr(self):
        return self.re_tree.re_string_repr()


class __in__(abstract_atom):
    """ Atom type that only matches a predicate at the entry of a switch. """
    def __init__(self, m):
        super(__in__, self).__init__(m, re_tree_class=__in_re_tree_gen__)

class __out__(abstract_atom):
    """ Atom type that only matches a predicate at the exit of a switch. """
    def __init__(self, m):
        super(__out__, self).__init__(m, re_tree_class=__out_re_tree_gen__)


class in_out_atom(path):
    """ The leaf atom for all path queries. """
    def __init__(self, in_pred, out_pred):
        self.in_pred  = in_pred
        self.out_pred = out_pred
        self.in_atom  = __in__(in_pred)
        self.out_atom = __out__(out_pred)
        self._re_tree = None
        super(in_out_atom, self).__init__()

    def gen_re_tree(self, in_cg, out_cg):
        self._re_tree = (self.in_atom.gen_re_tree(in_cg) ^
                         self.out_atom.gen_re_tree(out_cg))
        return self._re_tree

    def invalidate_re_tree(self):
        self.in_atom.invalidate_re_tree()
        self.out_atom.invalidate_re_tree()

    def __eq__(self, other):
        return (isinstance(other, in_out_atom) and
                self.in_pred == other.in_pred and
                self.out_pred == other.out_pred)

    def __repr__(self):
        return "\tin:\n\t%s\n\tout:\n\t%s\n\texpr:%s" % (repr(self.in_pred),
                                             repr(self.out_pred),
                                             self.expr)

    @property
    def re_tree(self):
        return self._re_tree if self._re_tree else re_empty()

    @re_tree.setter
    def re_tree(self, rt):
        self._re_tree = rt
        self.tree_counter += 1

class in_atom(in_out_atom):
    def __init__(self, m):
        super(in_atom, self).__init__(m, identity)

class out_atom(in_out_atom):
    def __init__(self, m):
        super(out_atom, self).__init__(identity, m)

class atom(in_atom):
    """A concrete "ingress" match atom."""
    def __init__(self, m):
        super(atom, self).__init__(m)

class in_out_group(in_out_atom):
    """A hook is essentially like an atom, but has a notion of "grouping"
    associated with it. Whenever a packet arrives into this hook, we group them
    by the values of the fields specified in the groupby=... argument of the
    constructor.
    """
    def __init__(self, in_pred, out_pred, in_groupby=[], out_groupby=[]):
        self.in_groupby = sorted(in_groupby)
        self.out_groupby = sorted(out_groupby)
        super(in_out_group, self).__init__(in_pred, out_pred)

    def substitute(self, in_group_val, out_group_val):
        """ Return a new in_out_atom with in_group_val and out_group_val
        substituted for the headers in in_groupby and out_groupby. """
        assert set(in_group_val.keys()) == set(self.in_groupby)
        assert set(out_group_val.keys()) == set(self.out_groupby)
        in_match = identity if not in_group_val else match(**in_group_val)
        out_match = identity if not out_group_val else match(**out_group_val)
        if (classifier_utils.is_not_drop(in_match & self.in_pred) and
            classifier_utils.is_not_drop(out_match & self.out_pred)):
            return in_out_atom(self.in_pred & in_match,
                               self.out_pred & out_match)
        else:
            return None

    def __repr__(self):
        return (super(in_out_group, self).__repr__() + ';\n' +
                'in_grouping:' + str(self.in_groupby) + '\n' +
                'out_grouping:' + str(self.out_groupby) + '\n')

class in_group(in_out_group):
    def __init__(self, pred, groupby=[]):
        super(in_group, self).__init__(pred, identity, groupby, [])

class out_group(in_out_group):
    def __init__(self, pred, groupby=[]):
        super(out_group, self).__init__(identity, pred, [], groupby)

### Path combinator classes ###

class path_combinator(path):
    """ Base class for all path combinators. """
    def __init__(self, paths=None):
        self.paths = paths
        super(path_combinator, self).__init__()

    def __eq__(self, other):
        return (type(self) == type(other) and
                reduce(lambda acc, (x,y): acc and x == y,
                       zip(self.paths, other.paths),
                       True))

    def __repr_pretty__(self, pre_spaces=''):
        extra_ind = '    '
        def get_repr(x):
            try:
                return x.__repr_pretty__(pre_spaces + extra_ind)
            except AttributeError:
                return pre_spaces + extra_ind + repr(x)
        repr_paths = map(get_repr, self.paths)
        return "%s%s:\n%s" % (pre_spaces, self.__class__.__name__, '\n'.join(repr_paths))

    def __repr__(self):
        return self.__repr_pretty__()


class path_alternate(path_combinator):
    """ Alternation of paths. """
    def __init__(self, paths_list):
        self.__check_type(paths_list)
        super(path_alternate, self).__init__(paths=paths_list)

    def __check_type(self, paths):
        for p in paths:
            assert isinstance(p, path)

    def gen_re_tree(self, in_cg, out_cg):
        tree = re_empty()
        for p in self.paths:
            tree = tree | p.gen_re_tree(in_cg, out_cg)
        return tree


class path_star(path_combinator):
    """ Kleene star on a path. """
    def __init__(self, p):
        self.__check_type(p)
        super(path_star, self).__init__(paths=(p if isinstance(p, list) else [p]))

    def __check_type(self, p):
        assert ((isinstance(p, list) and len(p) == 1 and isinstance(p[0], path))
                or isinstance(p, path))

    def gen_re_tree(self, in_cg, out_cg):
        p = self.paths[0]
        return +(p.gen_re_tree(in_cg, out_cg))


class path_concat(path_combinator):
    """ Concatenation of paths. """
    def __init__(self, paths_list):
        self.__check_type(paths_list)
        super(path_concat, self).__init__(paths=paths_list)

    def __check_type(self, paths):
        for p in paths:
            assert isinstance(p, path)

    @classmethod
    def smart_concat(cls, paths):
        """ Perform "smart concatenation" to maintain more compact path ASTs."""
        new_paths = []
        for p in paths:
            if not isinstance(p, path_epsilon):
                if not isinstance(p, path_concat):
                    new_paths.append(p)
                else:
                    new_paths += p.paths
        if len(new_paths) > 1:
            return path_concat(new_paths)
        elif len(new_paths) == 1:
            return new_paths[0]
        else:
            return path_epsilon()

    def gen_re_tree(self, in_cg, out_cg):
        tree = re_epsilon()
        for p in self.paths:
            tree = tree ^ p.gen_re_tree(in_cg, out_cg)
        return tree


class path_negate(path_combinator):
    """ Negation of paths. """
    def __init__(self, p):
        self.__check_type(p)
        super(path_negate, self).__init__(paths=(p if isinstance(p, list) else [p]))

    def __check_type(self, p):
        assert ((isinstance(p, list) and len(p) == 1 and isinstance(p[0], path))
                or isinstance(p, path))

    def gen_re_tree(self, in_cg, out_cg):
        p = self.paths[0]
        return ~(p.gen_re_tree(in_cg, out_cg))


class path_inters(path_combinator):
    """ Intersection of paths. """
    def __init__(self, paths_list):
        self.__check_type(paths_list)
        super(path_inters, self).__init__(paths=paths_list)

    def __check_type(self, paths):
        for p in paths:
            assert isinstance(p, path)

    def gen_re_tree(self, in_cg, out_cg):
        tree = ~re_empty()
        for p in self.paths:
            tree = tree & p.gen_re_tree(in_cg, out_cg)
        return tree

#############################################################################
###                      Optimizations                                    ###
#############################################################################

class QuerySwitch(Policy):

    def __init__(self, tag, policy_dic, default):
        #TODO (mina): add type checks

        self.tag = tag
        self.policy_dic = policy_dic
        self.default = default

    def eval(self, pkt):
        from pyretic.core.language import _match
        def eval_defaults(pkt):
            res = set()
            for act in self.default:
                res |= act.eval(pkt)
            return res

        for tag_value in self.policy_dic:
            match_pol = match(**{self.tag:tag_value})
            res = match_pol.eval(pkt)
            if res:
                pol_res = self.policy_dic[tag_value].eval(pkt)
                if not pol_res:
                    pol_res = eval_defaults(pkt)
                
                return pol_res
        
        return eval_defaults(pkt)
    
    def compile(self):
        from pyretic.core.classifier import Rule, Classifier
        def resolve_virtual_fields(act):
            try:
                if isinstance(act, modify):
                    r = act.compile().rules[0]
                    (mod_act,) =  r.actions
                    return mod_act
                if isinstance(act, match):
                    return act.compile().rules[0].match
                
                return act
            except:
                return act
            

        
        comp_defaults = set(map(resolve_virtual_fields, self.default))
        final_rules = []
        for tag_value in self.policy_dic:
            p_rules = self.policy_dic[tag_value].compile().rules
            for r in p_rules:
                new_match = r.match.intersect(match(**{self.tag : tag_value}))
                new_match = new_match.compile().rules[0].match
                if new_match == drop:
                    raise TypeError
                new_r = copy.copy(r)
                new_r.match = new_match
                if not new_r.actions:
                    new_r.actions = comp_defaults
                new_r.parents = [r]
                new_r.op = "switch"
                final_rules.append(new_r)

        final_rules.append(Rule(identity, comp_defaults, [self], "switch"))
        c = Classifier(final_rules)
        return c
    
    def netkat_compile(self, switch_cnt, multistage=True):
        from pyretic.core.classifier import Rule, Classifier
        import time
        tot_time = 0
        t_s = time.time()
        def resolve_virtual_fields(act):
            try:
                if isinstance(act, modify):
                    r = act.compile().rules[0]
                    (mod_act,) =  r.actions
                    return mod_act
                if isinstance(act, match):
                    return act.compile().rules[0].match
                
                return act
            except:
                return act
            

        
        comp_defaults = set(map(resolve_virtual_fields, self.default))
        final_rules = []
        for tag_value in self.policy_dic:
            tot_time += time.time() - t_s
            p_class = self.policy_dic[tag_value].netkat_compile(switch_cnt, multistage)
            p_rules = p_class[0].rules
            tot_time += float(p_class[1])
            t_s = time.time()
            for r in p_rules:
                new_match = r.match.intersect(match(**{self.tag : tag_value}))
                new_match = new_match.compile().rules[0].match
                if new_match == drop:
                    raise TypeError
                new_r = copy.copy(r)
                new_r.match = new_match
                if not new_r.actions:
                    new_r.actions = comp_defaults
                new_r.parents = [r]
                new_r.op = "switch"
                final_rules.append(new_r)

        final_rules.append(Rule(identity, comp_defaults, [self], "switch"))
        c = Classifier(final_rules)
        tot_time += time.time() - t_s
        return (c, str(tot_time))

    def __repr__(self):
        res = ''
        res +=  '----------------------------\n'
        res +=  str(self.tag) + '\n'
        res +=  str(self.default) + '\n'
        for tag, value in self.policy_dic.items():
            res += str(tag) + "----is---> " + str(value) + '\n'

        res +=  '----------------------------\n'
        return res

    def __eq__(self, other):
        return (isinstance(other, QuerySwitch) and self.tag == other.tag
                and self.policy_dic == other.policy_dic
                and self.default == other.default)
#############################################################################
###                      Path query compilation                           ###
#############################################################################

class path_grouping(object):
    """Expand queries with grouping atoms into ones without grouping atoms,
    using static lists of values for each field that may be in a groupby path
    atom. For instance,

        in_group(match(port=2), ['switch'])
        -> [in_atom(match(switch=1, port=2)),
            in_atom(match(switch=2, port=2)),
            ...
           ]

    Further, each combination of such atoms is represented as a unique
    query. For instance,

    in_group(ingress_network(),['switch']) ** out_group(egress_network(),['switch'])

    is expanded out to include one query for each combination of (ingress,
    egress) switches in the network. This pass by the compiler precedes regular
    compilation by methods in the `pathcomp` class.
    """
    @classmethod
    def list_isinstance(cls, l, typ):
        return reduce(lambda acc, x: acc and isinstance(item, typ), l, True)

    @classmethod
    def groupby_collect(cls, acc, ast):
        assert isinstance(ast, path)
        if isinstance(ast, in_out_group):
            return acc | set([ast])
        else:
            return acc

    @classmethod
    def map_substitute_groupby(cls, vals):
        def actual_mapper(ast):
            assert isinstance(ast, path)
            if isinstance(ast, in_out_group):
                try:
                    val = vals[id(ast)]
                except KeyError:
                    raise RuntimeError("Substitution vals has no "
                                       "substitution for current AST: %s" % repr(ast))
                return vals[id(ast)]
            else:
                return ast
        return actual_mapper

    @classmethod
    def flist_vlist_combos(cls, flist, fvlist):
        """Given a field list `flist`, and a dictionary `fvlist` of field -> [list
        values], generate all combinations of values of the fields as a list of
        lists, where each internal list is the list of values of fields in
        `flist` in the same order as `flist`.
        """
        if len(flist) == 0:
            return []
        else:
            res = []
            for first_val in fvlist[flist[0]]:
                tail_vals = cls.flist_vlist_combos(flist[1:], fvlist)
                if tail_vals:
                    for tail_val in tail_vals:
                        res.append([first_val] + tail_val)
                else:
                    res.append([first_val])
            return res

    @classmethod
    def gen_groupby_substitutes(cls, gatom, fvlist):
        """Given a group atom, generate all possible field combinations this
        grouping atom can take, as a list of dictionaries. Also ensure that the
        field combination results in non-empty matches when substituted into the
        in_out_group.
        """
        assert isinstance(gatom, in_out_group)
        ingby, outgby = gatom.in_groupby, gatom.out_groupby
        inlist = cls.flist_vlist_combos(ingby, fvlist)
        outlist = cls.flist_vlist_combos(outgby, fvlist)
        res = []
        for inl in inlist:
            for outl in outlist:
                res.append(gatom.substitute(
                    {f:v for (f,v) in zip(ingby,  inl)},
                    {f:v for (f,v) in zip(outgby, outl)}))
        return filter(lambda x: not x is None, res)

    @classmethod
    def gatom_to_ioatom_combos(cls, galist, fvlist):
        assert list_isinstance(galist, in_out_group)
        ga_subst_map = {id(gatom): cls.gen_groupby_substitutes(gatom, fvlist)
                        for gatom in galist}
        id_sorted_gatoms = sorted(map(id, galist))
        combos = cls.flist_vlist_combos(id_sorted_gatoms,
                                        ga_subst_map)
        res = []
        for atom_combo in combos:
            res.append({f:v for (f,v) in zip(id_sorted_gatoms, atom_combo)})
        return res

    @classmethod
    def expand_groupby(cls, path_pol, fvlist):
        """ Statically substitute groupby atoms in queries by query predicates
        that have 'complete' values, e.g.,:

        in_group(match(port=2), ['switch'])
        -> [in_atom(match(switch=1, port=2)),
            in_atom(match(switch=2, port=2)),
            ...
           ]

        Currently, only the switch and port fields are statically replaced in
        grouping atoms, as it's too expensive to pre-compute all destination
        IPs, etc. Instead, applications should use a sampling bucket to collect
        per-header-aggregate statistics.
        """
        ppu = path_policy_utils
        ppols_list = []
        if isinstance(path_pol, path_policy_union):
            ppols_list = path_pol.path_policies
        elif isinstance(path_pol, path_policy):
            ppols_list = [path_pol]
        else:
            raise TypeError("cannot expand groupby from non-path-policies!")
        res_ppols = []
        for p in ppols_list:
            gatm_list = ppu.path_ast_fold(p, cls.groupby_collect, set())
            gid_to_atoms = cls.gatom_to_ioatom_combos(gatm_list, fvlist)
            for mapping in gid_to_atoms:
                sub_mapper = cls.map_substitute_groupby(mapping)
                new_query = ppu.path_ast_map(p, sub_mapper)
                # TODO(ngsrinivas): must add a way to recover results
                # separately for each sub-aggregate query
                res_ppols.append(new_query)
        return res_ppols

class pathcomp(object):
    """ Functionality related to actual compilation of path queries. """
    log = logging.getLogger('%s.pathcomp' % __name__)
    log.setLevel(logging.ERROR)

    @classmethod
    def __num_set_tag__(cls, num):
        if num == 0:
            return modify(path_tag=None)
        else:
            return modify(path_tag=num)

    @classmethod
    def __num_match_tag__(cls, num):
        if num == 0:
            return match(path_tag=None)
        else:
            return match(path_tag=num)

    @classmethod
    def __get_dead_state_pred__(cls, du, dfa):
        dead = du.get_dead_state(dfa)
        if dead:
            return cls.__num_match_tag__(dead)
        else:
            return drop

    @classmethod
    def __set_dead_state_tag__(cls, du, dfa):
        dead = du.get_dead_state(dfa)
        if dead:
            return cls.__num_set_tag__(dead)
        else:
            return identity

    @classmethod
    def __invalidate_re_trees__(cls, acc, p, in_cg, out_cg):
        """ Invalidate the re_tree values for all abstract atoms in the given
        path policy p. """
        def inv_atoms(acc, x):
            if isinstance(x, in_out_atom):
                x.invalidate_re_tree()
            return None
        if (isinstance(p, path_policy) and
            not isinstance(p, dynamic_path_policy) and
            not isinstance(p, path_policy_union)):
            path_policy_utils.path_ast_fold(p.path, inv_atoms, None)
            return None
        elif isinstance(p, path_policy):
            return None
        else:
            raise TypeError("Expecting a path_policy")

    @classmethod
    def __prep_re_trees__(cls, acc, p, in_cg, out_cg):
        """ Access re_trees of constituent path policies to help generate DFA
        later on. """
        if (isinstance(p, path_policy) and
            not isinstance(p, dynamic_path_policy) and
            not isinstance(p, path_policy_union)):
            tree = p.path.gen_re_tree(in_cg, out_cg)
            return None
        elif isinstance(p, path_policy):
            return None
        else:
            raise TypeError("Can't prep re_tree for non-path-policy!")

    @classmethod
    def __get_re_pols__(cls, acc, p, in_cg, out_cg):
        """ A reduce lambda which extracts an re and a policy to go with the re,
        from the AST of paths. """
        (re_acc, pol_acc) = acc
        """ Skip re extraction for all but the leaves of the path policy ast. """
        if isinstance(p, dynamic_path_policy):
            return acc
        elif isinstance(p, path_policy_union):
            return acc
        elif isinstance(p, path_policy):
            """ Reached a leaf """
            tree = p.path.gen_re_tree(in_cg, out_cg)
            piped_pol = p.piped_policy
            return (re_acc + [tree], pol_acc + [piped_pol])
        else:
            raise TypeError("Can't get re_pols from non-path-policy!")

    @classmethod
    def init(cls, numvals, switch_cnt = None, cache_enabled = False,
            edge_contraction_enabled = False, partition_enabled = False):
        
        """ Initialize path-related structures, namely:
        - a new virtual field for path tag;
        - in and out character generators.
        """
        virtual_field(name="path_tag",
                      values=range(0, numvals),
                      type="integer")
       
        
        cls.swich_cnt = switch_cnt
        cls.cache_enabled = cache_enabled
        cls.partition_enabled = partition_enabled
        cls.edge_contraction_enabled = edge_contraction_enabled
    
    @classmethod
    @Stat.elapsed_time
    def pred_part(cls, path_pol, in_cg, out_cg):
        ast_fold = path_policy_utils.path_policy_ast_fold
        prep_trees = cls.__prep_re_trees__
        ast_fold(path_pol, prep_trees, None, in_cg, out_cg)

    @classmethod
    def get_directional_pathpol(cls, path_pol, dirn):
            is_dir_q = lambda pp: (pp.path.measure_loc == dirn)
            if isinstance(path_pol, path_policy_union):
                query_list = filter(is_dir_q, path_pol.path_policies)
            else:
                query_list = [path_pol] if is_dir_q(path_pol) else []
            if len(query_list) > 1:
                return path_policy_union(query_list)
            elif len(query_list) == 1:
                return query_list[0]
            else:
                return path_empty()

    @classmethod
    def compile_upstream(cls, path_pol, switch_ports, network_links, fwding,
                         max_states=65000, disjoint_enabled=False,
                         default_enabled=False, integrate_enabled=False,
                         ragel_enabled=False, match_enabled=False):
        """ Generates a policy corresponding to upstream path queries. """
        from pyretic.lib.hsa import (pyr_hs_format, get_hsa_edge_policy,
                                     setup_tfs_data, get_portid_map,
                                     get_hsa_edge_ports,
                                     get_reachable_inheaders)
        sw_ports = {k:v for (k,v) in switch_ports}
        hs_format = pyr_hs_format()
        edge_pol = get_hsa_edge_policy(sw_ports, network_links)
        vin_tagging = ((edge_pol >> modify(path_tag=None)) + ~edge_pol)
        in_cg = __in_re_tree_gen__(cls.swich_cnt, cls.cache_enabled,
                                   cls.partition_enabled)
        out_cg = __out_re_tree_gen__(cls.swich_cnt, cls.cache_enabled,
                                     cls.partition_enabled)

        ''' Downstream compilation to get full policy to test. '''
        (comp_res, acc_pols) = cls.compile_stage(path_pol, in_cg, out_cg,
                                                 max_states, disjoint_enabled,
                                                 default_enabled,
                                                 True,
                                                 ragel_enabled, match_enabled)
        (in_table_pol, out_table_pol) = comp_res
        pol = (vin_tagging >>
               in_table_pol >>
               fwding >>
               out_table_pol)

        ''' Set up headerspace reachability preliminaries '''
        setup_tfs_data(hs_format, pol, sw_ports, network_links)
        portids = get_portid_map(sw_ports)
        edge_ports = get_hsa_edge_ports(sw_ports, network_links)

        ''' Run reachability and construct upstream measurement policy. '''
        up_capture = drop
        reach_filter = get_reachable_inheaders
        from pyretic.core.language import parallel
        for (sw,ports) in edge_ports.iteritems():
            for p in ports:
                for (accstate, pol_list) in acc_pols.iteritems():
                    res_filter = reach_filter(hs_format, portids, sw_ports,
                                              sw, p,
                                              match(path_tag=accstate),
                                              no_vlan=True)
                    res_filter = res_filter & match(switch=sw,port=p)
                    if up_capture == drop:
                        up_capture = res_filter >> parallel(pol_list)
                    else:
                        up_capture += (res_filter >> parallel(pol_list))
        return up_capture

    @classmethod
    def compile_downstream(cls, path_pol, max_states=65000,
                           disjoint_enabled=False, default_enabled=False,
                           integrate_enabled=False, ragel_enabled=False,
                           match_enabled=False):
        if isinstance(path_pol, path_policy_union):
            query_list = path_pol.path_policies
        else:
            query_list = [path_pol]

        # TODO(ngsrinivas): revert to rule limited query-packing after testing
        # stages = pack_queries(query_list, 2000)
        if not isinstance(path_pol, path_empty):
            stages = pack_queries_stagelimited(query_list, 1)
        else:
            stages = {0: [path_pol]}
        
        in_res = []
        out_res = []
        cls.log.debug("Stages: %d" % len(stages))
        for stage in stages.values():
            in_cg = __in_re_tree_gen__(cls.swich_cnt, cls.cache_enabled, cls.partition_enabled)
            out_cg = __out_re_tree_gen__(cls.swich_cnt, cls.cache_enabled, cls.partition_enabled)

            if len(stage) == 1:
                stage_path_pol = stage[0]
            else:
                stage_path_pol = path_policy_union(stage)

            (compile_res, _) = cls.compile_stage(stage_path_pol, in_cg, out_cg,
                                                 max_states, disjoint_enabled,
                                                 default_enabled, integrate_enabled,
                                                 ragel_enabled, match_enabled)
            sep_index = len(compile_res) / 2
            in_part = compile_res[:sep_index]
            out_part = compile_res[sep_index:]
            in_res.append(in_part if len(in_part) != 1 else in_part[0])
            out_res.append(out_part if len(out_part) != 1 else out_part[0])
        
        return (in_res, out_res)
    
    @classmethod
    @Stat.elapsed_time
    def compile_stage(cls, path_pol, in_cg, out_cg, max_states=65000, 
            disjoint_enabled=False, default_enabled = False, 
            integrate_enabled=False, ragel_enabled = False, match_enabled = False):
        """ Compile the list of paths along with the forwarding policy `fwding`
        into a single classifier to be installed on switches.
        """
        
        classifier_utils.__set_init_vars__(match_enabled)

        ast_fold = path_policy_utils.path_policy_ast_fold
        re_pols  = cls.__get_re_pols__
        inv_trees = cls.__invalidate_re_trees__
        prep_trees = cls.__prep_re_trees__

        
        in_cg.clear()
        out_cg.clear()
        ast_fold(path_pol, inv_trees, None, in_cg, out_cg)
        
        cls.log.debug('pred_part started')
        cls.pred_part(path_pol, in_cg, out_cg)        

        (re_list, pol_list) =  ast_fold(path_pol, re_pols, ([], []), in_cg, out_cg)
        cls.log.debug('compiling')
        res = cls.compile_core(re_list, pol_list, in_cg, out_cg, max_states, 
                                disjoint_enabled, default_enabled, 
                                integrate_enabled, ragel_enabled)
        return res

    @classmethod
    @Stat.elapsed_time
    def add_query(cls, path_pol, max_states = 65000, disjoint_enabled = False, default_enabled = False, 
            integrate_enabled = False, ragel_enabled = False, match_enabled = False):
        
        classifier_utils.__set_init_vars__(match_enabled)

        ast_fold = path_policy_utils.path_policy_ast_fold
        re_pols  = cls.__get_re_pols__
        inv_trees = cls.__invalidate_re_trees__
        prep_trees = cls.__prep_re_trees__

        ast_fold(path_pol, inv_trees, None, in_cg, out_cg)
        
        cls.pred_part(path_pol)

        cls.path_policy += path_pol
        (re_list, pol_list) = ast_fold(cls.path_policy, re_pols, ([], []),
                                       in_cg, out_cg)

        return cls.compile_core(re_list, pol_list, in_cg, out_cg, max_states,
                                disjoint_enabled, default_enabled,
                                integrate_enabled, ragel_enabled)

    @classmethod
    def ast_node_cnt(cls, pol):
        if (pol == identity or
                pol == drop or
                isinstance(pol, match) or
                isinstance(pol,modify) or
                pol == Controller or
                isinstance(pol, Query)):
            return 1
        elif isinstance(pol, CombinatorPolicy):
            s = 1
            for p in pol.policies:
                s += cls.ast_node_cnt(p)
            return s
        elif isinstance(pol, QuerySwitch):
            s = 1
            for tag, p in pol.policy_dic.items():
                s += cls.ast_node_cnt(p)
            s += 1
            for p in pol.default:
                s += cls.ast_node_cnt(p)
            return s
        else:
            raise TypeError

    @classmethod
    @Stat.collects([('dfa', [], True), ('dfa_utils', [], True), 
                    ('pred_in_list', [], True), ('pred_out_list', [], True)])
    def compile_core(cls, re_list, pol_list, in_cg, out_cg, max_states,
                     disjoint_enabled, default_enabled,
                     integrate_enabled, ragel_enabled):

        default_link = default_enabled
       
        du = common_dfa_utils
        
        in_tag_rules = 0
        in_cap_rules = 0

        out_tag_rules = 0
        out_cap_rules = 0
       
        in_tagging = None
        out_tagging = None
        in_capture = None
        out_capture = None

        match_tag = cls.__num_match_tag__
        set_tag   = cls.__num_set_tag__

        get_edge_attributes = None

        if ragel_enabled:
            ragel_dfa_utils.init(in_cg, out_cg, cls.edge_contraction_enabled)
            du = ragel_dfa_utils
        else:
            dfa_utils.init(in_cg, out_cg)
            du = dfa_utils

        dfa = du.regexes_to_dfa(re_list)
        assert du.get_num_states(dfa) <= max_states
        

        Stat.collect_stat('dfa', dfa)
        Stat.collect_stat('dfa_utils', du)
        Stat.collect_stat('pred_in_list', in_cg.symbol_to_pred)
        Stat.collect_stat('pred_out_list', out_cg.symbol_to_pred)

        edges = du.get_edges(dfa)
        get_edge_attributes = du.get_edge_attributes

        in_edge_per_state = {}
        out_edge_per_state = {}
        in_pred_classifier = {}
        out_pred_classifier = {}

        ''' Construct a map from DFA accepting states to policies that should
        process packets. Useful for upstream queries. '''
        accstates_to_pols = {}
        for edge in edges:
            (_, _, dst, dst_num, _, _) = get_edge_attributes(dfa, edge)
            if du.is_accepting(dfa, dst):
                ords = du.get_accepting_exps(dfa, edge, dst)
                accstates_to_pols[dst_num] = [pol_list[i] for i in ords]

        if disjoint_enabled:
            
            if integrate_enabled:
                in_table_dic = {}
                out_table_dic = {}

                for edge in edges:
                    (src, src_num, dst, dst_num, pred, typ) = get_edge_attributes(dfa, edge)
                   
                    assert typ in [__in__, __out__]
                    action_frag = None
                    
                    if_pred = not du.is_dead(dfa, src)
                    if default_link:
                        if_pred = if_pred and not du.is_dead(dfa, dst)

                    if if_pred:
                                                
                        action_frag = set_tag(dst_num)

                        ### statistics ###
                        if typ == __in__:
                            in_tag_rules += 1
                        else:
                            out_tag_rules += 1
                        ################

                    if du.is_accepting(dfa, dst):
                        ords = du.get_accepting_exps(dfa, edge, dst)
                        for i in ords:
                            if action_frag is None:
                                action_frag = pol_list[i]
                            else:
                                action_frag += pol_list[i]
                           
                            ### statisitcs ###
                            if typ == __in__:
                                in_cap_rules += 1
                            else:
                                out_cap_rules += 1
                            ################
                    
                    if action_frag is not None:
                        table_frag = pred >> action_frag
                        if typ == __in__:
                            if not src_num in in_table_dic:
                                in_table_dic[src_num] = table_frag
                            else:
                                in_table_dic[src_num] += table_frag

                        elif typ == __out__:
                            if not src_num in out_table_dic:
                                out_table_dic[src_num] = table_frag
                            else:
                                out_table_dic[src_num] += table_frag
 
                table_default = set([cls.__set_dead_state_tag__(du, dfa)])
                in_table = QuerySwitch('path_tag', in_table_dic, table_default)
                out_table = QuerySwitch('path_tag', out_table_dic, table_default)
               
                return ((in_table, out_table), accstates_to_pols)
           
            else:
                in_tagging_dic = {}
                out_tagging_dic = {}

                in_capture = drop
                out_capture = drop

                for edge in edges:
                    (src, src_num, dst, dst_num, pred, typ) = get_edge_attributes(dfa, edge)
                    assert typ in [__in__, __out__]

                    if_pred = not du.is_dead(dfa, src)
                    if default_link:
                        if_pred = if_pred and not du.is_dead(dfa, dst)

                    if if_pred:
                        tag_frag = (pred >> set_tag(dst_num))
                        if typ == __in__:
                            if not src_num in in_tagging_dic:
                                in_tagging_dic[src_num] = tag_frag
                            else:
                                in_tagging_dic[src_num] += tag_frag
                            in_tag_rules += 1


                        elif typ == __out__:
                            if not src_num in out_tagging_dic:
                                out_tagging_dic[src_num] = tag_frag
                            else:
                                out_tagging_dic[src_num] += tag_frag
                            out_tag_rules += 1

                    if du.is_accepting(dfa, dst):
                        ords = du.get_accepting_exps(dfa, edge, dst)
                        for i in ords:

                            cap_frag = ((match_tag(src_num) & pred) >> pol_list[i])
                            if typ == __in__:
                                in_capture += cap_frag
                                in_cap_rules += 1
                            elif typ == __out__:
                                out_capture += cap_frag
                                out_cap_rules += 1
                     
                tagging_default = set([cls.__set_dead_state_tag__(du,dfa)])
                in_tagging = QuerySwitch('path_tag', in_tagging_dic, tagging_default)
                out_tagging = QuerySwitch('path_tag', out_tagging_dic, tagging_default)
                
                return ((in_tagging, in_capture, out_tagging, out_capture), accstates_to_pols)

        else:
            if integrate_enabled:
                in_default = (((in_cg.get_unaffected_pred() &
                                ~(cls.__get_dead_state_pred__(du,dfa)))
                               >> cls.__set_dead_state_tag__(du, dfa)) +
                              cls.__get_dead_state_pred__(du,dfa))
                out_default = (((out_cg.get_unaffected_pred() &
                                 ~(cls.__get_dead_state_pred__(du,dfa)))
                                >> cls.__set_dead_state_tag__(du,dfa)) +
                               cls.__get_dead_state_pred__(du, dfa))
                
                in_table = in_default
                out_table = out_default
                for edge in edges:
                    (src, src_num, dst, dst_num, pred, typ) = get_edge_attributes(dfa, edge)
                    assert typ in [__in__, __out__]
                    
                    action_frag = None
                   
                    
                    if not du.is_dead(dfa, src):
                        action_frag = set_tag(dst_num)

                        if typ == __in__:
                            in_tag_rules += 1
                        else:
                            out_tag_rules += 1
                    
                    if du.is_accepting(dfa, dst):
                        ords = du.get_accepting_exps(dfa, edge, dst)
                        for i in ords:
                            if action_frag is None:
                                action_frag = pol_list[i]
                            else:
                                action_frag += pol_list[i]
                           
                            if typ == __in__:
                                in_cap_rules += 1
                            else:
                                out_cap_rules += 1
                    
                    if action_frag is not None:
                        tag_frag = (match_tag(src_num) & pred) >> action_frag
                        if typ == __in__:
                            in_table += tag_frag
                        elif typ == __out__:
                            out_table += tag_frag
                
                return ((in_table, out_table), accstates_to_pols)

            else:
                """ Initialize tagging and capture policies. """
                in_tagging = (((in_cg.get_unaffected_pred() &
                                ~(cls.__get_dead_state_pred__(du,dfa)))
                               >> cls.__set_dead_state_tag__(du, dfa)) +
                              cls.__get_dead_state_pred__(du,dfa))
                out_tagging = (((out_cg.get_unaffected_pred() &
                                 ~(cls.__get_dead_state_pred__(du,dfa)))
                                >> cls.__set_dead_state_tag__(du,dfa)) +
                               cls.__get_dead_state_pred__(du, dfa))
                in_capture = drop
                out_capture = drop
                """ Generate transition/accept rules from DFA """
                for edge in edges:
                    (src, src_num, dst, dst_num, pred, typ) = get_edge_attributes(dfa, edge)
                    assert typ in [__in__, __out__]
                    if not du.is_dead(dfa, src):
                        tag_frag = ((match_tag(src_num) & pred) >> set_tag(dst_num))
                        if typ == __in__:
                            in_tagging += tag_frag
                            in_tag_rules += 1

                        elif typ == __out__:
                            out_tagging += tag_frag
                            out_tag_rules += 1

                    if du.is_accepting(dfa, dst):
                        ords = du.get_accepting_exps(dfa, edge, dst)
                        for i in ords:

                            cap_frag = ((match_tag(src_num) & pred) >> pol_list[i])
                            if typ == __in__:
                                in_capture += cap_frag
                                in_cap_rules += 1
                            elif typ == __out__:
                                out_capture += cap_frag
                                out_cap_rules += 1
                return ((in_tagging, in_capture, out_tagging, out_capture), accstates_to_pols)

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

class common_dfa_utils(object):
    @classmethod
    def regexes_to_dfa(cls, re_exp, sym_list=None):
        raise NotImplementedError

    @classmethod
    def get_edges(cls):
        raise NotImplementedError
    @classmethod
    def get_edge_attributes(cls, dfa, edge, in_list=None, out_list=None):
        raise NotImplementedError

    @classmethod
    def is_dead(cls, dfa, q):
        raise NotImplementedError

    @classmethod
    def is_accepting(cls, dfa, q):
        raise NotImplementedError

    @classmethod
    def get_accepting_exps(cls, dfa, edge, q):
        raise NotImplementedError

    @classmethod
    def get_num_states(cls, dfa):
        raise NotImplementedError


class dfa_utils(common_dfa_utils):
    """ Utilities to generate DFAs and access various properties. """
    @classmethod
    def init(cls, in_cg, out_cg):
        cls.in_cg = in_cg
        cls.out_cg = out_cg
    
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
        return tt_entry[0]

    @classmethod
    def get_edge_dst(cls, d, tt_entry):
        assert isinstance(d, dfa_base)
        assert isinstance(tt_entry, tuple) and len(tt_entry) == 3
        return tt_entry[1]

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
    def is_dead(cls, d, q):
        return d.all_states.is_dead(q)

    @classmethod
    def get_dead_state(cls, d):
        dead = d.all_states.get_dead_state()
        return cls.get_state_index(d, dead)

    @classmethod
    def get_accepting_exps(cls, d, edge, q):
        assert isinstance(d, dfa_base) # dfa object
        assert isinstance(d.all_states, re_vector_state_table)
        assert cls.is_accepting(d, q)
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
    def __dump_file__(cls, string, tmp_file):
        f = open(tmp_file, 'w')
        f.write(string)
        f.close()

    @classmethod
    def __get_pred__(cls, dfa, edge):
        """ Get predicate and atom type corresponding to an edge. """
        def __sym_in_class__(cg, sym):
            return sym in cg.symbol_to_pred

        def __get_atoms_cg_typ__(atoms, sym):
            if len(atoms) > 1:
                typ = type(atoms[0])
                for a in atoms[1:]:
                    assert typ == type(a)
                if typ == __in__:
                    return (cls.in_cg, __in__)
                elif typ == __out__:
                    return (cls.out_cg, __out__)
                else:
                    raise TypeError("Atoms can only be in or out typed.")
            else:
                if __sym_in_class__(cls.in_cg, sym):
                    return (cls.in_cg, __in__)
                elif __sym_in_class__(cls.out_cg, sym):
                    return (cls.out_cg, __out__)
                else:
                    raise TypeError("Symbol can only be in or out typed.")

        edge_label = cls.get_edge_label(edge)
        atoms_list = reduce(lambda a,x: a + x,
                            cls.get_edge_atoms(dfa,edge),
                            [])
        (cg, typ) = __get_atoms_cg_typ__(atoms_list, edge_label)
        return (cg.symbol_to_pred[edge_label], typ)
   
    
    @classmethod
    def __get_tag_val__(cls, d, q):
        val = dfa_utils.get_state_index(d, q)
        if int(val) == 0:
            return None
        else:
            return int(val)

    
    @classmethod
    def get_edge_attributes(cls, dfa, edge, in_list=None, out_list=None):
        src = cls.get_edge_src(dfa, edge)
        src_num = cls.__get_tag_val__(dfa, src)
        dst = cls.get_edge_dst(dfa, edge)
        dst_num = cls.__get_tag_val__(dfa, dst)
        (pred, typ) = cls.__get_pred__(dfa, edge)
        return (src, src_num, dst, dst_num, pred, typ)
    
    @classmethod
    @Stat.elapsed_time
    def regexes_to_dfa(cls, re_exps, symlist=None):
        """ Convert a list of regular expressions to a DFA. """
        assert reduce(lambda acc, x: acc and isinstance(x, re_deriv),
                      re_exps, True)
        
        if not symlist:
            symlist = (cls.in_cg.get_symlist() +
                       cls.out_cg.get_symlist())
        dfa = makeDFA_vector(re_exps, symlist)
        cls.__dump_file__(dfa.dot_repr(), '/tmp/graph.dot')
        leaf_preds = (cls.in_cg.get_leaf_preds() +
                      cls.out_cg.get_leaf_preds())
       
        cls.__dump_file__(leaf_preds, '/tmp/symbols.txt')

        return dfa


class ragel_dfa(object):
    def __init__(self, state_num, final_states, transition, 
                    edges, edge_ordinals):
        self.state_num = state_num
        self.final_states = final_states
        self.transition = transition
        self.edges = edges
        self.edge_ordinals = edge_ordinals
  
    def __str__(self):
        return str(self.state_num) + ": " + str(self.edges)

class ragel_dfa_utils(common_dfa_utils):
    @classmethod
    def init(cls, in_cg, out_cg, edge_contraction_enabled):
        cls.edge_contraction_enabled = edge_contraction_enabled
        cls.in_cg = in_cg
        cls.out_cg = out_cg

    @classmethod
    def get_accepting_states(cls, data):
        acc_seen = False
        res = []
        for line in data.splitlines():
            if 'node' in line and 'doublecircle' in line:
                acc_seen = True
            elif acc_seen:
                if 'node' in line:
                    break
                else:
                    res.append(cls.get_state(line.strip()[:-1]))

        if res:
            """ If the input RE is not dead """
            state_num = max(res) + 1
        else:
            state_num = 1
        return (res, state_num)
    
    @classmethod
    def get_state(cls, q):
        if q == '1':
            return None
        return int(q) - 1

    @classmethod
    def is_accepting(cls, dfa, q):
        return q in dfa.final_states

    @classmethod
    def get_accepting_exps(cls, dfa, edge, q):
        try:
            return dfa.edge_ordinals[edge]
        except:
            print edge
            print dfa.edge_ordinals
            raise KeyError

    
    @classmethod
    def get_extended_edges_contracted(cls, output):
        res = []
        edge_ordinals = {}
        dfa_dict = {}
        for line in output.splitlines():
            if not '->' in line or 'IN' in line or 'main' in line:
                continue
            
            line = line.strip()

            label = line[line.index('=') + 3: line.index(']') - 2]
            
            dst = line[line.index('->') + 3 : line.index('[') - 1]
            src = line[:line.index('->') - 1]
            dst = cls.get_state(dst)
            src = cls.get_state(src)
            
            if not (src, dst) in dfa_dict:
                dfa_dict[(src, dst)] = []

            parts = [s.strip() for s in label.split('/')]
            exp_list = []
            if len(parts) > 1:
                for exp_num in [s.strip() for s in parts[1].split(',')]:
                    try:
                        exp_num = int(exp_num[1:])
                        exp_list.append(exp_num)
                    except:
                        pass

            syms = [s.strip().replace('"','') for s in parts[0].split(',')]
            for s in syms:
                if '..' in s:
                    index = s.index('..')
                    start = int(s[:index])
                    end = int(s[index + 2:])
                    for i in range(start, end + 1):
                        edge = (src, i, dst)
                        dfa_dict[(src,dst)].append( edge)
                        res.append(edge)
                        edge_ordinals[edge] = exp_list
                else:
                    edge = (src, int(s), dst)
                    dfa_dict[(src, dst)].append(edge)
                    res.append(edge)
                    edge_ordinals[edge] = exp_list


        def create_id_list(re_tree):
            if isinstance(re_tree, re_symbol):
                return [re_tree.char]
            elif isinstance(re_tree, re_alter):
                res = []
                for sym in re_tree.re_list:
                    res.extend(create_id_list(sym))
                res.sort()
                return res
            else:
                raise TypeError
        def check_ordinals(edge_list):
            edge_ords = [edge_ordinals[e] for e in dfa_list]
            for i in range(len(edge_ords) - 1):
                if edge_ords[i] != edge_ords[i + 1]:
                    return False
            return True


        in_cache = cls.in_cg.cache
        out_cache = cls.out_cg.cache
        in_in = identity in in_cache
        in_out = identity in out_cache
        if in_in or in_out:
            in_id = []
            out_id = []
            if in_in:
                in_id = create_id_list(in_cache[identity].gen_re_tree(cls.in_cg))
            if in_out:
                out_id = create_id_list(out_cache[identity].gen_re_tree(cls.out_cg))
            if len(in_id) > 1 or len(out_id) > 1:
                res = []
                for (src, dst), dfa_list in dfa_dict.items():
                    if len(dfa_list) > 1:
                        
                        edge_syms = [sym for (e_src, sym, e_dst) in dfa_list]
                        edge_syms.sort()
                        if edge_syms == out_id:
                            assert edge_syms != in_id
                            if check_ordinals(dfa_list):
                                new_edge = (src, 'OUT_ID', dst)
                                new_ord = edge_ordinals[dfa_list[0]]
                                for edge in dfa_list:
                                    del edge_ordinals[edge]

                                res.append(new_edge)
                                edge_ordinals[new_edge] = new_ord
                                dfa_dict[(src, dst)] = [identity]
                                continue

                        elif edge_syms == in_id:
                            if check_ordinals(dfa_list):
                                new_edge = (src, 'IN_ID', dst)
                                new_ord = edge_ordinals[dfa_list[0]]
                                for edge in dfa_list:
                                    del edge_ordinals[edge]

                                res.append(new_edge)
                                edge_ordinals[new_edge] = new_ord
                                dfa_dict[(src, dst)] = [identity]
                                continue
                            
                    res.extend(dfa_list)
        return (res, edge_ordinals)

    
    @classmethod
    def get_extended_edges(cls, output):
        res = []
        edge_ordinals = {}
       
        for line in output.splitlines():
            if not '->' in line or 'IN' in line or 'main' in line:
                continue
            
            line = line.strip()

            label = line[line.index('=') + 3: line.index(']') - 2]
            
            dst = line[line.index('->') + 3 : line.index('[') - 1]
            src = line[:line.index('->') - 1]
            dst = cls.get_state(dst)
            src = cls.get_state(src)

            parts = [s.strip() for s in label.split('/')]
            exp_list = []
            if len(parts) > 1:
                for exp_num in [s.strip() for s in parts[1].split(',')]:
                    try:
                        exp_num = int(exp_num[1:])
                        exp_list.append(exp_num)
                    except:
                        pass

            syms = [s.strip().replace('"','') for s in parts[0].split(',')]
            for s in syms:
                if '..' in s:
                    index = s.index('..')
                    start = int(s[:index])
                    end = int(s[index + 2:])
                    for i in range(start, end + 1):
                        edge = (src, i, dst)
                        res.append( edge)
                        edge_ordinals[edge] = exp_list
                else:
                    edge = (src, int(s), dst)
                    res.append(edge)
                    edge_ordinals[edge] = exp_list
        return (res, edge_ordinals)

    @classmethod
    def get_edges(cls, dfa):
        return dfa.edges

    @classmethod
    def get_edge_attributes(cls, dfa, edge, in_list=None, out_list=None):
        assert len(edge) == 3
        src = edge[0]
        try:
            src_num = int(src)
        except:
            src_num = None
      
        dst = edge[2]
        try:
            dst_num = int(dst)
        except:
            dst_num = None

        if not in_list:
            in_list = cls.in_cg.symbol_to_pred
        if not out_list:
            out_list = cls.out_cg.symbol_to_pred

        sym = edge[1]
        if sym == 'IN_ID':
            typ = __in__
            pred = identity
        elif sym == 'OUT_ID':
            typ = __out__
            pred = identity
        elif sym in in_list:
            typ = __in__
            pred = in_list[sym]
        elif sym in out_list:
            typ = __out__
            pred = out_list[sym]
        else:
            raise TypeError

        return (src, src_num, dst, dst_num, pred, typ)
        
        
    @classmethod
    def is_dead(cls, dfa, q):
        return q == cls.get_dead_state(dfa)
        #TODO(mina): fix
        #return False

    @classmethod
    def get_num_states(cls, dfa):
        return dfa.state_num
   
    @classmethod
    def get_dead_state(cls, dfa):
        return cls.get_num_states(dfa)

    @classmethod
    def regex_to_ragel_format(cls, re_list):
        res = '%%{\n\tmachine pyretic;\n\talphtype unsigned int;\n'
        for i in range(len(re_list)):
            res += '\taction _%d {}\n' % i
        
        re_list_str = '\tmain := '
        for i,q in re_list:
            re_list_str += '((' + q.re_string_repr() + (') @_%d)|' %i)
        res += re_list_str[:-1] + ';}%%\n%% write data;'
        return res

    @classmethod
    def add_dead_edges(cls, edges, state_num):
        """ Ragel doesn't add edges to dead states by default. Add those
        here. """
        state_edges = {}
        state_type = {}
        # get list of all predicates
        in_pred_symbols = cls.in_cg.symbol_to_pred.keys()
        out_pred_symbols = cls.out_cg.symbol_to_pred.keys()
        """ Determine edges currently in DFA, i.e., "non-dead" """
        for edge in edges:
            (s, p, d) = edge
            if s in state_edges:
                state_edges[s].append(p)
            else:
                state_edges[s] = [p]
            if p in in_pred_symbols:
                assert s not in state_type or state_type[s] == "in"
                state_type[s] = "in"
            elif p in out_pred_symbols:
                assert s not in state_type or state_type[s] == "out"
                state_type[s] = "out"
            else:
                raise RuntimeError("Outgoing pred must be at least of one\
                                    (in/out) type!")
        dead = state_num
        """ Add dead edges. """
        for s in state_edges.keys():
            if state_type[s] == "in":
                all_symbols = set(copy.copy(in_pred_symbols))
            else:
                all_symbols = set(copy.copy(out_pred_symbols))
            state_symbols = set(state_edges[s])
            remaining_symbols = all_symbols - state_symbols
            for sym in remaining_symbols:
                edges.append((s, sym, dead))
        """ Add dead edges for accepting states (without outgoing transitions)
        too!! """
        dfa_states = set(state_edges.keys())
        all_states = set(range(1, state_num))
        for s in all_states - dfa_states:
            for sym in in_pred_symbols + out_pred_symbols:
                edges.append((s, sym, dead))

    @classmethod
    @Stat.elapsed_time
    def regexes_to_dfa(cls, re_list):
        re_list = zip(range(len(re_list)), re_list)
        lex_input = cls.regex_to_ragel_format(re_list)
       
        lex_input_file = '/tmp/pyretic-regexes.txt'
        f = open(lex_input_file, 'w')
        f.write(lex_input)
        f.close()
        try:
            g = open('/tmp/graph.dot', 'w')
            subprocess.call(['ragel', '-V', lex_input_file], stdout=g)
            g.close()
            g = open('/tmp/graph.dot')
            output = g.read()
            g.close()
        except subprocess.CalledProcessError as e:
            
            print "Error occured while running ragel"
            print e.message
            print e.returncode
            print e.cmd
            print e.output
        
        (accepting_states, state_num) = cls.get_accepting_states(output)
        if cls.edge_contraction_enabled:
            (edges, edge_ordinal) = cls.get_extended_edges_contracted(output)
        else:
            (edges, edge_ordinal) = cls.get_extended_edges(output)
        # Add missing edges going to dead states, if needed.
        cls.add_dead_edges(edges, state_num)
       
        #print 'dfa stat count', state_num
        #print 'dfa edge count', len(edges)  
        leaf_preds = (cls.in_cg.get_leaf_preds() +
                      cls.out_cg.get_leaf_preds())
       
        dfa_utils.__dump_file__(leaf_preds, '/tmp/symbols.txt')

        dfa = ragel_dfa(state_num, accepting_states, None, edges, edge_ordinal)
        return dfa


#############################################################################
###                              Pickling                                 ###
#############################################################################

MARK = '('
LIST_END = 'l'
TUPLE_END = 't'
DIC_END = 'd'
INT = 'I'

NEWOBJ = '\x81'
OBJ = 'o'
LOAD = 'c'
DELIM = '\n'
END = '.'


## Extra possible features:
# Query, Buckets, and PathQueries
# Derived Policy, Dynamic Policy

def pickle_dump(policy):
    cls = policy.__class__.__name__
    module = getattr(policy, '__module__', None)
    if policy in [identity, drop, Controller]:
        return LOAD + module + DELIM + cls + DELIM + END
    if isinstance(policy, match) or isinstance(policy, modify):
        args = {}
        for k,v in policy.map.items():
            if k in ['srcip', 'dstip']:
                v = util.network_to_string(v)
            args[k] = v

        args_dump = pickle.dumps(args)[:-1]
        return ( MARK + LOAD + module + DELIM + cls + DELIM
               + args_dump + OBJ + END)
    
    if isinstance(policy, fwd):
        return (MARK + LOAD + module + DELIM + cls + DELIM
                + INT + str(policy.outport) + DELIM 
                + OBJ + END)

    if isinstance(policy, CombinatorPolicy):
        res = LOAD + module + DELIM + cls + DELIM
        res += MARK + MARK
        for pol in policy.policies:
            pol_dump = pickle_dump(pol)[:-1]
            res += pol_dump
        res += LIST_END + TUPLE_END + NEWOBJ + END
        return res

    while instance(policy, DynamicPolicy):
        policy = policy.policy
        # TODO(Mina)
        # ... add more stuff here.
        # ... need unpickling as well.


    print type(policy)
    raise NotImplementedError

#############################################################################
###                    Compilation Sketch                                 ###
#############################################################################

class Sketch(object):
    
    def __init__(self, need_stat, name=None):
        self.need_stat = need_stat
        self.compiled = False
        if not name:
            self.name = self.get_def_name()
        else:
            self.name = name

    def compile(self):
        raise NotImplementedError

    def netkat_compile(self, sw_cnt, multistage=True):
        if not self.need_stat:
            return self.pol.netkat_compile(sw_cnt, multistage)[0]
        else:
            func_str = '@Stat.classifier_stat\n@Stat.elapsed_time\ndef %s(pol, sw_cnt, multistage):\n\treturn pol.netkat_compile(sw_cnt, multistage)' % (self.name)
            exec(func_str)
            func = locals()[self.name]
            return func(self.pol, sw_cnt, multistage)

    def get_def_name(self):
        raise NotImplementedError

    def __mul__(self, sketch):
        return SequentalSketch(self, sketch, False)

    def __pow__(self, sketch):
        return SequentalSketch(self, sketch, True)

    def __div__(self, sketch):
        return ParallelSketch(self, sketch, False)

    def __floordiv__(self, sketch):
        return ParallelSketch(self, sketch, True)


    
class SketchCombinator(Sketch):

    def __init__(self, s1, s2, need_stat, name=None):
        self.s1 = s1
        self.s2 = s2
        self.pol1 = s1.pol
        self.pol2 = s2.pol
        super(SketchCombinator, self).__init__(need_stat, name)
    
    def compile(self, pol, func_str):
        res = None

        c1 = self.s1.compile()
        c2 = self.s2.compile()
        
        if self.compiled or not self.need_stat:
            res = pol.compile()
        else:
            exec(func_str)
            func = locals()[self.name]
            res = func(c1, c2)
            pol._classifier = res
        self.compiled = True
        return res

class SequentalSketch(SketchCombinator):
    
    def __init__(self, s1, s2, need_stat, name=None):
        super(SequentalSketch, self).__init__(s1, s2, need_stat, name)
        self.pol = self.pol1 >> self.pol2

    def compile(self):
        func_str = '@Stat.classifier_stat\n@Stat.elapsed_time\ndef %s(c1, c2):\n\treturn c1 >> c2' % self.name
        return super(SequentalSketch, self).compile(self.pol, func_str)
    
    def get_def_name(self):
        return self.s1.name + "__seq__" + self.s2.name

class ParallelSketch(SketchCombinator):
    
    def __init__(self, s1, s2, need_stat, name=None):
        super(ParallelSketch, self).__init__(s1, s2, need_stat, name)
        self.pol = self.pol1 + self.pol2

    def compile(self):
        func_str = '@Stat.classifier_stat\n@Stat.elapsed_time\ndef %s(c1, c2):\n\treturn c1 + c2' % self.name
        return super(ParallelSketch, self).compile(self.pol, func_str)

    def get_def_name(self):
        return self.s1.name + "__par__" + self.s2.name

class LeafSketch(Sketch):

    def __init__(self, name, pol, need_stat=True):
        self.def_name = name
        self.pol = pol
        super(LeafSketch, self).__init__(need_stat, name)

    def compile(self):
        res = None
        if self.compiled or not self.need_stat:
            res =  self.pol.compile()
        else:
            func_str = '@Stat.classifier_stat\n@Stat.elapsed_time\ndef %s(pol):\n\treturn pol.compile()' % self.name
            exec(func_str)
            func = locals()[self.name]
            res = func(self.pol) 

        self.compiled = True
        return res
    
    def get_def_name(self):
        return self.def_name

#############################################################################
###                     Multi-stage : Query Packing                       ###
#############################################################################


def get_filter_type(pol):
    '''  
    This is assuming that we have cleared 
    the match from redundant identity and drops
    meaning that 
      id + x is replaced by id
      id ; x is replaced by x
      drop + x is replaced by x
      drop ; x is replaced by drop
    thus the only case in which we have id or drop
    in a filter is that the filter is actually equal to
    id or drop without having anything else
    '''

    assert isinstance(pol, Filter)
    
    if pol == identity:
        return set()
    elif pol == drop:
        return set()
    elif isinstance(pol, match): 
        try:
            return set(pol.map.keys())
        except:
            return set()
    elif isinstance(pol, CombinatorPolicy):
        res = set()
        for p in pol.policies:
            res |= get_filter_type(p)
        return res
    elif isinstance(pol, DynamicFilter):
        return get_filter_type(pol.policy)
    else:
        raise TypeError

def get_types_dict(query):    

    if isinstance(query, path_combinator):
        in_type = Counter()
        out_type = Counter()
        for p in query.paths:
            (tin, tout) = get_types_dict(p)
            in_type.update(tin)
            out_type.update(tout)
        return (in_type, out_type)

    elif isinstance(query, in_out_atom):
        in_fields = frozenset(get_filter_type(query.in_pred))  
        in_type = Counter({ in_fields: 1 if len(in_fields) > 0 else 0})
        out_fields = frozenset(get_filter_type(query.out_pred))  
        out_type = Counter({ out_fields: 1 if len(out_fields) > 0 else 0})
        return (in_type, out_type)
    else:
        raise TypeError

def get_type(query):
    (in_dict, out_dict) = get_types_dict(query)
    return (join_list(in_dict.items()), join_list(out_dict.items()))

def join_type(t1, t2):
    (fset1, n1) = t1
    (fset2, n2) = t2
    
    final_count = None
    if len(fset1) == 0:
        final_count = n2 + 1
    elif len(fset2) == 0:   
        final_count = n1 + 1
    elif len(fset1 & fset2) == 0:
        final_count = (n1 + 1) * (n2 + 1) - 1
    elif fset1 <= fset2 or fset2 <= fset1:
        final_count = n1 + n2
    elif len(fset1 & fset2) > 0:
        final_count = (n1 + 1) * (n2 + 1) - 1

    return (fset1 | fset2, final_count)

def join_list(type_list):
    if len(type_list) == 0:
        return (0, [])
    res = reduce(lambda acc, typ: join_type(acc, typ), type_list)
    return res

def join_list_inout(type_list):
    in_list = [t[0] for t in type_list]
    out_list = [t[1] for t in type_list]
    return (join_list(in_list), join_list(out_list))

def join((in1, out1), (in2, out2)):
    return (join_type(in1, in2), join_type(out1, out2))

def pack(type_list, limit):
    stages = []
    assgn = {}

    for (q, typ) in type_list:
        assigned = False
        for i in range(len(stages)):
            new_typ = join(stages[i], typ)
            ((in_fset, in_cnt), (out_fset, out_cnt)) = new_typ 
            if in_cnt <= limit and out_cnt <= limit:
                stages[i] = new_typ
                if not i in assgn:
                    assgn[i] = []
                assgn[i].append(q)
                assigned = True
                break
        if not assigned:
            ((_, in_cnt), (_, out_cnt)) = typ 
            if in_cnt <= limit and out_cnt <= limit:
                stages.append(typ)
                assgn[len(stages) - 1] = [q]
            else:
                print q, in_cnt, out_cnt
                raise TypeError
    return assgn

def pack_stagelimited(type_list, numstages):
    stages = []
    assgn = {}

    for (q, typ) in type_list:
        min_max_size  = -1
        min_max_stage = -1
        min_max_type  = None
        if len(stages) < numstages:
            stages.append(typ)
            ((in_fset, in_cnt), (out_fset, out_cnt)) = typ
            assgn[len(stages) - 1] = [q]
        else:
            for i in range(numstages):
                new_typ = join(stages[i], typ)
                ((in_fset, in_cnt), (out_fset, out_cnt)) = new_typ
                val = max(in_cnt, out_cnt)
                if min_max_size == -1 or val < min_max_size:
                    min_max_size  = val
                    min_max_stage = i
                    min_max_type = new_typ
            assert min_max_stage >= 0 and min_max_size > 0 and not (
                min_max_type is None)
            stages[min_max_stage] = min_max_type
            if not min_max_stage in assgn:
                assgn[min_max_stage] = []
            assgn[min_max_stage].append(q)
    return assgn

def pack_queries(queries, limit):
    q_list = [get_type(q) for q in queries]
    q_list = zip(range(len(q_list)), q_list)
    assgn = pack(q_list, limit)
    for i in assgn:
        res = []
        for qi in assgn[i]:
            res.append(queries[qi])  
        assgn[i] = res
    return assgn

def pack_queries_stagelimited(queries, numstages):
    assert numstages > 0
    q_list = [get_type(q) for q in queries]
    q_list = zip(range(len(q_list)), q_list)
    assgn = pack_stagelimited(q_list, numstages)
    for i in assgn:
        res = []
        for qi in assgn[i]:
            res.append(queries[qi])
        assgn[i] = res
    return assgn
