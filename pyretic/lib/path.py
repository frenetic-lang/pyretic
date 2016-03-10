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
from pyretic.core.runtime import virtual_field, virtual_virtual_field

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
import sys
from collections import Counter

TOKEN_START_VALUE = 0 # start with printable ASCII for visual inspection ;)
TOKEN_END_VALUE = 0xFFFFFFFF 
# token type definitions
TOK_INGRESS = "ingress"
TOK_EGRESS = "egress"
TOK_DROP = "drop"
TOK_END_PATH = "end_path"
TOK_HOOK = "ingress_hook"
# limit on the number of stages for multi-stage table rule packing
MAX_STAGES = 13
# Runtime write log, for a single place to log everything from the runtime
# Default is None.
rt_write_log=None
# QuerySwitch compilation parallelism has this limit on maximum number of
# spawned processes.
QS_MAX_PROCESSES = 6
# Flag to remember if parallel Frenetic compilers have started
par_frenetics_started=False
# Maximum number of states allowed
NUM_PATH_TAGS=32000
# virtual stage identifier for virtual virtual headers. An unreasonably high
# number that can never be a "stage" for virtual header fields that actually
# live in the data plane.
VIRT_STAGE=1024

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

#########################################
#####             FDD               #####
#########################################

class FDD(object):

    def level_repr(self, acc, shift):
        raise NotImplementedError

    def get_leaves(self):
        raise NotImplementedError

    def __str__(self):
        lrepr = self.level_repr([], '')
        return '\n'.join(lrepr) + "\n\n-------------------\n"

    def __hash__(self):
        return hash(str(self))

class Node(FDD):
    def __init__(self, test, lchild, rchild):
        assert isinstance(test, tuple) and len(test) == 2
        assert issubclass(lchild.__class__, FDD)
        assert issubclass(rchild.__class__, FDD)
        super(Node, self).__init__()
        self.test = test
        self.lchild = lchild
        self.rchild = rchild
    
    def level_repr(self, acc, shift):
        acc.append(shift + self.test.__repr__())
        acc = (self.lchild.level_repr(acc, shift + '\t'))
        acc = (self.rchild.level_repr(acc, shift + '\t')) 
        return acc

    def get_leaves(self):
        res = self.lchild.get_leaves()
        res += self.rchild.get_leaves()
        return res

    def __eq__(self, other):
        return (type(self) == type(other) and
                self.test == other.test and
                self.lchild == other.lchild and
                self.rchild == other.rchild)

    def __repr__(self):
        return self.test.__repr__()

class Leaf(FDD):

    def __init__(self, pred_set = frozenset(), path = ([], set())):
        super(Leaf, self).__init__()
        self.pred_set = pred_set
        self.path = path
        self.symbol = None
    
    def level_repr(self, acc, shift):
        acc.append(shift + self.__repr__())
        return acc

    def get_leaves(self):
        return [self]

    def is_drop(self):
        return len(self.pred_set) == 0

    def __add__(self, other):
        
        new_pred_set = self.pred_set | other.pred_set
        #new_path = self.path | other.path
        res = Leaf(new_pred_set)
        #print 'adding'
        #print self.__repr__()
        #print other.__repr__()
        #print res.__repr__()
        #print '-------' 
        return res

    def __rshift__(self, other):
        new_pred_set = self.pred_set & other.pred_set
        #new_path = self.path | other.path
        return Leaf(new_pred_set)

    def neg(self, pred):
        assert len(self.pred_set) < 2
        if len(self.pred_set) == 0:
            return Leaf(set([pred])) 
        else:
            return Leaf()

    def get_pred(self, neg_cache):
        (true_dict, false_set) = self.path
        if len(true_dict) == 0:
            true_match = identity
        else:
            true_match = match(**dict(true_dict))
        false_match = None
        for (f, v) in false_set:
            if f in true_dict:
                continue
            pred = neg_cache[(f,v)]
            if false_match is None:
                false_match = pred
            else:
                false_match &= pred
        if false_match == None:
            false_match = identity
        return true_match & false_match

    def __eq__(self, other):
        res = (isinstance(other, Leaf) and self.pred_set == other.pred_set)
        return res 

    def __hash__(self):
        return hash(self.pred_set)

    def __repr__(self):

        res = '{'
        res += ','.join([str(x) for x in self.pred_set])
        res += '}'
        #res += '{'
        #res += ','.join([str(x) for x in self.path])
        #res += "}"
        return res

class FDDTranslator(object):
   
    @classmethod
    def refine(cls, d, fmap):
        if isinstance(d, Node):
            (f, v) = d.test
            if f in fmap:
                if fmap[f] == v:
                    return cls.refine(d.lchild, fmap)
                else:
                    return cls.refine(d.rchild, fmap)
            else:
                return d
        else:
            return d

    @classmethod
    def fmap_digest(cls, fmap, t):
        (f, v) = t
        if f in fmap:
            return (True, f, fmap[f])
        else:
            return (False, f, None)

    @classmethod
    def revert_fmap(cls, fmap, digest):
        (changed, f, v) = digest
        if changed:
            fmap[f] = v
        else:
            del fmap[f]
        return fmap

    @classmethod
    def merge(cls, d1, d2, fmap, union):
        d1 = cls.refine(d1, fmap)
        d2 = cls.refine(d2, fmap)
        if isinstance(d1, Node):
            t1 = d1.test
            if isinstance(d2, Node):
                t2 = d2.test
                if t1 == t2:
                    digest = cls.fmap_digest(fmap, t1)
                    (f, v) = t1
                    fmap[f] = v
                    lchild = cls.merge(d1.lchild, d2.lchild, fmap, union)
                    fmap = cls.revert_fmap(fmap, digest)
                    rchild = cls.merge(d1.rchild, d2.rchild, fmap, union)
                    test = t1
                else:
                    if t1 > t2:
                        d1, d2 = d2, d1
                        t1, t2 = t2, t1
                    
                    (f1, v1) = t1
                    (f2, v2) = t2
                    digest = cls.fmap_digest(fmap, t1)
                    fmap[f1] = v1
                    if f1 == f2 and v1 != v2:
                        lchild = cls.merge(d1.lchild, d2.rchild, fmap, union)
                        fmap = cls.revert_fmap(fmap, digest)
                        rchild = cls.merge(d1.rchild, d2, fmap, union)
                        test = t1
                    else:
                        lchild = cls.merge(d1.lchild, d2, fmap, union)
                        fmap = cls.revert_fmap(fmap, digest)
                        rchild = cls.merge(d1.rchild, d2, fmap, union)
                        test = t1
                         
            elif isinstance(d2, Leaf):
                lchild = cls.merge(d1.lchild, d2, fmap, union)
                rchild = cls.merge(d1.rchild, d2, fmap, union)
                test = t1
            else:
                raise TypeError
        elif isinstance(d1, Leaf):
            if isinstance(d2, Node):
                lchild = cls.merge(d2.lchild, d1, fmap, union)
                rchild = cls.merge(d2.rchild, d1, fmap, union)
                test = d2.test

            elif isinstance(d2, Leaf):
                if union:
                    return d1 + d2
                else:
                    return d1 >> d2
            else:
                raise TypeError
        else: 
            raise TypeError
        if rchild == lchild:
            res = lchild
        else:
            res = Node(test, lchild, rchild)
        return res
    @classmethod
    def neg(cls, d, pred):
        if isinstance(d, Node):
            lchild = cls.neg(d.lchild, pred)
            rchild = cls.neg(d.rchild, pred)
            return Node(d.test, lchild, rchild)
                    
        elif isinstance(d, Leaf):
            return d.neg(pred)
        else:
            raise TypeError


    @classmethod
    def get_id(cls, pred, path = ([], set())):
        return Leaf(frozenset([pred]), path)

    @classmethod
    def get_drop(cls, path = ([], set())):
        return Leaf(frozenset(), path)

    @classmethod 
    def translate(cls, pol, pred):
        if pol == identity:
            return cls.get_id(pred)            
        if pol == drop:
            return cls.get_drop()

        typ = type(pol)
        if issubclass(typ, DynamicFilter):
            return cls.translate(pol.policy, pred)
        if typ == match:
            fmap = pol.map.items()
            (f, v) = fmap[0]
            res = Node((f, v), cls.get_id(pred), cls.get_drop())

            for (f, v) in fmap[1:]:
                new_match = Node((f, v), cls.get_id(pred), cls.get_drop())
                res = cls.merge(res, new_match, {}, False)
            return res

        elif typ == negate:
            inner_pol = cls.translate(pol.policies[0], pred)
            return cls.neg(inner_pol, pred)
       
        elif issubclass(typ, union):
            res = cls.translate(pol.policies[0], pred)            
            for p in pol.policies[1:]:
                p_fdd = cls.translate(p, pred)
                res = cls.merge(res, p_fdd, {}, True)
            return res
        
        if issubclass(typ, intersection):
            res = cls.translate(pol.policies[0], pred)
            for p in pol.policies[1:]:
                p_fdd = cls.translate(p, pred)
                res = cls.merge(res, p_fdd, {}, False)
            return res
        raise TypeError

    @classmethod
    def assign_path(cls, fdd, path, neg_cache):
        if isinstance(fdd, Node):
            (true_dict, false_set) = path
            (f, v) = fdd.test
            assert not f in true_dict
            true_dict[f] = v
            cls.assign_path(fdd.lchild, path, neg_cache)
            del true_dict[f]
            new_false = false_set | {(f, v)}
            if not (f,v) in neg_cache:
                neg_cache[(f,v)] = ~match(**{f:v})
            cls.assign_path(fdd.rchild, (true_dict, new_false), neg_cache)
        elif isinstance(fdd, Leaf):
            (true_dict, false_set) = path
            fdd.path = (true_dict.items(), false_set)
        else:
            raise TypeError


class fdd_re_tree_gen(object):
    token = TOKEN_START_VALUE
    in_cg_list = []
    out_cg_list = []

    def __init__(self):
        self.num_to_pred = {}
        self.next = 0
        self.neg_cache = {}

        self.pred_to_atoms = {}
        self.pred_to_leafs = {}
        self.symbol_to_leaf = {}
        self.symbol_to_pred = {}
        self.leaf_list = []
        self.base = None
        self.dyn_preds = []

    def clear(self):
        self.num_to_pred = {}
        self.next = 0
        self.neg_cache = {}

        self.pred_to_atoms = {}
        self.pred_to_leafs = {}
        self.symbol_to_leaf = {}
        self.symbol_to_pred = {}
        self.leaf_list = []
        self.base = None
        self.dyn_preds = []

    @classmethod
    def global_sym_list(cls):
        res = []
        for cg in cls.in_cg_list + cls.out_cg_list:
            res.extend([l.token for l in cg.leaf_list])
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


    def __add_dyn_preds__(self, preds, atom_pol):
        """ Add each predicate in `preds` to list of dynamic predicates, with
        the corresponding `atom`. """
        for pred in preds:
            dyn_obj = self.dyn_pred_obj(pred, atom_pol)
            self.dyn_preds.append(dyn_obj)

            
    def add_pred(self, pred, at):
        
        """ Record dynamic predicates separately for update purposes."""
        dyn_pols = path_policy_utils.get_dyn_pols(pred)
        if dyn_pols:
            """ If new_pred contains a dynamic predicate, it must be remembered
            explicitly to set up recompilation routines in the runtime."""
            self.__add_dyn_preds__(dyn_pols, at.policy)
       
        if pred in self.pred_to_atoms:
            self.pred_to_atoms[pred].append(at)
            return
        
        self.pred_to_atoms[pred] = [at]
        self.num_to_pred[self.next] = pred
        pred_fdd = FDDTranslator.translate(pred, self.next)
        self.next += 1
        #FDDTranslator.assign_path(pred_fdd, set())
        if self.base == None:
            self.base = pred_fdd
        else:
            self.base = FDDTranslator.merge(pred_fdd, self.base, {}, True)

    def prep_re_tree(self):
        FDDTranslator.assign_path(self.base, ({}, set()), self.neg_cache)
        self.leaf_list = self.base.get_leaves()
        for leaf in self.leaf_list:
            if leaf.is_drop():
                continue
            sym = self.__new_symbol__()
            leaf.symbol = sym
            self.symbol_to_leaf[sym] = leaf
            self.symbol_to_pred[sym] = leaf.get_pred(self.neg_cache)
            for pred_id in leaf.pred_set:
                pred = self.num_to_pred[pred_id]
                if not pred in self.pred_to_leafs:
                    self.pred_to_leafs[pred] = []
                self.pred_to_leafs[pred].append(leaf)
    
    def get_re_tree(self, pred, at):
        assert isinstance(at, abstract_atom)
        assert isinstance(pred, Filter)
         
        if not pred in self.pred_to_leafs:
            return re_empty()
        
        re_tree = re_empty()
        for leaf in self.pred_to_leafs[pred]:
            re_tree |= re_symbol(leaf.symbol, metadata=at)
        return re_tree
 
    def get_re_string(self, pred, at):
        assert isinstance(at, abstract_atom)
        assert isinstance(pred, Filter)
         
        if not pred in self.pred_to_leafs:
            return "^any"
        
        syms = [str(leaf.symbol) for leaf in self.pred_to_leafs[pred]]
        return '(' + string.join(syms, ')|(') + ')'

    def get_leaf_preds(self):
        output = ''
        for sym in self.symbol_to_pred:
            pred = self.symbol_to_pred[sym]
            output += (str(sym) + ': ' + repr(pred) + '\n')
        return output

    
    def get_unaffected_pred(self):
        """ Predicate that covers packets unaffected by query predicates. """
        pred_list = self.symbol_to_pred.values()
        if len(pred_list) >= 1:
            return ~(reduce(lambda a,x: a | x, pred_list))
        else:
            return identity

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

class __fdd_in_re_tree_gen__(fdd_re_tree_gen):
    """ Character generator for in_atom matches. """
    def __init__(self):
        super(__fdd_in_re_tree_gen__, self).__init__()
        fdd_re_tree_gen.in_cg_list.append(self)

class __fdd_out_re_tree_gen__(fdd_re_tree_gen):
    """ Character generator for out_atom matches. """
    def __init__(self):

        super(__fdd_out_re_tree_gen__, self).__init__()
        fdd_re_tree_gen.out_cg_list.append(self)

           
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
        :param fold_f: 'a -> path_policy -> re_tree_gen -> re_tree_gen -> 'a
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
        self.grouping_fvlist = {}

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

    def get_measure_loc(self):
        return self.measure_loc

    def set_measure_loc(self, val):
        self.measure_loc = val

    def set_fvlist(self, fvdict):
        """ A way to inform the compiler that a set of substitutions may be used
        for grouping atoms. The format of the input is a dictionary of the form:

        {header:  [list of values]}
        """
        self.grouping_fvlist = fvdict

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

    def gen_re_string(self, in_cg, out_cg):
        return "^any"

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

    def gen_re_string(self, cg):
        return cg.get_re_string(self.policy, self)

    def invalidate_re_tree(self):
        """ Invalidate the internal representation in terms of regular
        expressions, for example, during recompilation. """
        self._re_tree = None
        self.tree_counter = 0

    def add_to_fdd(self, cg):
        cg.add_pred(self.policy, self)

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

    def gen_re_string(self, in_cg, out_cg):
        re_string = ('(' + self.in_atom.gen_re_string(in_cg) + ').(' +
                         self.out_atom.gen_re_string(out_cg) + ')')
        return re_string

    def invalidate_re_tree(self):
        self.in_atom.invalidate_re_tree()
        self.out_atom.invalidate_re_tree()

    def add_to_fdd(self, in_cg, out_cg):
        self.in_atom.add_to_fdd(in_cg)
        self.out_atom.add_to_fdd(out_cg)

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

    def replace_by_atom(self):
        """Return a corresponding in_out_atom without any grouping
        substitutions, including only the predicates provided during
        construction.
        """
        return in_out_atom(self.in_pred, self.out_pred)

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
   
    def gen_re_string(self, in_cg, out_cg):
        words = map(lambda x : x.gen_re_string(in_cg, out_cg), self.paths)
        return '(' + string.join(words, ')|(') + ')'

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

    def gen_re_string(self, in_cg, out_cg):
        return '(' + self.paths[0].gen_re_string(in_cg, out_cg) + ')*'

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

    def gen_re_string(self, in_cg, out_cg):
        words = map(lambda x : x.gen_re_string(in_cg, out_cg), self.paths)
        return '(' + string.join(words, ').(') + ')'

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

    def gen_re_string(self, in_cg, out_cg):
        return '!(' + self.paths[0] + ')'

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

    def gen_re_string(self, in_cg, out_cg):
        words = map(lambda x : x.gen_re_string(in_cg, out_cg), self.paths)
        return '(' + string.join(words, ')&(') + ')'


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

    def netkat_compile(self, switch_cnt=None, multistage=True):
        """ QuerySwitch netkat compilation. """
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
            p_class = self.policy_dic[tag_value].netkat_compile(
                switch_cnt=switch_cnt,
                multistage=multistage)
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

    def netkat_compile_par(self, switch_cnt=None, multistage=True):
        """ QuerySwitch netkat compilation; the parallel version. """
        global rt_write_log
        import multiprocessing
        from multiprocessing import Process
        from pyretic.core.classifier import Rule, Classifier
        import cProfile, pstats, StringIO
        import time
        from Queue import Empty as QE
        import subprocess, shlex
        from pyretic.core.netkat import NETKAT_PORT
        global par_frenetics_started

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

        def tagwise_helper(tag_field, tag_value, tag_policy, switch_cnt,
                           multistage, comp_defaults, frenetic_port):
            """ This function computes the classifier for a given state
            (tag_value) specialized by the value of the state on all
            matches. This is core to the compilation logic of QuerySwitch. """
            p_class = tag_policy.netkat_compile(switch_cnt=switch_cnt,
                                                multistage=multistage,
                                                server_port=frenetic_port)
            p_rules = p_class[0].rules
            netkat_time = float(p_class[1])
            t_s = time.time()
            final_rules = []
            for r in p_rules:
                new_match = r.match.intersect(match(**{tag_field : tag_value}))
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
            other_time = time.time() - t_s
            return (tag_value, final_rules, netkat_time, other_time)

        def tagwise_process(tag_field, outq, tag_value, tag_policy,
                            switch_cnt, multistage, comp_defaults,
                            frenetic_port):
            outq.put(tagwise_helper(tag_field, tag_value, tag_policy,
                                    switch_cnt, multistage, comp_defaults,
                                    frenetic_port))
            return 0

        def setwise_process(tag_field, outq, tag_policy_set, switch_cnt,
                            multistage, comp_defaults, frenetic_port):
            """ Compile a set of tag -> policy policies from the
            QuerySwitch. This is the core compilation logic in QuerySwitch. """
            for (tag_value, tag_policy) in tag_policy_set:
                final_rules = []
                p_class = tag_policy.netkat_compile(switch_cnt=switch_cnt,
                                                    multistage=multistage,
                                                    server_port=frenetic_port)
                t_s = time.time()
                p_rules = p_class[0].rules
                netkat_time = float(p_class[1])
                for r in p_rules:
                    new_match = r.match.intersect(match(**{tag_field : tag_value}))
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
                other_time = time.time() - t_s
                outq.put((tag_value, final_rules, netkat_time, other_time))
            return 0

        def wait_outputs(unscheduled_remaining, num_completed, num_total,
                         tagwise_rules, outputs, queue_timeout=2,
                         max_retries=5):
            """ This function implements the logic to wait for a spawned process
            to complete its execution. Used by the process pool to implement
            parallelized compilation over states. """
            num_retries = max_retries
            while True:
                try:
                    next_ruleset = outputs.get(block=True, timeout=2)
                    tagwise_rules.append(next_ruleset)
                    num_completed += 1
                    num_retries = max_retries
                    rt_write_log.info("%d outputs have completed (%d total)" %
                                      (num_completed, num_total))
                    if unscheduled_remaining or (num_completed == num_total):
                        return num_completed
                except QE:
                    rt_write_log.error("Empty queue after waiting 2 sec")
                    rt_write_log.info("%d outputs have completed" %
                                      num_completed)
                    if num_completed > 0:
                        # only subtract retries if we know outputs have started
                        # coming already. Note: this is dangerous because it is
                        # possible that the process waits indefinitely
                        # for outputs forever.
                        num_retries -= 1
                    if num_retries == 0:
                        return 0

        def chunks(l, n):
            """ generate successive n-sized from a list l. """
            for i in xrange(0, len(l), n):
                yield l[i:i+n]

        def pset_pool_compile(policy_dic, comp_defaults, tag,
                               use_standard_port=False):
            """ Implement a process pool where the querySwitch policies are
            partitioned off among a pre-generated static number of
            processes. There are no more than QS_MAX_PROCESSES spawned through
            the entire time. """
            outputs = multiprocessing.Queue()
            q_timeout = 2
            q_maxretries = 20
            all_tagpols = [x for x in policy_dic.iteritems()]
            chunk_size = (len(all_tagpols) / QS_MAX_PROCESSES) + 1
            tagpolsets = list(chunks(all_tagpols, chunk_size))
            assert len(tagpolsets) <= QS_MAX_PROCESSES
            iter_tagpolsets = zip(range(1, len(tagpolsets)+1), tagpolsets)
            for (index, tagpolset) in iter_tagpolsets:
                rt_write_log.info("Spawning a new process with %d items" %
                                  len(tagpolset))
                proc_port = 0 if use_standard_port else index
                proc_port += NETKAT_PORT
                p = Process(target=setwise_process,
                            args=((tag, outputs,tagpolset,switch_cnt,
                                   multistage, comp_defaults, proc_port)))
                p.start()
            num_completed = 0
            num_total = len(policy_dic.keys())
            tagwise_rules = []
            completed = wait_outputs(False, num_completed, num_total,
                                     tagwise_rules, outputs,
                                     q_timeout, q_maxretries)
            if completed > 0:
                assert completed == num_total
            else:
                raise RuntimeError("Processes did not make enough progress in %d"
                                   " seconds" % (q_timeout * q_maxretries))
            rt_write_log.info("Got ALL the outputs back from processes!")
            return tagwise_rules

        def process_pool_compile(policy_dic, comp_defaults, tag,
                                 use_standard_port=False):
            """ Implement a process pool to parallelize the compilation of
            QuerySwitch over at most QS_MAX_PROCESSES processes. This method
            spawns a new process for each new tag policy that's being
            compiled."""
            outputs = multiprocessing.Queue()
            q_timeout = 2
            q_maxretries = 5
            rt_write_log.info("Parallelizing %d jobs into %d processes" % (
                len(policy_dic.keys()), QS_MAX_PROCESSES))
            num_active_procs = 0
            num_completed = 0
            num_total = len(policy_dic.keys())
            tagwise_rules = []
            total_scheduled = 0
            for tagpol in policy_dic.iteritems():
                if num_active_procs >= QS_MAX_PROCESSES:
                    rt_write_log.info("Max process threshold: wait for process results...")
                    completed = wait_outputs(True, num_completed, num_total,
                                             tagwise_rules, outputs,
                                             q_timeout, q_maxretries)
                    if completed > 0:
                        num_completed = completed
                        num_active_procs -= 1
                    else:
                        raise RuntimeError("Processes did not make enough progress"
                                           "in %d seconds" % (q_timeout *
                                                          q_maxretries))
                assert num_active_procs < QS_MAX_PROCESSES
                rt_write_log.info("Schedule new compile process...")
                # TODO: this isn't *ideal* load balancing; since processes don't
                # necessarily complete in the order they were spawned.
                proc_port = 0 if use_standard_port else (total_scheduled %
                                                         QS_MAX_PROCESSES)
                proc_port += NETKAT_PORT
                p = Process(target=tagwise_process,
                            args=((tag, outputs,) + tagpol +
                                  (switch_cnt, multistage, comp_defaults,
                                   proc_port)))
                p.start()
                total_scheduled += 1
                num_active_procs += 1
                rt_write_log.info("Scheduled %d'th process (%d active)" %
                                  (total_scheduled, num_active_procs))
            # At most QS_MAX_PROCESSES compilations remain to finish; and
            # they've all been scheduled by now.
            completed = wait_outputs(False, num_completed, num_total,
                                     tagwise_rules, outputs,
                                     q_timeout, q_maxretries)
            if completed > 0:
                assert completed == num_total
            else:
                raise RuntimeError("Processes did not make enough progress in %d"
                                   " seconds" % (q_timeout * q_maxretries))
            rt_write_log.info("Got ALL the outputs back from processes!")
            return tagwise_rules

        def start_frenetics(docker_start):
            global par_frenetics_started
            par_frenetics_started = True
            num_servers = QS_MAX_PROCESSES
            plist = []
            for proc in range(1, num_servers+1):
                port = NETKAT_PORT + proc
                if docker_start:
                    netkat_cmd = ("bash start-docker.sh %d" % port)
                else:
                    netkat_cmd = ("./frenetic compile-server --http-port %d"
                                  " --verbosity error" % port)
                try:
                    phandle = subprocess.Popen(shlex.split(netkat_cmd), #shell=True,
                                               stderr=subprocess.STDOUT)
                    rt_write_log.info("Executed command %s" % netkat_cmd)
                    plist.append(phandle)
                except Exception as e:
                    print "Could not start frenetic server successfully."
                    print e
                    sys.exit(1)
            time.sleep(2) # to allow daemons to be started
            return plist

        def kill_frenetics(phandles):
            for p in phandles:
                p.terminate()

        t_s = time.time()
        profile_enabled = False
        if profile_enabled:
            pr = cProfile.Profile()
            pr.enable()
        comp_defaults = set(map(resolve_virtual_fields, self.default))
        parallelize_frenetic = True
        parallelize_compilation = False
        docker_start = True
        if parallelize_compilation:
            phandles = (start_frenetics(docker_start) if parallelize_frenetic
                        else [])
            time.sleep(1)
            # Try the "process-set" pool, instead of "process" pool, for compilation.
            pool_method = pset_pool_compile
            tagwise_rules = pool_method(self.policy_dic, comp_defaults, self.tag,
                                        use_standard_port=not
                                        parallelize_frenetic)
            kill_frenetics(phandles)
        else:
            frenetic_port = NETKAT_PORT
            tagwise_rules = []
            for (tag_value, tag_policy) in self.policy_dic.iteritems():
                tagwise_rules.append(tagwise_helper(self.tag, tag_value, tag_policy,
                                                    switch_cnt, multistage, comp_defaults,
                                                    frenetic_port))
        # Aggregate results and return the final classifier
        netkat_tot_time = 0.0
        other_tot_time = 0.0
        tot_time = 0.0
        final_rules = []
        for (tag_value, tag_rules, netkat_time, other_time) in tagwise_rules:
            final_rules += tag_rules
            netkat_tot_time += netkat_time
            other_tot_time += other_time
            tot_time += (netkat_time + other_time)
        final_rules.append(Rule(identity, comp_defaults, [self], "switch"))
        c = Classifier(final_rules)
        if profile_enabled:
            pr.disable()
            s = StringIO.StringIO()
            sortby = 'cumulative'
            ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
            ps.print_stats()
        wall_clock_time = time.time() - t_s
        rt_write_log.info("netkat time: %f; other time: %f" % (netkat_tot_time,
                                                               other_tot_time))
        rt_write_log.info("wall clock time: %f" % wall_clock_time)
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
    rtm_fvlist  = {}

    @classmethod
    def set_rtm_fvlist(cls, switch_ports):
        """ Set the field=value list populated by runtime, including the latest
        topology information. """
        cls.rtm_fvlist = {'switch': [], 'port': set()}
        for (sw,ports) in switch_ports:
            cls.rtm_fvlist['switch'].append(sw)
            # for now, all ports can go with all switches.
            cls.rtm_fvlist['port'] |= set(ports)
        cls.rtm_fvlist['port'] = list(cls.rtm_fvlist['port'])

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
                    # return the in_out_atom corresponding to this group.
                    # recall that vals[id(ast)] has the form (in_out_atom, (field_map))
                    val = vals[id(ast)][0] 
                except KeyError:
                    raise RuntimeError("Substitution vals has no "
                                       "substitution for current AST: %s" % repr(ast))
                return val
            else:
                return ast
        return actual_mapper

    @classmethod
    def atom_substitute_groupby(cls):
        def actual_mapper(ast):
            assert isinstance(ast, path)
            if isinstance(ast, in_out_group):
                return ast.replace_by_atom()
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
            return [[]]
        else:
            res = []
            if not fvlist[flist[0]]:
                # Sometimes, the value list for a field may be empty.
                return [[None]]
            # From here on, fvlist[...] has a nonempty list of values for header
            # flist[0].
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
                in_field_map = dict(zip(ingby, inl))
                out_field_map = dict(zip(outgby, outl))
                atom = gatom.substitute(in_field_map, out_field_map)
                res.append((atom, (in_field_map, out_field_map)))
        return filter(lambda x: not x[0] is None, res)

    @classmethod
    def gatom_to_ioatom_combos(cls, galist, fvlist):
        """ Result is of the form 
            [ group_to_atom_metadata_map ]
            where each element is a dictionary of the form
            gatom_id : (in_out_atom, (in_field_list_map, out_field_list_map) )
            where in_field_list_map is a dictionary of the form
            { field1: value1, field2: value2, ...}
            (corresponding to each groupby field substitution).
        """
        assert list_isinstance(galist, in_out_group)
        ga_subst_map = {id(gatom): cls.gen_groupby_substitutes(gatom, fvlist)
                        for gatom in galist}
        empty_subs = reduce(lambda acc, v: acc or (False if v else True),
                            ga_subst_map.values(), False)
        if empty_subs:
            return []
        id_sorted_gatoms = sorted(map(id, galist))
        combos = cls.flist_vlist_combos(id_sorted_gatoms,
                                        ga_subst_map)
        res = []
        for atom_combo in combos:
            res.append({f:v for (f,v) in zip(id_sorted_gatoms, atom_combo)})
        return res

    @classmethod
    def aggwrap(cls, funlist, agg):
        def actual_callback(res):
            for f in funlist:
                f(agg, res)
        return actual_callback

    @classmethod
    def get_eff_fvlist(cls, p, fvlist):
        """ For each path query being processed, get an effective field=value
        list for expansion of grouping atoms. The priority is as follows:
        - the runtime populated list has lowest priority
        - the field value list set when defining the path query gets higher
        priority
        - the arguments to the expand_groupby function get highest
        priority. This is to allow the function to be called by applications to
        enforce their own expansions on queries they choose to expand (e.g., see
        path_test_tm_groupby in examples/path_query.py).
        """
        assert isinstance(p, path_policy)
        eff_fvlist = {}
        eff_fvlist.update(cls.rtm_fvlist)
        eff_fvlist.update(p.grouping_fvlist)
        eff_fvlist.update(fvlist)
        return eff_fvlist

    @classmethod
    def specialize_query(cls, p, mapper, mapping={}):
        """Return a "basic" version of a groupby query, where groupby atoms are
        replaced by the in/out atoms with the same predicates. Given a mapper to
        replace the instance of the grouping atom by an atom of choice, return a
        query that looks identical to the original query. """
        ppu = path_policy_utils
        new_query = ppu.path_ast_map(p, mapper)
        p_cbs = p.get_bucket().callbacks
        p_bucket = type(p.get_bucket())()
        mapping = dict([(i, x[1]) for i, x in mapping.items()])
        p_bucket.register_callback(cls.aggwrap(p_cbs, mapping))
        new_query.set_bucket(p_bucket)
        new_query.set_measure_loc(p.get_measure_loc())
        return new_query

    @classmethod
    def expand_groupby(cls, path_pol, fvlist={}):
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
        def collect_primitive_pathpols(acc, p, in_cg=None, out_cg=None):
            if isinstance(p, path_policy_union) or isinstance(
                    p, dynamic_path_policy):
                return acc
            elif isinstance(p, path_policy):
                return acc | set([p])
            else:
                raise TypeError("Expecting type path_policy")
        assert isinstance(path_pol, path_policy), "cannot expand groupby from non-path-policies"
        ppols_list = ppu.path_policy_ast_fold(
            path_pol, collect_primitive_pathpols, set([]))
        res_ppols = []
        for p in ppols_list:
            gatm_list = ppu.path_ast_fold(p.path, cls.groupby_collect, set())
            if not gatm_list:
                res_ppols.append(p)
                continue
            # From here on, deal with queries p that have groupby atoms.
            fvlist = cls.get_eff_fvlist(p, fvlist)
            gid_to_atoms = cls.gatom_to_ioatom_combos(gatm_list, fvlist)
            if not gid_to_atoms:
                mapper = cls.atom_substitute_groupby()
                res_ppols.append(cls.specialize_query(p, mapper, {}))
                continue
            # From here on, deal with queries p that have a nonzero expansion.
            for mapping in gid_to_atoms:
                mapper = cls.map_substitute_groupby(mapping)
                res_ppols.append(cls.specialize_query(p, mapper, mapping))
        assert len(res_ppols) > 0
        if len(res_ppols) > 1:
            return path_policy_union(res_ppols)
        else:
            return res_ppols[0]

class pathcomp(object):
    """ Functionality related to actual compilation of path queries. """
    log = logging.getLogger('%s.pathcomp' % __name__)
    log.setLevel(logging.ERROR)

    @classmethod
    def __num_set_tag__(cls, num, vfield):
        val = None if num == 0 else num
        kw = {vfield: val}
        return modify(**kw)

    @classmethod
    def __num_match_tag__(cls, num, vfield):
        val = None if num == 0 else num
        kw = {vfield: val}
        return match(**kw)

    @classmethod
    def __get_dead_state_pred__(cls, du, dfa, vfield):
        dead = du.get_dead_state(dfa)
        if dead:
            return cls.__num_match_tag__(dead, vfield)
        else:
            return drop

    @classmethod
    def __set_dead_state_tag__(cls, du, dfa, vfield):
        dead = du.get_dead_state(dfa)
        if dead:
            return cls.__num_set_tag__(dead, vfield)
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
    def __prep_fdd__(cls, acc, p, in_cg, out_cg):
        def add_atoms(acc, x):
            if isinstance(x, in_out_atom):
                x.add_to_fdd(in_cg, out_cg)
            return None

        if (isinstance(p, path_policy) and
            not isinstance(p, dynamic_path_policy) and
            not isinstance(p, path_policy_union)):
            path_policy_utils.path_ast_fold(p.path, add_atoms, None)
            return None
        elif isinstance(p, path_policy):
            return None
        else:
            raise TypeError("Can't prep fdd for non-path-policy!")

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
    def __get_re_strings__(cls, acc, p, in_cg, out_cg):
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
            tree = p.path.gen_re_string(in_cg, out_cg)
            piped_pol = p.piped_policy
            return (re_acc + [tree], pol_acc + [piped_pol])
        else:
            raise TypeError("Can't get re_pols from non-path-policy!")

    @classmethod
    def init(cls, numvals, switch_cnt = None, cache_enabled = False,
             edge_contraction_enabled = False, partition_enabled = False,
             use_fdd = False, write_log = None):
        
        """ Initialize path-related structures, namely:
        - a new virtual field for path tag;
        - in and out character generators.
        """
        global rt_write_log
        cls.swich_cnt = switch_cnt
        cls.cache_enabled = cache_enabled
        cls.partition_enabled = partition_enabled
        cls.edge_contraction_enabled = edge_contraction_enabled
        cls.use_fdd = use_fdd 
        if write_log:
            rt_write_log = write_log

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
                         sw_cnt,
                         max_states=NUM_PATH_TAGS, disjoint_enabled=False,
                         default_enabled=False, integrate_enabled=False,
                         ragel_enabled=False, match_enabled=False):
        """ Generates a policy corresponding to upstream path queries. """
        from pyretic.lib.hsa import (pyr_hs_format, get_hsa_edge_policy,
                                     setup_tfs_data_from_policy,
                                     setup_tfs_data_from_cls,
                                     get_portid_map,
                                     get_hsa_edge_ports,
                                     get_reachable_inheaders)
        sw_ports = {k:v for (k,v) in switch_ports}
        hs_format = pyr_hs_format()
        edge_pol = get_hsa_edge_policy(sw_ports, network_links)

        if cls.use_fdd:
            in_cg = __fdd_in_re_tree_gen__()
            out_cg = __fdd_out_re_tree_gen__()
        else:
            in_cg = __in_re_tree_gen__(cls.swich_cnt, cls.cache_enabled,
                                    cls.partition_enabled)
            out_cg = __out_re_tree_gen__(cls.swich_cnt, cls.cache_enabled,
                                     cls.partition_enabled)

        ''' Downstream compilation to get full policy to test. '''
        (comp_res, acc_pols) = cls.compile_stage(path_pol, in_cg, out_cg,
                                                 max_states=max_states,
                                                 disjoint_enabled=disjoint_enabled,
                                                 default_enabled=default_enabled,
                                                 integrate_enabled=True,
                                                 ragel_enabled=ragel_enabled,
                                                 match_enabled=match_enabled,
                                                 stage=VIRT_STAGE)
        (in_table_pol, out_table_pol) = comp_res
        vvfield = 'path_tag_%s' % str(VIRT_STAGE)
        vin_tagging = ((edge_pol >> modify(**{vvfield:None})) + ~edge_pol)
        pol = (vin_tagging >>
               in_table_pol >>
               fwding >>
               out_table_pol)

        ''' Set up headerspace reachability preliminaries '''
        if disjoint_enabled:
            # TODO(ngsrinivas): fwding policy is compiled with pyretic; not
            # netkat. This is to temporarily allow compilation of forwarding
            # policies which are used for evaluation, which are anyhow generated
            # in "non-standard" ways independent of the compiler.
            c = (vin_tagging.netkat_compile(switch_cnt=sw_cnt)[0] >>
                 in_table_pol.netkat_compile(switch_cnt=sw_cnt)[0] >>
                 fwding.compile() >>
                 out_table_pol.netkat_compile(switch_cnt=sw_cnt)[0])
            setup_tfs_data_from_cls(hs_format, c, sw_ports, network_links)
        else:
            setup_tfs_data_from_policy(hs_format, pol, sw_ports, network_links)
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
                                              match(**{vvfield:accstate}),
                                              no_vlan=True)
                    res_filter = res_filter & match(switch=sw,port=p)
                    if up_capture == drop:
                        up_capture = res_filter >> parallel(pol_list)
                    else:
                        up_capture += (res_filter >> parallel(pol_list))

        return up_capture

    @classmethod
    def compile_downstream(cls, path_pol, max_states=NUM_PATH_TAGS,
                           disjoint_enabled=False, default_enabled=False,
                           integrate_enabled=False, ragel_enabled=False,
                           match_enabled=False, preddecomp_enabled=False):
        def stage_pack_helper(query_list, path_pol, numstages):
            if not isinstance(path_pol, path_empty):
                # TODO(ngsrinivas): check whether rule-limit-driven or
                # stage-limit-driven functions do better.
                # i.e., pack_queries(query_list, 2000) versus the one below.
                stages = pack_queries_stagelimited(query_list, numstages)
            else:
                stages = {0: [path_pol]}
            return stages

        def stage_pack_helper_debug_static(query_list, path_pol, numstages):
            """A debug stage pack helper for easy testing.  Use the example `path_test_3` or
            any combination of two queries in `path_main`, and replace the call
            to stage_pack_helper to a call to this function. """
            return {0: [query_list[0]], 1: [query_list[1]]}

        if isinstance(path_pol, path_policy_union):
            query_list = path_pol.path_policies
        else:
            query_list = [path_pol]

        if preddecomp_enabled:
            numstages = MAX_STAGES
        else:
            numstages = 1
        stages = stage_pack_helper(query_list, path_pol, numstages)

        in_res = []
        out_res = []
        cls.log.debug("Stages: %d" % len(stages))
        for (stage_index, stage) in stages.items():
            if cls.use_fdd:
                in_cg = __fdd_in_re_tree_gen__()
                out_cg = __fdd_out_re_tree_gen__()
            else:
                in_cg = __in_re_tree_gen__(cls.swich_cnt, cls.cache_enabled,
                                        cls.partition_enabled)
                out_cg = __out_re_tree_gen__(cls.swich_cnt, cls.cache_enabled,
                                         cls.partition_enabled)

            if len(stage) == 1:
                stage_path_pol = stage[0]
            else:
                stage_path_pol = path_policy_union(stage)
            res = cls.compile_stage(stage_path_pol, in_cg, out_cg,
                                    max_states=max_states,
                                    disjoint_enabled=disjoint_enabled,
                                    default_enabled=default_enabled,
                                    integrate_enabled=integrate_enabled,
                                    ragel_enabled=ragel_enabled,
                                    match_enabled=match_enabled,
                                    stage=stage_index)
            (compile_res, _) = res
            sep_index = len(compile_res) / 2
            in_part = compile_res[:sep_index]
            out_part = compile_res[sep_index:]
            """ If the "integrate" option is enabled, in_res looks like:
            [in_table1, in_table2, ..., in_tableN] for N query matching stages.

            Otherwise, in_res looks like:
            [(in_tag1, in_cap1), (in_tag2, in_cap2), ..., (in_tagN, in_capN)]
            for N query matching stages.

            Respectively for out_res.
            """
            in_res.append(in_part if len(in_part) != 1 else in_part[0])
            out_res.append(out_part if len(out_part) != 1 else out_part[0])
       
        return (in_res, out_res)
    
    @classmethod
    @Stat.elapsed_time
    def compile_stage(cls, path_pol, in_cg, out_cg, max_states=NUM_PATH_TAGS,
                      disjoint_enabled=False, default_enabled = False,
                      integrate_enabled=False, ragel_enabled = False,
                      match_enabled = False, stage=0):
        """ Compile the list of paths along with the forwarding policy `fwding`
        into a single classifier to be installed on switches.
        """
        
        classifier_utils.__set_init_vars__(match_enabled)

        ast_fold = path_policy_utils.path_policy_ast_fold
        re_pols  = cls.__get_re_pols__
        inv_trees = cls.__invalidate_re_trees__
        prep_fdd = cls.__prep_fdd__
        prep_trees = cls.__prep_re_trees__
       
        
        in_cg.clear()
        out_cg.clear()
        ast_fold(path_pol, inv_trees, None, in_cg, out_cg)

        @Stat.elapsed_time
        def partition_fdd(ast_fold, path_pol, prep_fdd, in_cg, out_cg):
            ast_fold(path_pol, prep_fdd, None, in_cg, out_cg)
            in_cg.prep_re_tree()
            out_cg.prep_re_tree()

        @Stat.elapsed_time
        def partition_nonfdd(path_pol, in_cg, out_cg):
            cls.pred_part(path_pol, in_cg, out_cg)

        if cls.use_fdd:
            t_s = time.time()
            partition_fdd(ast_fold, path_pol, prep_fdd, in_cg, out_cg)
            cls.log.debug('predicate partitioning: %f' % (time.time() - t_s))
            (re_list, pol_list) =  ast_fold(path_pol, cls.__get_re_strings__, ([], []), in_cg, out_cg)

        else: 
            cls.log.debug('pred_part started')
            t_s = time.time()
            partition_nonfdd(path_pol, in_cg, out_cg)
            cls.log.debug('predicate partitioning: %f' % (time.time() - t_s))
            (re_list, pol_list) =  ast_fold(path_pol, re_pols, ([], []), in_cg, out_cg)
        
        cls.log.debug('compiling')
        res = cls.compile_core(re_list, pol_list, in_cg, out_cg, max_states, 
                                disjoint_enabled, default_enabled, 
                                integrate_enabled, ragel_enabled, cls.use_fdd, stage)
        return res

    @classmethod
    @Stat.elapsed_time
    def add_query(cls, path_pol, max_states = NUM_PATH_TAGS, disjoint_enabled = False, default_enabled = False,
            integrate_enabled = False, ragel_enabled = False, match_enabled = False):
        """TODO(ngsrinivas): this is a deprecated function. Refactor or
        remove. """
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

        # TODO(ngsrinivas): this call will need to be refactored when we test
        # incremental query addition.
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
                     integrate_enabled, ragel_enabled, use_fdd, stage):

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
            regexes_to_dfa_fun = lambda rlist: du.regexes_to_dfa(rlist, use_fdd=use_fdd)
        else:
            dfa_utils.init(in_cg, out_cg)
            du = dfa_utils
            regexes_to_dfa_fun = du.regexes_to_dfa

        dfa = regexes_to_dfa_fun(re_list)
        assert du.get_num_states(dfa) <= max_states

        ''' Initialize virtual field for this stage to hold tag values. '''
        vfield = 'path_tag_%s' % str(stage)
        vcls = virtual_field if stage != VIRT_STAGE else virtual_virtual_field
        vcls(vfield,
             range(0, du.get_num_states(dfa)+1),
             type="integer", stage=stage)

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
                polset = set([pol_list[i] for i in ords])
                if dst_num in accstates_to_pols:
                    accstates_to_pols[dst_num] |= polset
                else:
                    accstates_to_pols[dst_num] = polset

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
                                                
                        action_frag = set_tag(dst_num, vfield)

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
 
                table_default = set([cls.__set_dead_state_tag__(du, dfa, vfield)])
                in_table = QuerySwitch(vfield, in_table_dic, table_default)
                out_table = QuerySwitch(vfield, out_table_dic, table_default)
               
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
                        tag_frag = (pred >> set_tag(dst_num, vfield))
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

                            cap_frag = ((match_tag(src_num, vfield) & pred) >> pol_list[i])
                            if typ == __in__:
                                in_capture += cap_frag
                                in_cap_rules += 1
                            elif typ == __out__:
                                out_capture += cap_frag
                                out_cap_rules += 1
                     
                tagging_default = set([cls.__set_dead_state_tag__(du,dfa,vfield)])
                in_tagging = QuerySwitch(vfield, in_tagging_dic, tagging_default)
                out_tagging = QuerySwitch(vfield, out_tagging_dic, tagging_default)
                
                return ((in_tagging, in_capture, out_tagging, out_capture), accstates_to_pols)

        else:
            if integrate_enabled:
                in_default = (((in_cg.get_unaffected_pred() &
                                ~(cls.__get_dead_state_pred__(du,dfa,vfield)))
                               >> cls.__set_dead_state_tag__(du, dfa, vfield)) +
                              cls.__get_dead_state_pred__(du,dfa,vfield))
                out_default = (((out_cg.get_unaffected_pred() &
                                 ~(cls.__get_dead_state_pred__(du,dfa,vfield)))
                                >> cls.__set_dead_state_tag__(du,dfa,vfield)) +
                               cls.__get_dead_state_pred__(du, dfa,vfield))
                
                in_table = in_default
                out_table = out_default
                for edge in edges:
                    (src, src_num, dst, dst_num, pred, typ) = get_edge_attributes(dfa, edge)
                    assert typ in [__in__, __out__]
                    
                    action_frag = None
                   
                    
                    if not du.is_dead(dfa, src):
                        action_frag = set_tag(dst_num, vfield)

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
                        tag_frag = (match_tag(src_num, vfield) & pred) >> action_frag
                        if typ == __in__:
                            in_table += tag_frag
                        elif typ == __out__:
                            out_table += tag_frag
                
                return ((in_table, out_table), accstates_to_pols)

            else:
                """ Initialize tagging and capture policies. """
                in_tagging = (((in_cg.get_unaffected_pred() &
                                ~(cls.__get_dead_state_pred__(du,dfa,vfield)))
                               >> cls.__set_dead_state_tag__(du, dfa, vfield)) +
                              cls.__get_dead_state_pred__(du,dfa,vfield))
                out_tagging = (((out_cg.get_unaffected_pred() &
                                 ~(cls.__get_dead_state_pred__(du,dfa,vfield)))
                                >> cls.__set_dead_state_tag__(du,dfa,vfield)) +
                               cls.__get_dead_state_pred__(du, dfa, vfield))
                in_capture = drop
                out_capture = drop
                """ Generate transition/accept rules from DFA """
                for edge in edges:
                    (src, src_num, dst, dst_num, pred, typ) = get_edge_attributes(dfa, edge)
                    assert typ in [__in__, __out__]
                    if not du.is_dead(dfa, src):
                        tag_frag = ((match_tag(src_num, vfield) & pred) >>
                                    set_tag(dst_num, vfield))
                        if typ == __in__:
                            in_tagging += tag_frag
                            in_tag_rules += 1

                        elif typ == __out__:
                            out_tagging += tag_frag
                            out_tag_rules += 1

                    if du.is_accepting(dfa, dst):
                        ords = du.get_accepting_exps(dfa, edge, dst)
                        for i in ords:

                            cap_frag = ((match_tag(src_num, vfield) & pred) >> pol_list[i])
                            if typ == __in__:
                                in_capture += cap_frag
                                in_cap_rules += 1
                            elif typ == __out__:
                                out_capture += cap_frag
                                out_cap_rules += 1
                return ((in_tagging, in_capture, out_tagging, out_capture), accstates_to_pols)


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
    def regex_to_ragel_format(cls, re_list, use_fdd):
        res = '%%{\n\tmachine pyretic;\n\talphtype unsigned int;\n'
        for i in range(len(re_list)):
            res += '\taction _%d {}\n' % i
        
        re_list_str = '\tmain := '
        for i,q in re_list:
            q_str = q if use_fdd else q.re_string_repr()
            re_list_str += '((' + q_str + (') @_%d)|' %i)
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
    def regexes_to_dfa(cls, re_list, use_fdd=False):
        import cProfile, pstats, StringIO
        import time
        global rt_write_log
        profile_enabled = True
        lex_gen_time = 0.0
        lex_write_time = 0.0
        ragel_time = 0.0
        graph_read_time = 0.0
        dfa_attr_gen_time = 0.0
        leaf_gen_time = 0.0
        dfa_gen_time = 0.0
        if profile_enabled:
            pr = cProfile.Profile()
            pr.enable()
        t_s = time.time()
        re_list = zip(range(len(re_list)), re_list)
        lex_input = cls.regex_to_ragel_format(re_list, use_fdd)
        lex_gen_time = time.time() - t_s

        t_s = time.time()
        lex_input_file = '/tmp/pyretic-regexes.txt'
        f = open(lex_input_file, 'w')
        f.write(lex_input)
        f.close()
        lex_write_time = time.time() - t_s
        try:
            g = open('/tmp/graph.dot', 'w')
            t_s = time.time()
            subprocess.call(['ragel', '-V', lex_input_file], stdout=g)
            g.close()
            ragel_time = time.time() - t_s
            t_s = time.time()
            g = open('/tmp/graph.dot')
            output = g.read()
            g.close()
            graph_read_time = time.time() - t_s
        except subprocess.CalledProcessError as e:
            
            print "Error occured while running ragel"
            print e.message
            print e.returncode
            print e.cmd
            print e.output

        t_s = time.time()
        (accepting_states, state_num) = cls.get_accepting_states(output)
        if cls.edge_contraction_enabled:
            (edges, edge_ordinal) = cls.get_extended_edges_contracted(output)
        else:
            (edges, edge_ordinal) = cls.get_extended_edges(output)
        # Add missing edges going to dead states, if needed.
        cls.add_dead_edges(edges, state_num)
        dfa_attr_gen_time = time.time() - t_s
       
        #print 'dfa stat count', state_num
        #print 'dfa edge count', len(edges)  
        t_s = time.time()
        leaf_preds = (cls.in_cg.get_leaf_preds() +
                      cls.out_cg.get_leaf_preds())
       
        dfa_utils.__dump_file__(leaf_preds, '/tmp/symbols.txt')
        leaf_gen_time = time.time() - t_s

        t_s = time.time()
        dfa = ragel_dfa(state_num, accepting_states, None, edges, edge_ordinal)
        dfa_gen_time = time.time() - t_s
        if profile_enabled:
            pr.disable()
            s = StringIO.StringIO()
            sortby = 'cumulative'
            ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
            ps.print_stats()
            rt_write_log.info(s.getvalue())
        rt_write_log.info("Times:\n" +
                          "lex_gen_time: %f\n" % lex_gen_time +
                          "lex_write_time: %f\n" % lex_write_time +
                          "ragel_time: %f\n" % ragel_time +
                          "graph_read_time: %f\n" % graph_read_time +
                          "dfa_attr_gen_time: %f\n" % dfa_attr_gen_time +
                          "leaf_gen_time: %f\n" % leaf_gen_time +
                          "dfa_gen_time: %f\n" % dfa_gen_time)
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
        raise NotImplementedError
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
        raise TypeError, "Got unexpected type %s" % type(query)

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

def pack(type_list, limit, stagelimit=14):
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
                assert len(stages) < stagelimit
            else:
                print q, in_cnt, out_cnt
                raise TypeError
    return assgn

def pack_stage(type_list, limit, max_stage):
    stages = []
    assgn = {}
    range_dict = dict([(i, range(i)) for i in range(max_stage + 1)])
    stage_len = 0
    for (q, typ) in type_list:
        assigned = False
        min_cost = None
        min_stage = None
        min_type = None

        for i in range_dict[stage_len]:
            new_typ = join(stages[i], typ)
            ((in_fset, in_cnt), (out_fset, out_cnt)) = new_typ 

            cost = max(in_cnt , out_cnt)
            if min_cost is None or cost < min_cost:
                min_cost = cost
                min_stage = i
                min_type = new_typ

            if in_cnt <= limit and out_cnt <= limit:
                stages[i] = new_typ
                if not i in assgn:
                    assgn[i] = []
                assgn[i].append(q)
                assigned = True
                break
        if not assigned:
            if stage_len == max_stage:
                stages[min_stage] = min_type
                assgn[min_stage].append(q)
            else:
                ((_, in_cnt), (_, out_cnt)) = typ 
                if in_cnt <= limit and out_cnt <= limit:
                    stages.append(typ)
                    stage_len += 1
                    assgn[stage_len - 1] = [q]
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
    nonempty_qs = filter(lambda x: not isinstance(x, path_empty), queries)
    empty_qs = filter(lambda x: isinstance(x, path_empty), queries)
    # only do packing for non-empty queries
    q_list = [get_type(q) for q in nonempty_qs]
    q_list = zip(range(len(q_list)), q_list)
    assgn = pack_stage(q_list, 2000, numstages)
    for i in assgn:
        res = []
        for qi in assgn[i]:
            res.append(nonempty_qs[qi])
        assgn[i] = res
    # attach all empty queries to 0th stage
    assgn[0] += empty_qs
    return assgn
