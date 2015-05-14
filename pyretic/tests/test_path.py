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

from pyretic.core.language import *
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.path import *
from pyretic.lib.path import __in_re_tree_gen__, __out_re_tree_gen__

import copy
import pytest
import sys

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')
ip4 = IPAddr('10.0.0.4')
in_cg  = __in_re_tree_gen__
out_cg = __out_re_tree_gen__
cu = classifier_utils
ne_inters = cu.has_nonempty_intersection

### Classifier utilities sanity checks ###

def test_classifier_ne_inters():
    m1 = match(srcip=ip1)
    m2 = match(switch=1)
    m3 = match(srcip=ip2)
    m4 = match(srcip=ip1) & match(switch=2)
    assert ne_inters(m1, m2)
    assert not ne_inters(m1, m3)
    assert ne_inters(m1, m4)
    assert ne_inters(m1, ~m4)
    assert not ne_inters(m4, ~m1)

def test_overlap_mode():
    ovlap = cu.get_overlap_mode
    m1 = match(srcip=ip1)
    m2 = match(switch=1)
    m3 = match(srcip=ip2)
    m4 = match(srcip=ip1) & match(switch=2)
    m5 = match(srcip=ip2) | match(srcip=ip1)
    m6 = match(srcip=ip2) | match(switch=1)
    m7 = match(switch=1)
    assert ovlap(m1, m1) == (True, False, False, False)
    assert ovlap(m2, m7) == (True, False, False, False)
    assert ovlap(m1, m3) == (False, False, False, False)
    assert ovlap(m1, m4) == (False, True, False, False)
    assert ovlap(m5, m6) == (False, False, False, True)
    assert ovlap(m4, m1) == (False, False, True, False)
    assert ovlap(m6, m5) == (False, False, False, True)

### Character generator basic sanity checks ###

def test_CG_token_gen():
    """Ensure you get a token back."""
    in_cg.clear()
    m = match(srcip=ip1) & match(switch=1)
    a = atom(m)
    assert a.re_tree

def test_CG_token_equality_1():
    in_cg.clear()
    m1 = match(srcip=ip1)
    m2 = m1
    a1 = atom(m1)
    a2 = atom(m2)
    assert a1.re_tree == a2.re_tree
    assert not a1.re_tree.equals_meta_by_id(a2.re_tree)
    assert a1.re_tree.equals_meta_structural(a2.re_tree)

def test_CG_token_equality_2():
    in_cg.clear()
    m1 = match(srcip=ip1)
    a1 = atom(m1)
    m2 = copy.copy(m1)
    a2 = atom(m2)
    tree1 = a1.re_tree
    tree2 = a2.re_tree
    assert a1 == a2
    assert id(a1) != id(a2)
    assert tree1 == tree2
    assert tree1.equals_meta_structural(tree2)
    assert not tree1.equals_meta_by_id(tree2)

def test_CG_token_equality_3():
    in_cg.clear()
    m1 = match(srcip=ip1)
    m2 = match(srcip=ip1) & match(switch=2)
    a1 = atom(m1)
    a2 = atom(m2)
    assert a1.re_tree != a2.re_tree

### Check re_tree generation under various predicate overlap conditions ###

@pytest.mark.skipif(True)
def check_metadata_list(a_list):
    """ Given a list of atoms, check if their re_tree objects have metadata
    pointing back to the atom objects. """
    def check_metadata_single_re(r, m):
        """ Subroutine to check metadata """
        if isinstance(r, re_symbol):
            assert r.metadata == [m]
        elif isinstance(r, re_combinator):
            for re in r.re_list:
                check_metadata_single_re(re, m)
        else:
            raise TypeError("Can't check metadata on re of any other type!")
    for a in a_list:
        check_metadata_single_re(a.in_atom.re_tree, a.in_atom)
        check_metadata_single_re(a.out_atom.re_tree, a.out_atom)

@pytest.mark.skipif(True)
def assert_and_get_syms(ms, cg):
    syms = []
    for m in ms:
        assert m in cg.pred_to_symbol
        assert m in cg.pred_to_atoms
        syms.append(cg.pred_to_symbol[m])
    return syms

@pytest.mark.skipif(True)
def generate_re_trees(plist):
    """ Just generates the re_tree for each path in turn, triggering the
    generation of regular expression ASTs for each path and predicate. """
    for p in plist:
        rt = p.re_tree

def test_CG_equal_matches():
    in_cg.clear()
    out_cg.clear()
    m1 = match(srcip=ip1)
    m2 = match(srcip=ip1)
    a1 = atom(m1)
    a2 = atom(m2)

    generate_re_trees([a1, a2])
    assert len(in_cg.pred_to_symbol.keys()) == 1
    assert len(out_cg.pred_to_symbol.keys()) == 1
    ms = [match(srcip=ip1)]
    in_syms  = assert_and_get_syms(ms, in_cg)
    out_syms = assert_and_get_syms([identity], out_cg)

    assert m1 in in_cg.pred_to_symbol and m1 in in_cg.pred_to_atoms
    assert m2 in in_cg.pred_to_symbol and m2 in in_cg.pred_to_atoms

    assert a1.in_atom.re_tree  == re_symbol(in_syms[0])
    assert a2.in_atom.re_tree  == re_symbol(in_syms[0])
    assert a1.out_atom.re_tree == re_symbol(out_syms[0])
    assert a2.out_atom.re_tree == re_symbol(out_syms[0])
    assert a1.re_tree == (re_symbol(in_syms[0]) ^ re_symbol(out_syms[0]))
    assert a2.re_tree == (re_symbol(in_syms[0]) ^ re_symbol(out_syms[0]))

    assert in_cg.pred_to_atoms[ms[0]] == [a1.in_atom, a2.in_atom]
    assert out_cg.pred_to_atoms[identity] == [a1.out_atom, a2.out_atom]

    check_metadata_list([a1, a2])

def test_CG_unequal_matches():
    in_cg.clear()
    out_cg.clear()
    m1 = match(srcip=ip1)
    a1 = in_atom(m1)
    a2 = out_atom(m1)
    generate_re_trees([a1, a2])

    assert len(in_cg.pred_to_symbol.keys()) == 2
    assert len(out_cg.pred_to_symbol.keys()) == 2
    in_syms  = assert_and_get_syms([m1, identity & ~m1], in_cg)
    out_syms = assert_and_get_syms([m1, identity & ~m1], out_cg)

    assert m1 in in_cg.pred_to_symbol and m1 in in_cg.pred_to_atoms
    assert m1 in out_cg.pred_to_symbol and m1 in out_cg.pred_to_atoms

    assert in_cg.pred_to_symbol[m1] != out_cg.pred_to_symbol[m1]

    assert a1.in_atom.re_tree  == re_symbol(in_syms[0])
    assert a1.out_atom.re_tree == (re_symbol(out_syms[0]) |
                                   re_symbol(out_syms[1]))
    assert a2.out_atom.re_tree == re_symbol(out_syms[0])
    assert a2.in_atom.re_tree  == (re_symbol(in_syms[0]) |
                                   re_symbol(in_syms[1]))

def test_CG_superset_matches():
    in_cg.clear()
    out_cg.clear()
    m1 = match(srcip=ip1)
    m2 = match(srcip=ip1) & match(switch=2)
    a1 = atom(m1)
    a2 = atom(m2)

    generate_re_trees([a1, a2])
    assert len(in_cg.pred_to_symbol.keys()) == 2
    assert len(out_cg.pred_to_symbol.keys()) == 1
    ms = [match(srcip=ip1) & match(switch=2),
          match(srcip=ip1) & ~(match(srcip=ip1) & match(switch=2))]

    syms = assert_and_get_syms(ms, in_cg)

    assert not m1 in in_cg.pred_to_symbol
    assert m2 in in_cg.pred_to_symbol

    assert a1.in_atom.re_tree == re_symbol(syms[0]) | re_symbol(syms[1])
    assert a2.in_atom.re_tree == re_symbol(syms[0])

    assert in_cg.pred_to_atoms[ms[0]] == [a1.in_atom, a2.in_atom]
    assert in_cg.pred_to_atoms[ms[1]] == [a1.in_atom]
    assert out_cg.pred_to_atoms[identity] == [a1.out_atom, a2.out_atom]

    check_metadata_list([a1, a2])

def test_CG_subset_matches():
    in_cg.clear()
    out_cg.clear()
    m1 = match(srcip=ip1, switch=2)
    m2 = match(srcip=ip1)
    a1 = atom(m1)
    a2 = atom(m2)

    generate_re_trees([a1, a2])
    assert len(in_cg.pred_to_symbol.keys()) == 2
    assert len(out_cg.pred_to_symbol.keys()) == 1

    ms = [(match(srcip=ip1, switch=2)),
          (match(srcip=ip1) & ~match(srcip=ip1, switch=2))]

    syms = assert_and_get_syms(ms, in_cg)

    assert m1 in in_cg.pred_to_symbol and m1 in in_cg.pred_to_atoms
    assert not m2 in in_cg.pred_to_symbol and not m2 in in_cg.pred_to_symbol
    assert identity in out_cg.pred_to_symbol

    assert a1.in_atom.re_tree == re_symbol(syms[0])
    assert a2.in_atom.re_tree == re_symbol(syms[0]) | re_symbol(syms[1])

    assert in_cg.pred_to_atoms[ms[0]] == [a1.in_atom, a2.in_atom]
    assert in_cg.pred_to_atoms[ms[1]] == [a2.in_atom]
    assert out_cg.pred_to_atoms[identity] == [a1.out_atom, a2.out_atom]

    check_metadata_list([a1, a2])

def test_CG_intersection_matches_1():
    in_cg.clear()
    out_cg.clear()
    m1 = match(srcip=ip1)
    m2 = match(dstip=ip2)
    a1 = out_atom(m1)
    a2 = out_atom(m2)

    generate_re_trees([a1, a2])
    assert len(out_cg.pred_to_symbol.keys()) == 3
    assert len(in_cg.pred_to_symbol.keys()) == 1
    ms = [(match(srcip=ip1) & ~match(dstip=ip2)),
          (match(dstip=ip2) & ~match(srcip=ip1)),
          (match(srcip=ip1) & match(dstip=ip2))]

    syms = assert_and_get_syms(ms, out_cg)

    assert not m1 in out_cg.pred_to_symbol and not m1 in out_cg.pred_to_atoms
    assert not m2 in out_cg.pred_to_symbol and not m2 in out_cg.pred_to_atoms
    assert identity in in_cg.pred_to_symbol

    assert a1.out_atom.re_tree == re_symbol(syms[0]) | re_symbol(syms[2])
    assert a2.out_atom.re_tree == re_symbol(syms[1]) | re_symbol(syms[2])

    assert out_cg.pred_to_atoms[ms[0]] == [a1.out_atom]
    assert out_cg.pred_to_atoms[ms[1]] == [a2.out_atom]
    assert out_cg.pred_to_atoms[ms[2]] == [a1.out_atom, a2.out_atom]
    assert in_cg.pred_to_atoms[identity] == [a1.in_atom, a2.in_atom]

    check_metadata_list([a1, a2])

def test_CG_intersection_matches_2():
    in_cg.clear()
    out_cg.clear()
    m1 = match(srcip=ip1)
    m2 = match(srcip=ip2)
    m3 = m1 | m2
    a1 = atom(m1)
    a2 = atom(m2)
    a3 = atom(m3)

    generate_re_trees([a1, a2, a3])
    assert len(in_cg.pred_to_symbol.keys()) == 2
    assert len(out_cg.pred_to_symbol.keys()) == 1
    ms = [match(srcip=ip1),
          match(srcip=ip2)]

    syms = assert_and_get_syms(ms, in_cg)

    assert a1.in_atom.re_tree == re_symbol(syms[0])
    assert a2.in_atom.re_tree == re_symbol(syms[1])
    assert a3.in_atom.re_tree == re_symbol(syms[0]) | re_symbol(syms[1])

    assert in_cg.pred_to_atoms[ms[0]] == [a1.in_atom, a3.in_atom]
    assert in_cg.pred_to_atoms[ms[1]] == [a2.in_atom, a3.in_atom]
    assert out_cg.pred_to_atoms[identity] == [a1.out_atom, a2.out_atom,
                                              a3.out_atom]

    check_metadata_list([a1, a2, a3])

### Basic checks on creating and manipulating path atoms ###

def test_atom_creation():
    in_cg.clear()
    out_cg.clear()
    m1 = match(srcip=ip1) & match(switch=2)
    a1 = atom(m1)
    assert a1.in_atom.policy == m1

### Basic path creation and expression capabilities ###

def test_path_creation():
    in_cg.clear()
    out_cg.clear()
    a = atom(match(srcip=ip2))
    assert isinstance(a, path)
    assert a.expr

def test_path_concatenation():
    in_cg.clear()
    out_cg.clear()
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(dstip=ip2))
    p = a1 ^ a2
    generate_re_trees([p])
    assert isinstance(p, path)
    assert p.re_tree == a1.re_tree ^ a2.re_tree
    # since a1, a2, themselves are path_concat objects internally, the
    # expression is flattened out, no longer (.) ^ (.) for basic atoms.
    #assert p.expr == ('(' + a1.expr + ') ^ (' + a2.expr + ')')

def test_path_alternation_1():
    in_cg.clear()
    out_cg.clear()
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(srcip=ip2))
    p = a1 | a2
    generate_re_trees([a1, a2])
    assert isinstance(p, path)
    assert p.re_tree == a1.re_tree | a2.re_tree
    assert p.expr == ('(' + a1.expr + ') | (' + a2.expr + ')')

def test_path_alternation_2():
    in_cg.clear()
    out_cg.clear()
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(srcip=ip2))
    p1 = a1 ^ a2
    p2 = a2 ^ a1
    p = p1 | p2
    generate_re_trees([a1, a2, p])
    assert isinstance(p, path)
    assert p.re_tree == p1.re_tree | p2.re_tree
    assert p.expr == ('(' + p1.expr + ') | (' + p2.expr + ')')

def test_path_kleene_closure():
    in_cg.clear()
    out_cg.clear()
    a1 = atom(match(srcip=ip1))
    p1 = +a1
    generate_re_trees([a1])
    assert isinstance(p1, path)
    assert p1.re_tree == +a1.re_tree
    assert p1.expr == '(' + a1.expr + ')*'
    p2 = +p1
    assert isinstance(p2, path)
    assert p2.re_tree == +a1.re_tree
    assert p2.expr == '(' + a1.expr + ')*'

def test_slightly_complicated_expr_1():
    in_cg.clear()
    out_cg.clear()
    a1 = atom(match(srcip=ip1, switch=2))
    a2 = atom(match(srcip=ip2, switch=1))
    a3 = atom(match(dstip=ip2))
    a4 = atom(match(dstip=ip1))
    a5 = atom(match(switch=1)) | atom(match(srcip=ip3))
    p = ((a1 ^ a4) | (a2 ^ a3)) & a5
    generate_re_trees([a1, a2, a3, a4, a5])
    assert isinstance(p, path)
    assert p.re_tree == (((a1.re_tree ^ a4.re_tree) | (a2.re_tree ^ a3.re_tree))
                         & a5.re_tree)
    #assert p.expr == ('(((' + a1.expr + ') ^ (' + a4.expr + ')) | ((' + a2.expr +
    #                  ') ^ (' + a3.expr + '))) & (' + a5.expr + ')')

### Path compilation testing ###

du = dfa_utils

def test_path_compile_1():
    in_cg.clear()
    out_cg.clear()
    a1 = atom(match(srcip=ip1))
    (in_tagging, in_capture, out_tagging, out_capture) = pathcomp.compile(a1)
    ref_in_tag = ((~match(srcip=ip1) >> ~match(path_tag=2) >>
                    modify(path_tag=2)) +
                  (match(path_tag=2)) +
                  (match(srcip=ip1, path_tag=1) >> modify(path_tag=2)) +
                  (match(srcip=ip1, path_tag=None) >> modify(path_tag=1)) +
                  (match(srcip=ip1, path_tag=3) >> modify(path_tag=2)))
    ref_out_tag = ((~identity >> ~match(path_tag=2) >>
                     modify(path_tag=2)) +
                   (match(path_tag=2)) +
                   (match(path_tag=1) >> identity >> modify(path_tag=3)) +
                   (match(path_tag=None) >> identity >> modify(path_tag=2)) +
                   (match(path_tag=3) >> identity >> modify(path_tag=2)))
    ref_in_cap  = drop
    ref_out_cap = (drop +
                   (match(path_tag=1) >> identity >> FwdBucket()))
    [x.compile() for x in [in_tagging, in_capture, out_tagging, out_capture,
                           ref_in_tag, ref_in_cap, ref_out_tag, ref_out_cap]]
    assert in_tagging._classifier == ref_in_tag._classifier
    assert in_capture._classifier == ref_in_cap._classifier
    assert out_tagging._classifier == ref_out_tag._classifier
    assert out_capture._classifier == ref_out_cap._classifier

def test_path_compile_2():
    in_cg.clear()
    out_cg.clear()
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(dstip=ip2))
    (in_tag, in_cap, out_tag, out_cap) = pathcomp.compile(a1 ^ a2)

    pred_a = match(srcip=ip1) & ~match(dstip=ip2)
    pred_b = match(dstip=ip2) & ~match(srcip=ip1)
    pred_c = match(srcip=ip1) & match(dstip=ip2)

    ref_in_tag = ((~(pred_a | pred_b | pred_c) >> ~match(path_tag=2) >>
                    modify(path_tag=2)) +
                  (match(path_tag=2)) +
                  ((match(path_tag=3) & pred_a) >> modify(path_tag=2)) +
                  ((match(path_tag=3) & pred_b) >> modify(path_tag=4)) +
                  ((match(path_tag=3) & pred_c) >> modify(path_tag=4)) +
                  ((match(path_tag=5) & pred_a) >> modify(path_tag=2)) +
                  ((match(path_tag=5) & pred_b) >> modify(path_tag=2)) +
                  ((match(path_tag=5) & pred_c) >> modify(path_tag=2)) +
                  ((match(path_tag=None) & pred_a) >> modify(path_tag=1)) +
                  ((match(path_tag=None) & pred_b) >> modify(path_tag=2)) +
                  ((match(path_tag=None) & pred_c) >> modify(path_tag=1)) +
                  ((match(path_tag=1) & pred_a) >> modify(path_tag=2)) +
                  ((match(path_tag=1) & pred_b) >> modify(path_tag=2)) +
                  ((match(path_tag=1) & pred_c) >> modify(path_tag=2)) +
                  ((match(path_tag=4) & pred_a) >> modify(path_tag=2)) +
                  ((match(path_tag=4) & pred_b) >> modify(path_tag=2)) +
                  ((match(path_tag=4) & pred_c) >> modify(path_tag=2)))
    ref_in_cap = drop
    ref_out_tag = ((~identity >> ~match(path_tag=2) >> modify(path_tag=2)) +
                   (match(path_tag=2)) +
                   (match(path_tag=3) >> identity >> modify(path_tag=2)) +
                   (match(path_tag=5) >> identity >> modify(path_tag=2)) +
                   (match(path_tag=None) >> identity >> modify(path_tag=2)) +
                   (match(path_tag=1) >> identity >> modify(path_tag=3)) +
                   (match(path_tag=4) >> identity >> modify(path_tag=5)))
    ref_out_cap = (drop +
                   (match(path_tag=4) >> identity >> FwdBucket()))

    [x.compile() for x in [in_tag, in_cap, out_tag, out_cap,
                           ref_in_tag, ref_in_cap, ref_out_tag, ref_out_cap]]
    assert in_tag._classifier == ref_in_tag._classifier
    assert in_cap._classifier == ref_in_cap._classifier
    assert out_tag._classifier == ref_out_tag._classifier
    assert out_cap._classifier == ref_out_cap._classifier

def test_in_out_compile_1():
    in_cg.clear()
    out_cg.clear()
    m1 = match(srcip=ip1)
    m2 = match(dstip=ip2)
    p = in_out_atom(match(srcip=ip1), match(dstip=ip2))
    (in_tag, in_cap, out_tag, out_cap) = pathcomp.compile(p)
    get_dead = match(path_tag=2)
    set_dead = modify(path_tag=2)

    ref_in_tag = ((~match(srcip=ip1) >> ~match(path_tag=2) >>
                    modify(path_tag=2)) +
                  (match(path_tag=2)) +
                  ((match(path_tag=None, srcip=ip1)) >>
                   modify(path_tag=1)) +
                  ((match(srcip=ip1, path_tag=1)) >> set_dead) +
                  ((match(srcip=ip1, path_tag=3)) >> set_dead))
    ref_in_cap = drop
    ref_out_tag = ((~m2 >> ~get_dead >> set_dead) +
                   (get_dead) +
                   ((match(path_tag=None) & m2) >> set_dead) +
                   ((match(path_tag=1) & m2) >> modify(path_tag=3)) +
                   ((match(path_tag=3) & m2) >> set_dead))
    ref_out_cap = ((drop) +
                   (match(path_tag=1, dstip=ip2) >> p.get_bucket()))

    [x.compile() for x in [in_tag, in_cap, out_tag, out_cap,
                           ref_in_tag, ref_in_cap, ref_out_tag, ref_out_cap]]

    assert in_tag == ref_in_tag
    assert out_tag == ref_out_tag
    assert in_cap == ref_in_cap
    assert out_cap == ref_out_cap
    # TODO: Why aren't the classifiers of tagging policies unequal?!
    # assert in_tag._classifier == ref_in_tag._classifier
    assert in_cap._classifier == ref_in_cap._classifier
    # assert out_tag._classifier == ref_out_tag._classifier
    assert out_cap._classifier == ref_out_cap._classifier

def test_in_out_compile_2():
    in_cg.clear()
    out_cg.clear()
    a1 = in_atom(match(srcip=ip1))
    a2 = out_atom(match(dstip=ip2))
    fb = FwdBucket()
    p = path_policy(a1 ^ a2, fb)
    (in_tag, in_cap, out_tag, out_cap) = pathcomp.compile(p)

    pred_a = match(srcip=ip1)
    pred_b = identity & ~match(srcip=ip1)
    pred_c = match(dstip=ip2)
    pred_d = identity & ~match(dstip=ip2)
    mtag = [match(path_tag=None)]
    atag = [modify(path_tag=None)]
    for i in range(1, 6):
        mtag.append(match(path_tag=i))
        atag.append(modify(path_tag=i))

    ref_in_tag = ((~(pred_b | pred_a) >> ~mtag[2] >> atag[2]) +
                  (mtag[2]) +
                  ((mtag[5] & pred_a) >> atag[2]) +
                  ((mtag[5] & pred_b) >> atag[2]) +
                  ((mtag[3] & pred_a) >> atag[4]) +
                  ((mtag[3] & pred_b) >> atag[4]) +
                  ((mtag[1] & pred_a) >> atag[2]) +
                  ((mtag[1] & pred_b) >> atag[2]) +
                  ((mtag[0] & pred_a) >> atag[1]) +
                  ((mtag[0] & pred_b) >> atag[2]) +
                  ((mtag[4] & pred_a) >> atag[2]) +
                  ((mtag[4] & pred_b) >> atag[2]))
    ref_out_tag = ((~(pred_c | pred_d) >> ~mtag[2] >> atag[2]) +
                   (mtag[2]) +
                   ((mtag[5] & pred_c) >> atag[2]) +
                   ((mtag[5] & pred_d) >> atag[2]) +
                   ((mtag[3] & pred_c) >> atag[2]) +
                   ((mtag[3] & pred_d) >> atag[2]) +
                   ((mtag[1] & pred_c) >> atag[3]) +
                   ((mtag[1] & pred_d) >> atag[3]) +
                   ((mtag[0] & pred_c) >> atag[2]) +
                   ((mtag[0] & pred_d) >> atag[2]) +
                   ((mtag[4] & pred_c) >> atag[5]) +
                   ((mtag[4] & pred_d) >> atag[2]))
    ref_in_cap = drop
    ref_out_cap = ((drop) +
                   ((mtag[4] & pred_c) >> fb))

    assert in_tag == ref_in_tag
    assert out_tag == ref_out_tag
    assert in_cap == ref_in_cap
    assert out_cap == ref_out_cap

    [x.compile() for x in [in_tag, in_cap, out_tag, out_cap,
                           ref_in_tag, ref_in_cap, ref_out_tag, ref_out_cap]]

    # TODO: figure out why classifier assertions are failing
    # assert in_tag._classifier == ref_in_tag._classifier
    assert in_cap._classifier == ref_in_cap._classifier
    # assert out_tag._classifier == ref_out_tag._classifier
    assert out_cap._classifier == ref_out_cap._classifier

def test_empty_paths():
    in_cg.clear()
    out_cg.clear()
    (in_tag, in_cap, out_tag, out_cap) = pathcomp.compile(path_empty())
    ref_tagging = ((identity >> ~match(path_tag=None) >>
                    modify(path_tag=None)) +
                   match(path_tag=None))
    ref_capture = drop
    [x.compile() for x in [in_tag, in_cap, out_tag, out_cap,
                           ref_tagging, ref_capture]]
    assert in_tag._classifier == ref_tagging._classifier
    assert in_cap._classifier == ref_capture._classifier
    assert out_tag._classifier == ref_tagging._classifier
    assert out_cap._classifier == ref_capture._classifier

### Tests for path policy ast folding routine. ###

ast_fold = path_policy_utils.path_policy_ast_fold
add_dyn  = path_policy_utils.add_dynamic_path_pols
re_pols  = pathcomp.__get_re_pols__

def test_ast_fold():
    in_cg.clear()
    out_cg.clear()
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(srcip=ip2))

    """ Base case folding. """
    val = ast_fold(a1, lambda a, x: a | ~(x.path), path_empty())
    assert val == path_empty() | ~a1

    """ Path policy unions are folded correctly. """
    val = ast_fold(a1 + a2, lambda x, y: y, ())
    assert val == a2
    val = ast_fold(a1 + a2, lambda x, y: x + [y], [])
    assert val == [a1+a2, a1, a2]
    val = ast_fold(a1 + a2, lambda x, y: x, [])
    assert val == []

    """ Get innermost policy of dynamic path policies when folding. """
    p1 = dynamic_path_policy(a1)
    val = ast_fold(p1, lambda x, y: y, [])
    assert val == a1

    p2 = dynamic_path_policy(a2)
    p3 = dynamic_path_policy(p2)
    val = ast_fold(p3, lambda x, y: y, [])
    assert val == a2

    """ Aggregate dynamic policies as ast traversal goes. """
    val = ast_fold(p1 + p3, add_dyn, set())
    assert val == set([p1, p2, p3])

    """ Test re-policy extraction lambda. """
    val = ast_fold(p1 + p3, re_pols, ([], []))
    assert val == ([a1.re_tree, a2.re_tree], [a1.get_bucket(), a2.get_bucket()])

### Unit test class-based token generation using the various atom types ###

def test_CG_token_equivalence_classes_1():
    cg.clear()
    m = match(srcip=ip1)
    tok1 = cg.get_token(m, toktype="test1")
    tok2 = cg.get_token(m, toktype="test2")
    assert tok1 != tok2

def test_CG_token_equivalence_classes_2():
    cg.clear()
    m = match(srcip=ip1)
    tok1 = cg.get_token(m, toktype="test1", nonoverlapping_filters=False)
    tok2 = cg.get_token(m, toktype="test1", nonoverlapping_filters=False)
    assert tok1 != tok2

def test_CG_token_equivalence_classes_3():
    cg.clear()
    m = match(srcip=ip1)
    tok1 = cg.get_token(m, toktype="test1")
    tok2 = cg.get_token(m, toktype="test1")
    assert tok1 == tok2

### Initialize end_path and drop_atom classes and ensure they get tokens ###

def test_end_path():
    cg.clear()
    m = match(srcip=ip1)
    a1 = atom(m)
    a2 = end_path(m)
    a3 = atom(m)
    a4 = end_path(m)
    assert a1.token and a2.token and a3.token
    assert a1.token == a3.token
    assert a1.token != a2.token
    assert a2.token == a4.token

def test_drop_atom():
    cg.clear()
    m = match(srcip=ip1)
    a1 = atom(m)
    a2 = drop_atom(m)
    a3 = drop_atom(m)
    assert a1.token and a2.token
    assert a1.token != a2.token
    assert a2.token == a3.token

### Basic compilation for end_path and drop atoms ###

def test_endpath_drop_finalization():
    cg.clear()
    pathcomp.clear()
    p1 = end_path(match(srcip=ip1))
    p2 = drop_atom(match(srcip=ip1))
    pathcomp.finalize(p1)
    pathcomp.finalize(p2)
    assert pathcomp.re_list and pathcomp.paths_list and pathcomp.path_to_bucket
    assert pathcomp.re_list == [p1.expr, p2.expr]
    assert pathcomp.paths_list == [ [p1], [p2] ]

def test_endpath_compilation():
    cg.clear()
    pathcomp.clear()
    p = end_path(match(srcip=ip1))
    endpath = pathcomp.compile([p]).get_endpath()
    assert endpath == ((match({'path_tag': None}) &
                        match(srcip=ip1)) >> p.bucket_instance)

def test_drop_compilation():
    cg.clear()
    pathcomp.clear()
    p = drop_atom(match(srcip=ip1))
    dropping = pathcomp.compile([p]).get_dropping()
    assert dropping == ((match({'path_tag': None}) &
                         match(srcip=ip1)) >> p.bucket_instance)

def test_multiple_atomtype_compilation_1():
    cg.clear()
    pathcomp.clear()
    a1 = atom(match(srcip=ip1))
    a2 = end_path(match(dstip=ip2))
    p = a1 ^ a2
    frags = pathcomp.compile([p])
    tagging = frags.get_tagging()
    counting = frags.get_counting()
    endpath = frags.get_endpath()
    assert tagging == (drop +
                       (match(srcip=ip1,path_tag=None) >>
                        modify(path_tag=1)) +
                       (identity & ~match(srcip=ip1, path_tag=None)))
    assert counting == drop
    assert endpath == (match(path_tag=1,dstip=ip2) >>
                       p.bucket_instance)

def test_multiple_atomtype_compilation_2():
    cg.clear()
    pathcomp.clear()
    a1 = atom(match(srcip=ip1))
    a2 = drop_atom(match(dstip=ip2))
    p = a1 ^ a2
    frags = pathcomp.compile([p])
    tagging = frags.get_tagging()
    counting = frags.get_counting()
    dropping = frags.get_dropping()
    assert tagging == (drop +
                       (match(srcip=ip1,path_tag=None) >>
                        modify(path_tag=1)) +
                       (identity & ~match(srcip=ip1, path_tag=None)))
    assert counting == drop
    assert dropping == (match(path_tag=1,dstip=ip2) >>
                        p.bucket_instance)

def test_multiple_atomtype_compilation_3():
    cg.clear()
    pathcomp.clear()
    a1 = atom(match(srcip=ip1))
    a2 = drop_atom(match(dstip=ip2))
    a3 = end_path(match(srcip=ip3))
    a4 = atom(match(srcip=ip4))
    p1 = a1 ^ a2
    p2 = a1 ^ a3
    p3 = a1 ^ a4
    frags = pathcomp.compile([p1, p2, p3])
    tagging = frags.get_tagging()
    counting = frags.get_counting()
    endpath = frags.get_endpath()
    dropping = frags.get_dropping()
    assert tagging == (drop +
                       (match(srcip=ip1,path_tag=None) >>
                        modify(path_tag=1)) +
                       (match(srcip=ip4,path_tag=1) >>
                        modify(path_tag=4)) +
                       (identity &
                        (~match(srcip=ip1, path_tag=None)) &
                        (~match(srcip=ip4, path_tag=1))))
    assert counting == (match(srcip=ip4, path_tag=1) >>
                        p3.bucket_instance)
    assert endpath  == (match(srcip=ip3, path_tag=1) >>
                        p2.bucket_instance)
    assert dropping == (match(dstip=ip2, path_tag=1) >>
                        p1.bucket_instance)

def test_hook_compilation_1():
    cg.clear()
    pathcomp.clear()
    a1 = atom(match(srcip=ip1))
    h2 = hook(match(srcip=ip2), ['srcip'])
    a3 = atom(match(srcip=ip3))
    p = a1 ^ h2 ^ a3
    hooks = pathcomp.compile([p]).get_hooks()
    assert hooks == match(path_tag=2) >> FwdBucket()

def test_hook_compilation_2():
    cg.clear()
    pathcomp.clear()
    a1 = atom(match(srcip=ip1))
    h2 = hook(match(srcip=ip2), ['srcip'])
    h3 = hook(match(srcip=ip3), ['dstip'])
    p = a1 ^ h2 ^ h3
    hooks = pathcomp.compile([p]).get_hooks()
    assert hooks == ((match(path_tag=4) + match(path_tag=2))
                     >> FwdBucket())



# Just in case: keep these here to run unit tests in vanilla python
if __name__ == "__main__":

    test_overlap_mode()
    test_classifier_ne_inters()

    test_CG_token_gen()

    test_CG_token_equality_1()
    test_CG_token_equality_2()
    test_CG_token_equality_3()

    test_CG_equal_matches()
    test_CG_unequal_matches()
    test_CG_superset_matches()
    test_CG_subset_matches()
    test_CG_intersection_matches_1()
    test_CG_intersection_matches_2()

    test_atom_creation()

    test_path_creation()
    test_path_concatenation()
    test_path_alternation_1()
    test_path_alternation_2()
    test_path_kleene_closure()

    test_slightly_complicated_expr_1()

    test_path_compile_1()
    test_path_compile_2()
    test_in_out_compile_1()
    test_in_out_compile_2()
    test_empty_paths()

    test_ast_fold()

    print "If this message is printed without errors before it, we're good."
    print "Also ensure all unit tests are listed above this line in the source."
    sys.exit(0)

    # XXX: legacy tests from old token generator remain
    # for testing later if token types are re-introduced.
    test_CG_token_equivalence_classes_1()
    test_CG_token_equivalence_classes_2()
    test_CG_token_equivalence_classes_3()

    test_end_path()
    test_drop_atom()

    test_endpath_drop_finalization()
    test_endpath_compilation()
    test_drop_compilation()
    test_multiple_atomtype_compilation_1()
    test_multiple_atomtype_compilation_2()
    test_multiple_atomtype_compilation_3()

    test_hook_compilation_1()
    test_hook_compilation_2()

