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

import copy
import pytest

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
cg = CharacterGenerator

### Character generator basic sanity checks ###

def test_CG_token_gen():
    """Ensure you get a token back."""
    m = match(srcip=ip1) & match(switch=1)
    new_token = cg.get_token(m)
    assert new_token

def test_CG_token_equality_1():
    m1 = match(srcip=ip1)
    m2 = m1
    token1 = cg.get_token(m1)
    token2 = cg.get_token(m2)
    assert token1 == token2

def test_CG_token_equality_2():
    m1 = match(srcip=ip1)
    m2 = copy.deepcopy(m1)
    token1 = cg.get_token(m1)
    token2 = cg.get_token(m2)
    assert token1 == token2

def test_CG_token_equality_3():
    m1 = match(srcip=ip1)
    m2 = match(srcip=ip1) & match(switch=2)
    token1 = cg.get_token(m1)
    token2 = cg.get_token(m2)
    assert token1 != token2

def test_CG_policy_equality():
    m = match(srcip=ip1)
    tok = cg.get_token(m)
    assert cg.token_to_filter[tok] == m

### Basic checks on creating and manipulating path atoms ###

def test_atom_creation():
    m1 = match(srcip=ip1) & match(switch=2)
    a1 = atom(m1)
    assert a1.policy == m1

def test_atom_and_1():
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(switch=1))
    assert (a1 & a2).policy == (match(srcip=ip1) & match(switch=1))

def test_atom_and_2():
    a1 = atom(match(srcip=ip1))
    a2 = a1 & atom(match(switch=1))
    assert isinstance(a2, atom)
    assert a2.policy == (match(srcip=ip1) & match(switch=1))

def test_atom_negate():
    a1 = atom(match(srcip=ip1))
    assert (~a1).policy == (~match(srcip=ip1))

# TODO(ngsrinivas): skipping test_atom_or and test_atom_difference, since these
# two don't work currently. Adding two atoms will result in a TypeError (it
# results in a `parallel` type, not a `Filter` type), and difference
# implementation is just buggy in the language right now.

### Basic token generation capabilities for atoms ###

def test_atom_token_generation_1():
    a = atom(match(srcip=ip1))
    assert a.token

def test_atom_token_generation_2():
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(srcip=ip2))
    a3 = atom(match(srcip=ip1))
    assert a1.token != a2.token
    assert a1.token == a3.token

### Basic path creation and expression capabilities ###

def test_path_creation_1():
    a = atom(match(srcip=ip2))
    assert isinstance(a, path)
    assert a.expr

def test_path_creation_2():
    a = path(expr='abc|def')
    assert isinstance(a, path)
    assert a.expr

def test_path_concatenation():
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(dstip=ip2))
    p = a1 ^ a2
    assert isinstance(p, path)
    assert p.expr == (a1.expr + a2.expr)

def test_path_alternation():
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(srcip=ip2))
    p = a1 | a2
    assert isinstance(p, path)
    assert p.expr == ('(' + a1.expr + ')|(' + a2.expr + ')')

def test_path_kleene_closure():
    a1 = atom(match(srcip=ip1))
    p1 = +a1 # kleene closure is a unary prefix '+' as of now.
    assert isinstance(p1, path)
    assert p1.expr == '(' + a1.expr + ')*'
    p2 = +p1
    assert isinstance(p2, path)
    assert p2.expr == '(' + p1.expr + ')*'

### Slightly more complicated path expressions testing ###

def test_slightly_complicated_expr_1():
    a1 = atom(match(srcip=ip1, switch=2))
    a2 = atom(match(srcip=ip2, switch=1))
    a3 = atom(match(dstip=ip2))
    a4 = atom(match(dstip=ip1))
    p = (a1 ^ a4) | (a2 ^ a3)
    assert isinstance(p, path)
    assert p.expr == ('(' + a1.expr + a4.expr + ')|(' + a2.expr +
                      a3.expr + ')')

### Simple tests on dfa_utils ### 

### These are some very basic sanity checks, but it's best to confirm
### correctness by visually inspecting the DFA from ml-ulex for these lists of
### regexes, and ensuring the printed DFA from du.print_dfa is consistent.

du = dfa_utils

def test_dfa_const_1():
    re_list = ['ab', 'cd']
    tmp_file = '/tmp/my_regexes.txt'
    dfa = du.regexes_to_dfa(re_list, tmp_file) 
    assert dfa # i.e., we get the dfa without errors.
    assert du.get_num_states(dfa) == 5
    assert du.get_num_transitions(dfa) == 4
    assert du.get_num_accepting_states(dfa) == 2

def test_dfa_const_2():
    re_list = ['ab',
               'a|b',
               'abb*',
               'cd | ef',
               '((ac)|(bd))*e',
               '\ufc66ab']
    tmp_file = '/tmp/my_regexes.txt'
    dfa = du.regexes_to_dfa(re_list, tmp_file) 
    assert dfa
    assert du.get_num_states(dfa) == 15
    assert du.get_num_transitions(dfa) == 19
    assert du.get_num_accepting_states(dfa) == 8

def test_regex_intersection():
    tmp = '/tmp/my_regexes_int.txt'
    assert not du.intersection_is_null('ab*', 'a*b', tmp)
    assert du.intersection_is_null('ab', 'cd', tmp)
    assert not du.intersection_is_null('ab|cd', 'ef|a*b*', tmp)

### Test path finalization and compilation ###

def test_path_finalize_1():
    path.clear()
    a1 = atom(match(srcip=ip2))
    a2 = atom(match(switch=2))
    p = a1 ^ a2
    path.finalize(p)
    assert path.re_list and path.paths_list and path.path_to_bucket
    assert path.re_list == [p.expr]
    assert path.paths_list == [[p]]
    assert isinstance(path.path_to_bucket[p], Query)

def test_path_finalize_2():
    path.clear()
    a1 = atom(match(srcip=ip2))
    a2 = atom(match(switch=2))
    p1 = a1 ^ a2
    p2 = a1 | a2
    path.finalize(p1)
    path.finalize(p2)
    assert path.re_list == [p1.expr, p2.expr]
    assert path.paths_list == [ [p1], [p2] ]
    for p in path.path_to_bucket:
        assert isinstance(path.path_to_bucket[p], Query)

def test_path_compile_1():
    path.clear()
    a1 = atom(match(srcip=ip1))
    path.finalize(a1)
    [tags, counts] = path.compile()
    # Note: this test depends on state numbers, which eventually get changed
    # into tags. So it's not implementation detail-independent. Also, it relies
    # on the fact that vlan is used for packet tagging.
    ref_tags = ((match(vlan_id=0xffff, vlan_pcp=0) & match(srcip=ip1))
                >> modify(vlan_id=1, vlan_pcp=0))
    ref_counts = ((match(vlan_id=0xffff, vlan_pcp=0) & match(srcip=ip1)) >>
                  FwdBucket())
    [x.compile() for x in [tags, ref_tags, counts, ref_counts]]
    assert tags._classifier
    assert counts._classifier
    assert tags._classifier == ref_tags._classifier
    assert counts._classifier == ref_counts._classifier

def test_path_compile_2():
    path.clear()
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(dstip=ip2))
    path.finalize(a1 ^ a2)
    [tags, counts] = path.compile()
    # Note: Caveats in test_path_compile_1 apply.
    ref_tags = (((match(vlan_id=0xffff, vlan_pcp=0) & match(srcip=ip1))
                 >> modify(vlan_id=1, vlan_pcp=0)) +
                ((match(vlan_id=1, vlan_pcp=0) & match(dstip=ip2))
                 >> modify(vlan_id=2, vlan_pcp=0)))
    ref_counts = ((match(vlan_id=1, vlan_pcp=0) & match(dstip=ip2)) >>
                  FwdBucket())
    [x.compile() for x in [tags, ref_tags, counts, ref_counts]]
    assert tags._classifier
    assert counts._classifier
    assert tags._classifier == ref_tags._classifier
    assert counts._classifier == ref_counts._classifier

# Just in case: keep these here to run unit tests in vanilla python
if __name__ == "__main__":

    test_CG_token_gen()
    test_CG_token_equality_1()
    test_CG_token_equality_2()
    test_CG_token_equality_3()
    test_CG_policy_equality()

    test_atom_creation()
    test_atom_and_1()
    test_atom_and_2()
    test_atom_negate()

    test_atom_token_generation_1()
    test_atom_token_generation_2()

    test_path_creation_1()
    test_path_creation_2()
    test_path_concatenation()
    test_path_alternation()
    test_path_kleene_closure()

    test_slightly_complicated_expr_1()

    test_dfa_const_1()
    test_dfa_const_2()
    test_regex_intersection()

    test_path_finalize_1()
    test_path_finalize_2()
    test_path_compile_1()
    test_path_compile_2()

    print "If this message is printed without errors before it, we're good."
    print "Also ensure all unit tests are listed above this line in the source."
