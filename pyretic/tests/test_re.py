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
from pyretic.lib.re import *

import pytest

def test_normal_forms():
    # Declare some regular expressions first.
    x1 = re_symbol('x')
    x2 = re_concat(re_symbol('x'), re_symbol('y'))
    x3 = re_concat(x2, re_symbol('z'))
    x4 = re_symbol('y')
    x5 = re_inters([x1, x4])
    x6 = re_alter([x1, x4])
    l = [x1, x2, x3, x4, x5]

    # Check various representation invariants
    assert is_normal(re_empty())
    assert is_normal(re_epsilon())
    assert is_normal(x1)
    assert is_normal(x2)
    assert not is_normal(x3)
    assert is_normal(x4)
    assert is_normal

    assert not is_normal(re_star(re_epsilon()))
    assert not is_normal(re_star(re_empty()))

    for x in l:
        assert not is_normal(re_star(re_star(x)))
        assert is_normal(re_star(x)) == is_normal(x)
        assert not is_normal(re_negate(re_negate(x)))
        assert is_normal(re_negate(x)) == is_normal(x)
        assert not is_normal(re_inters([x]))
        assert not is_normal(re_concat(re_empty(), x))
        assert not is_normal(re_concat(x, re_empty()))
        assert not is_normal(re_concat(x, re_epsilon()))

    assert not is_normal(re_inters([x1]))
    assert is_normal(re_inters([x1, x4]))
    assert not is_normal(re_inters([x1, x2, x3, x4]))
    assert not is_normal(re_inters([x1, x1]))
    assert not is_normal(re_inters([x1, x2]))
    assert not is_normal(re_inters([x4, x1]))
    assert is_normal(re_inters([x2, x1, x4]))
    assert not is_normal(re_inters([x5, x2]))
    assert is_normal(re_inters([x6, x1]))

    assert not is_normal(re_alter([x1]))
    assert is_normal(re_alter([x1, x4]))
    assert not is_normal(re_alter([x1, x2, x3, x4]))
    assert not is_normal(re_alter([x1, x1]))
    assert not is_normal(re_alter([x1, x2]))
    assert not is_normal(re_alter([x4, x1]))
    assert is_normal(re_alter([x2, x1, x4]))
    assert not is_normal(re_alter([x6, x2]))
    assert is_normal(re_alter([x5, x1]))

    assert is_normal(re_alter([re_star(re_symbol('c')),
                              re_epsilon(),
                              re_empty()]))

def test_smart_constructors():
    # Declare some basic re's first
    eps = re_epsilon()
    phi = re_empty()
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')

    # Ensure normality of expressions put together using various operators
    assert is_normal(a)
    assert is_normal(eps)
    assert is_normal(phi)
    assert is_normal(a ^ b)
    assert is_normal(+(+(b)))
    assert is_normal(a | (b | c))
    assert is_normal(a & (b | c))
    assert is_normal(c & b & a)
    assert is_normal(a & a)
    assert is_normal(c | c | b)
    assert is_normal(++eps)
    assert is_normal(~a)
    assert is_normal(~~a)
    assert is_normal(~phi)
    assert is_normal((a ^ b) ^ c)
    assert is_normal(a ^ eps ^ b ^ eps)
    assert is_normal(phi ^ c)
    assert is_normal(eps ^ b ^ b)
    assert is_normal(a | (b | a))

def test_nullable():
    eps = re_epsilon()
    phi = re_empty()
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')
    r = (a|b) ^ (b|eps) ^ +c

    assert nullable(eps) == eps
    assert nullable(phi) == phi
    assert nullable(a) == phi
    assert nullable(a | eps) == eps
    assert nullable(a & eps) == nullable(a) & nullable(eps)
    assert nullable(eps & eps) == nullable(eps) & nullable(eps)
    assert nullable(b ^ eps) == nullable(b) & nullable(eps)
    assert nullable(+r) == eps
    assert nullable(a | b) == nullable(a) | nullable(b)
    assert nullable(~a) == eps
    assert nullable(~eps) == phi

def test_deriv():
    # Declare some basic re's first
    eps = re_epsilon()
    phi = re_empty()
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')
    symbols = [a, b, c]

    # write some regular expressions for later testing
    r1 = (a | b) ^ (+c)
    r2 = a | (b | a)
    r3 = (~(a ^ b)) & (~(c ^ a))
    l = symbols + [eps, phi, r1, r2, r3]

    # Check derivative equality with concatenation
    assert deriv(phi, a) == phi
    assert deriv(eps, a) == phi
    assert deriv(b, a) == phi
    assert deriv(b, b) == eps
    assert deriv(a ^ b, a) == b

    # Sample tests with small mixes of various operations
    assert deriv(+a ^ b, a) == +a ^ b
    assert deriv(+a ^ b, b) == re_epsilon()
    assert deriv(+a | b | (a ^ b), a) == +a | b
    assert deriv(~a, a) == ~re_epsilon()
    assert deriv(~b, a) == ~re_empty()
    assert deriv(~(a | (a ^ b)), a) == ~(re_epsilon() | b)
    assert deriv(~(+a ^ b ^ b) & (a ^ +b), a) == ~(+a ^ b ^ b) & +b
    assert deriv(~(+a ^ b ^ b) & (a ^ +b), b) == re_empty()

    # Some basic regression for star and negate
    for r in l:
        for s in symbols:
            assert deriv(+r, s) == (deriv(r,s) ^ +r)
            assert deriv(~r, s) == ~deriv(r, s)

    # Some more regression for intersection, alternation and concatenation
    for r1 in l:
        for r2 in l:
            for r3 in l:
                for s in symbols:
                    if not isinstance(r1, re_concat):
                        assert deriv(r1 ^ r2, s) == ((deriv(r1, s) ^ r2) |
                                                     (nullable(r1) ^
                                                      deriv(r2, s)))
                    assert deriv(r1 | r2, s) == (deriv(r1, s) |
                                                 deriv(r2, s))
                    assert deriv(r1 | r2 | r3, s) == (deriv(r3, s) |
                                                      deriv(r2, s) |
                                                      deriv(r1, s))
                    assert deriv(r1 & r2, s) == (deriv(r1, s) &
                                                 deriv(r2, s))
                    assert deriv(r1 & r2 & r3, s) == (deriv(r3, s) &
                                                      deriv(r2, s) &
                                                      deriv(r1, s))

def test_match():
    # declare some symbols first
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')
    d = re_symbol('d')
    e = re_symbol('e')
    eps = re_epsilon()
    phi = re_empty()

    # simple tests to test out matching using derivatives
    r = a ^ +b
    s = 'abb'
    assert match_string(r, s)
    s = ''
    assert not match_string(r, s)
    s = 'aba'
    assert not match_string(r, s)
    r = (a | b) ^ (c | d) ^ e
    s = 'abe'
    assert not match_string(r, s)
    s = 'ace'
    assert match_string(r, s)
    r = (~(a ^ +b)) | (a ^ b)
    s = 'ab'
    assert match_string(r, s)
    s = 'abb'
    assert not match_string(r, s)
    s = 'cde'
    assert match_string(r, s)
    r = ((~a) & (~(b ^ c))) | +(d ^ e)
    s = 'bc'
    assert not match_string(r, s)
    s = 'a'
    assert not match_string(r, s)
    s = 'dede'
    assert match_string(r, s)
    s = 'dedea'
    assert match_string(r, s)
    s = ''
    assert match_string(r, s)

def test_dfa():
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')
    dfa1 = makeDFA((a ^ b) | (a ^ c), 'abc')
    dfa2 = makeDFA((a ^ c) | (b ^ c), 'abc')
    dfa3 = makeDFA((+a) | (b ^ c), 'abc')

    assert dfa1.accepts('ab')
    assert not dfa1.accepts('bc')
    assert not dfa1.accepts('ca')
    assert dfa2.accepts('ac')
    assert not dfa2.accepts('')
    assert dfa2.accepts('bc')
    assert not dfa1.accepts('')
    assert dfa3.accepts('')
    assert dfa3.accepts('bc')
    assert not dfa3.accepts('b')
    assert dfa3.accepts('aaaa')

def test_dot():
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')
    symbol_list = 'abc'

    expr_list = [(a ^ b) | (a ^ c),
                (+a) | (b ^ c),
                (+a) & ~(a ^ a ^ a)]

    import subprocess
    file_prefix = "/tmp/re_test_"
    index = 0

    for e in expr_list:
        index += 1
        d = makeDFA(e, symbol_list)
        dot_text = d.dot_repr()
        fname = file_prefix + str(index) + '.txt'
        f = open(fname, 'w')
        f.write(dot_text)
        f.close()
        # print "Printing DFA for expression:", e
        # output = subprocess.check_output(['dot', '-Tx11', fname])
        # print dot_text

def test_smart_constructors_metadata():
    """ Test if smart constructors remember objects with metadata correctly. """
    a  = re_symbol('a')
    a1 = re_symbol('a', metadata='ingress')
    a2 = re_symbol('a', metadata='egress')
    b  = re_symbol('b')
    b1 = re_symbol('b', metadata='hook')
    c  = re_symbol('c')
    c1 = re_symbol('c', metadata='ingress')
    c2 = re_symbol('c', metadata='egress')
    symbol_list = 'cba'

    assert a.get_metadata() == []
    assert a1 == a

    assert a1 & a == a
    assert (a1 & a).get_metadata() == ['ingress']
    assert c1 & c & c2 == c
    assert (c1 & c2 & c).get_metadata() == ['ingress', 'egress']
    assert (c1 & c2 & c & c2).get_metadata() == ['ingress', 'egress', 'egress']
    assert c1 & c2 & c & c2 == c

    assert a1 | a == a
    assert (a1 | a).get_metadata() == ['ingress']
    assert c1 | c | c2 == c
    assert (c1 | c2 | c).get_metadata() == ['ingress', 'egress']
    assert (c1 | c2 | c | c2).get_metadata() == ['ingress', 'egress', 'egress']
    assert c1 | c2 | c | c2 == c

def test_deriv_metadata():
    """ Test if derivation works well when consuming derivatives """
    a  = re_symbol('a')
    a1 = re_symbol('a', metadata='ingress')
    a2 = re_symbol('a', metadata='egress')
    b  = re_symbol('b')
    b1 = re_symbol('b', metadata='hook')
    c  = re_symbol('c')
    c1 = re_symbol('c', metadata='ingress')
    c2 = re_symbol('c', metadata='egress')

    # tests for sample expressions
    (d, r) = deriv_consumed(a1, a)
    assert d == re_epsilon()
    assert len(r) == 1 and r == a1.get_metadata()

    (d, r) = deriv_consumed(c2, c)
    assert d == re_epsilon()
    assert len(r) == 1 and r == c2.get_metadata()

    (d, r) = deriv_consumed(a1, b)
    assert d == re_empty()
    assert len(r) == 0

    (d, r) = deriv_consumed(a1 ^ b, a)
    assert d == b
    assert len(r) == 1 and r == a1.get_metadata()

    (d, r) = deriv_consumed(c1 | c2, c)
    assert d == re_epsilon()
    assert len(r) == 2
    assert r == c1.get_metadata() + c2.get_metadata()

    (d, r) = deriv_consumed((c1 ^ a) | (c2 ^ b), c)
    assert d == a | b
    assert len(r) == 2
    assert sorted(r) == sorted(c1.get_metadata() + c2.get_metadata())

    (d, r) = deriv_consumed((c1 | a) & (c2 | b), c)
    assert d == re_epsilon()
    assert len(r) == 2
    assert sorted(r) == sorted(c1.get_metadata() + c2.get_metadata())

    (d, r) = deriv_consumed(~(c2 & (+c) & (c1 ^ b)), c)
    assert d == ~(re_epsilon() & (re_epsilon() ^ +c) & b)
    assert len(r) == 2
    assert sorted(r) == sorted(c1.get_metadata() + c2.get_metadata())

    (d, r) = deriv_consumed((a1 ^ +c1) & ~(a2 ^ c1 ^ c2), a)
    assert d == +c & ~(c ^ c)
    assert len(r) == 2
    assert sorted(r) == sorted(a1.get_metadata() + a2.get_metadata())

def test_dfa_metadata():
    """ Check if metadata is stored appropriately mapping to the transitions in
    the resulting DFA from specific regular expressions. """
    a  = re_symbol('a')
    a1 = re_symbol('a', metadata='ingress')
    a2 = re_symbol('a', metadata='egress')
    b  = re_symbol('b')
    b1 = re_symbol('b', metadata='ingress')
    b2 = re_symbol('b', metadata='egress')
    c  = re_symbol('c')
    c1 = re_symbol('c', metadata='ingress')
    c2 = re_symbol('c', metadata='egress')
    c3 = re_symbol('c', metadata='hook')
    d  = re_symbol('d')
    symbol_list = 'abcd'

    def list_equals_meta_structural(x, y):
        return reduce(lambda acc, (u,v): acc and u.equals_meta_structural(v),
                      zip(x, y),
                      True)

    # make DFAs, and check all metadata transitions
    e = a1
    tt = makeDFA(e, symbol_list).transition_table
    assert tt.get_metadata(a1, 'a') == a1.get_metadata()
    assert tt.get_metadata(re_empty(), 'a') == []

    e = a1 ^ b
    tt = makeDFA(e, symbol_list).transition_table
    assert tt.get_metadata(a1 ^ b, 'a') == a1.get_metadata()
    assert tt.get_metadata(b, 'b') == []
    assert tt.get_metadata(re_empty(), 'a') == []

    e = c1 | c2
    tt = makeDFA(e, symbol_list).transition_table
    assert (sorted(tt.get_metadata(c1 | c2, 'c')) ==
            sorted(c1.get_metadata() + c2.get_metadata()))
    assert tt.get_metadata(re_empty(), 'c') == []

    e = (c1 ^ a2 ^ c3) | (c2 ^ b1 ^ c)
    tt = makeDFA(e, symbol_list).transition_table
    assert (sorted(tt.get_metadata(e, 'c')) ==
            sorted(c1.get_metadata() + c2.get_metadata()))
    r1 = (a ^ c) | (b ^ c)
    assert tt.get_metadata(r1, 'a') == a2.get_metadata()
    assert tt.get_metadata(r1, 'b') == b1.get_metadata()
    assert tt.get_metadata(c, 'c') == c3.get_metadata()
    assert tt.get_metadata(re_empty(), 'b') == []

    e = (+c1 ^ a1 ^ b ^ a2) | (c2 ^ c3 ^ b1 ^ a1)
    dfa = makeDFA(e, symbol_list)
    tt = dfa.transition_table
    st = dfa.all_states
    assert (sorted(tt.get_metadata(e, 'c')) ==
            sorted(c1.get_metadata() + c2.get_metadata()))
    r1 = (+c ^ a ^ b ^ a) | (c ^ b ^ a)
    assert (sorted(tt.get_metadata(r1, 'c')) ==
            sorted(c1.get_metadata() + c3.get_metadata()))
    assert list_equals_meta_structural(st.get_expressions(b ^ a), [b ^ a2])
    assert tt.get_metadata(b ^ a, 'b') == []
    assert list_equals_meta_structural(st.get_expressions(a), [a2, a1])

    e = (+c1 ^ c3 ^ b ^ a2) | (c2 ^ c3 ^ b1 ^ a1)
    tt = makeDFA(e, symbol_list).transition_table
    assert (sorted(tt.get_metadata(e, 'c')) ==
            sorted(c1.get_metadata() + c2.get_metadata() + c3.get_metadata()))

    e = (b1 ^ c1 ^ b ^ a2) | (c3 ^ b1 ^ b1 ^ a1)
    dfa = makeDFA(e, symbol_list)
    tt = dfa.transition_table
    st = dfa.all_states
    assert tt.get_metadata(e, 'c') == c3.get_metadata()
    assert list_equals_meta_structural(st.get_expressions(b ^ a),
                            [b ^ a2, b1 ^ a1])
    assert tt.get_metadata(b ^ a, 'b') == b1.get_metadata()
    assert list_equals_meta_structural(st.get_expressions(a), [a2, a1])
    assert (sorted(tt.get_metadata(a, 'a')) ==
            sorted(a1.get_metadata() + a2.get_metadata()))

    e = (+c1 ^ a1 ^ b2 ^ a2) | (c ^ d ^ b1 ^ a1)
    dfa = makeDFA(e, symbol_list)
    st = dfa.all_states
    tt = dfa.transition_table
    assert list_equals_meta_structural(st.get_expressions(b ^ a),
                            [b2 ^ a2, b1 ^ a1])
    assert (sorted(tt.get_metadata(b ^ a, 'b')) ==
            sorted(b1.get_metadata() + b2.get_metadata()))
    assert list_equals_meta_structural(st.get_expressions(a), [a2, a1])
    assert (sorted(tt.get_metadata(a, 'a')) ==
            sorted(a1.get_metadata() + a2.get_metadata()))

def test_dfa_vector():
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')
    d = re_symbol('d')
    e1 = (a ^ b) | (a ^ c)
    e2 = (a ^ c) | (b ^ c)
    e3 = (+a) | (b ^ c)
    e4 = (+a ^ +b) | (c ^ d)
    symlist = 'abcd'

    # base case: single expression lists.
    dfa1 = makeDFA_vector([e1], symlist)
    dfa2 = makeDFA_vector([e2], symlist)
    dfa3 = makeDFA_vector([e3], symlist)

    assert dfa1.accepts('ab')
    assert not dfa1.accepts('bc')
    assert not dfa1.accepts('ca')
    assert dfa2.accepts('ac')
    assert not dfa2.accepts('')
    assert dfa2.accepts('bc')
    assert not dfa1.accepts('')
    assert dfa3.accepts('')
    assert dfa3.accepts('bc')
    assert not dfa3.accepts('b')
    assert dfa3.accepts('aaaa')

    # try multiple expression tests :)
    dfa12 = makeDFA_vector([e1, e2], symlist)
    assert dfa12.accepts('ab')
    assert dfa12.accepts('bc')
    assert not dfa12.accepts('abc')
    assert not dfa12.accepts('ca')
    assert dfa12.accepts('ac')
    assert not dfa12.accepts('')
    assert dfa12.accepts('bc')
    assert not dfa12.accepts('')

    dfa23 = makeDFA_vector([e2, e3], symlist)
    assert dfa23.accepts('ac')
    assert dfa23.accepts('')
    assert dfa23.accepts('bc')
    assert not dfa23.accepts('b')
    assert dfa23.accepts('aaaa')
    assert not dfa23.accepts('aaaaaaaab')
    assert dfa23.accepts('aaaaaaaaa')

    dfa1234 = makeDFA_vector([e1, e2, e3, e4], symlist)
    assert dfa1234.accepts('')
    assert dfa1234.accepts('ac')
    assert dfa1234.accepts('ab')
    assert dfa1234.accepts('aaaaaaaaab')
    assert dfa1234.accepts('aaaaaaaaabbbbbb')
    assert not dfa1234.accepts('aaaaaaaaabbbbbbc')
    assert not dfa1234.accepts('c')
    assert dfa1234.accepts('cd')

def test_dot_vector():
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')
    d = re_symbol('d')
    symbol_list = 'abcd'

    expr_list1 = [(a ^ b) | (a ^ c),
                (+a) | (b ^ c),
                (+a) & ~(a ^ a ^ a)]
    expr_list2 = [(+c ^ a ^ b ^ a) | (c ^ d ^ b ^ a),
                  (c ^ a ^ c) | (c ^ b ^ c)]

    re_lists = [expr_list1, expr_list2]

    import subprocess
    file_prefix = "/tmp/re_test_"
    index = 0

    for e in re_lists:
        index += 1
        d = makeDFA_vector(e, symbol_list)
        dot_text = d.dot_repr()
        fname = file_prefix + '-' + str(index) + '-vector.txt'
        f = open(fname, 'w')
        f.write(dot_text)
        f.close()
        # output = subprocess.check_output(['dot', '-Tx11', fname])

# Just in case: keep these here to run unit tests in vanilla python
if __name__ == "__main__":
    test_normal_forms()
    test_smart_constructors()
    test_nullable()
    test_deriv()
    test_match()
    test_dfa()
    test_dot()
    test_smart_constructors_metadata()
    test_deriv_metadata()
    test_dfa_metadata()
    test_dfa_vector()
    test_dot_vector()

    print "If this message is printed without errors before it, we're good."
    print "Also ensure all unit tests are listed above this line in the source."

