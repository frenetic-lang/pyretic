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
# Basic classes for derivative-based construction of deterministic automata    #
# for regular expressions.                                                     #
################################################################################

import string

# Sorting key macros
KEY_EPSILON = -1
KEY_EMPTY   = -2
KEY_CONCAT  = -3
KEY_ALTER   = -4
KEY_STAR    = -5
KEY_INTERS  = -6
KEY_NEGATE  = -7

# Data type definitions
# These are basic elements to be used by applications to construct regular
# expressions, with various combinators that invoke smart constructors that
# produce regular expressions in a pre-designated "normal form".
class re_deriv(object):
    """ Top-level regular expression class. """
    def __xor__(self, other):
        """ Concatenation """
        return smart_concat(self, other)

    def __or__(self, other):
        """ Alternation """
        return smart_alter(self, other)

    def __and__(self, other):
        """ Intersection """
        return smart_inters(self, other)

    def __pos__(self):
        """ Kleene star """
        return smart_star(self)

    def __invert__(self):
        """ Negation """
        return smart_negate(self)

# These are the basic building blocks that applications should use, before
# combining them with the combinators defined under the parent re_deriv class.
# epsilon, empty set, and a single symbol from the alphabet.
class re_epsilon(re_deriv):
    def __init__(self):
        super(re_epsilon, self).__init__()

    def __eq__(self, other):
        return isinstance(other, re_epsilon)

    def sort_key(self):
        return KEY_EPSILON

    def __repr__(self):
        return "epsilon"

class re_empty(re_deriv):
    def __init__(self):
        super(re_empty, self).__init__()

    def __eq__(self, other):
        return isinstance(other, re_empty)

    def sort_key(self):
        return KEY_EMPTY

    def __repr__(self):
        return "phi"

class re_symbol(re_deriv):
    def __init__(self, char):
        self.char = char
        super(re_symbol, self).__init__()

    def __eq__(self, other):
        return (isinstance(other, re_symbol) and
                other.char == self.char)

    def sort_key(self):
        return ord(self.char)

    def __repr__(self):
        return self.char

### The following classes are only to be used internally to represent various
### regular expression combinators as ASTs. They should *not* be used to
### construct regular expressions by applications.
class re_combinator(re_deriv):
    def __init__(self, re_list):
        self.re_list = re_list
        super(re_combinator, self).__init__()

class re_concat(re_combinator):
    def __init__(self, re1, re2):
        self.re1 = re1
        self.re2 = re2
        super(re_concat, self).__init__([re1, re2])

    def __eq__(self, other):
        return (isinstance(other, re_concat) and
                self.re1 == other.re1 and
                self.re2 == other.re2)

    def sort_key(self):
        return KEY_CONCAT

    def __repr__(self):
        return '(' + repr(self.re1) + ')^(' + repr(self.re2) + ')'

class re_alter(re_combinator):
    def __init__(self, re_list):
        super(re_alter, self).__init__(re_list)

    def __eq__(self, other):
        return (isinstance(other, re_alter) and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_ALTER

    def __repr__(self):
        words = map(lambda x: repr(x), self.re_list)
        return '(' + string.join(words, ') | (') + ')'

class re_star(re_deriv):
    def __init__(self, re):
        self.re = re
        super(re_star, self).__init__()

    def __eq__(self, other):
        return (isinstance(other, re_star) and
                self.re == other.re)

    def sort_key(self):
        return KEY_STAR

    def __repr__(self):
        return '(' + repr(self.re) + ')*'

class re_inters(re_combinator):
    def __init__(self, re_list):
        super(re_inters, self).__init__(re_list)

    def __eq__(self, other):
        return (isinstance(other, re_inters) and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_INTERS

    def __repr__(self):
        words = map(lambda x: repr(x), self.re_list)
        return '(' + string.join(words, ') & (') + ')'

class re_negate(re_deriv):
    def __init__(self, re):
        self.re = re
        super(re_negate, self).__init__()

    def __eq__(self, other):
        return (isinstance(other, re_negate) and
                self.re == other.re)

    def sort_key(self):
        return KEY_NEGATE

    def __repr__(self):
        return '~(' + repr(self.re) + ')'

# Nullable function
def nullable(r):
    """ Return re_epsilon if a regular expression r is nullable, else
    re_empty. """
    def bool_to_re(b):
        return re_epsilon() if b else re_empty()
    def re_to_bool(r):
        assert isinstance(r, re_epsilon) or isinstance(r, re_empty)
        return True if isinstance(r, re_epsilon) else False
    
    assert isinstance(r, re_deriv)
    if isinstance(r, re_epsilon):
        return re_epsilon()
    elif isinstance(r, re_symbol):
        return re_empty()
    elif isinstance(r, re_empty):
        return re_empty()
    elif isinstance(r, re_concat):
        f = lambda x: re_to_bool(nullable(x))
        return f(r.re1) and f(r.re2)
    elif isinstance(r, re_alter):
        return reduce(lambda acc, s: acc or re_to_bool(nullable(s)),
                      r.re_list,
                      False)
    elif isinstance(r, re_star):
        return re_epsilon()
    elif isinstance(r, re_inters):
        return reduce(lambda acc, s: acc and re_to_bool(nullable(s)),
                      r.re_list,
                      True)
    elif isinstance(r, re_negate):
        return bool_to_re(not re_to_bool(nullable(r.re)))
    else:
        raise TypeError

# Smart constructors, which enforce some useful representation invariants in the regular
# expressions they construct. In particular, the RE is flattened out as much as
# possible (e.g., no head constructor "and" in any r \in re if smart_and is
# called).

# Sort a list of regular expressions. Uses the sort_key() function to sort
# through different regular expressions
def re_sort(re_list):
    return sorted(re_list, key=lambda r: r.sort_key())

# Function to remove duplicates in a *sorted* list of REs.
def re_nub(re_list):
    new_list = []
    prev_re = None
    for re in re_list:
        if not (re == prev_re):
            new_list.append(re)
        prev_re = re
    return new_list

# smart star for regular expressions
def smart_star(r):
    if isinstance(r, re_star):
        return smart_star(r.re)
    elif isinstance(r, re_epsilon):
        return re_epsilon()
    elif isinstance(r, re_empty):
        return re_epsilon()
    else:
        return re_star(r)

# smart negation of regular expressions
def smart_negate(r):
    if isinstance(r, re_negate):
        return r.re
    else:
        return re_negate(r)

# smart intersection of regular expressions
def smart_inters(r, s):
    if r == s:
        return r
    elif isinstance(r, re_inters) and isinstance(s, re_inters):
        return re_inters(re_nub(re_sort(r.re_list + s.re_list)))
    elif isinstance(r, re_inters):
        return re_inters(re_nub(re_sort(r.re_list + [s])))
    elif isinstance(s, re_inters):
        return re_inters(re_nub(re_sort([r] + s.re_list)))
    elif isinstance(r, re_empty):
        return re_empty()
    elif isinstance(s, re_empty):
        return re_empty()
    elif isinstance(r, re_negate) and isinstance(r.re, re_empty):
        return s
    elif isinstance(s, re_negate) and isinstance(s.re, re_empty):
        return r
    else:
        return re_inters(re_nub(re_sort([r, s])))

# smart alternation of regular expressions
def smart_alter(r, s):
    if r == s:
        return r
    elif isinstance(r, re_alter) and isinstance(s, re_alter):
        return re_alter(re_nub(re_sort(r.re_list + s.re_list)))
    elif isinstance(r, re_alter):
        return re_alter(re_nub(re_sort(r.re_list + [s])))
    elif isinstance(s, re_alter):
        return re_alter(re_nub(re_sort([r] + s.re_list)))
    elif isinstance(r, re_negate) and isinstance(r.re, re_empty):
        return re_negate(re_empty)
    elif isinstance(s, re_negate) and isinstance(s.re, re_empty):
        return re_negate(re_empty)
    elif isinstance(r, re_empty):
        return s
    elif isinstance(s, re_empty):
        return r
    else:
        return re_alter(re_nub(re_sort([r, s])))

# smart concatenation for regular expressions
def smart_concat(r, s):
    if isinstance(r, re_concat):
        return smart_concat(r.re1, smart_concat(r.re2, s))
    elif isinstance(r, re_empty):
        return re_empty()
    elif isinstance(s, re_empty):
        return re_empty()
    elif isinstance(r, re_epsilon):
        return s
    elif isinstance(s, re_epsilon):
        return r
    else:
        return re_concat(r, s)

# normal form checking functions
def re_list_sorted(re_list):
    return re_list == re_sort(re_list)

def re_list_nodups(re_list):
    return re_list == re_nub(re_list)

def no_tail_inters(re_list):
    def is_inters(r):
        return isinstance(r, re_inters)
    return reduce(lambda acc, x: acc and not is_inters(x),
                  re_list,
                  True)

def no_tail_alter(re_list):
    def is_alter(r):
        return isinstance(r, re_alter)
    return reduce(lambda acc, x: acc and not is_alter(x),
                  re_list,
                  True)

def is_normal(r):
    """ Function RE -> bool, telling us whether the RE is in normal form. """
    def all_normal(re_list):
        return reduce(lambda acc, x: acc and is_normal(x),
                      re_list,
                      True)
    if isinstance(r, re_empty):
        return True
    elif isinstance(r, re_epsilon):
        return True
    elif isinstance(r, re_symbol):
        return True
    elif isinstance(r, re_star):
        s = r.re
        if isinstance(s, re_star):
            return False
        elif isinstance(s, re_epsilon):
            return False
        elif isinstance(s, re_empty):
            return False
        else:
            return is_normal(s)
    elif isinstance(r, re_negate):
        s = r.re
        if isinstance(s, re_negate):
            return False
        else:
            return is_normal(s)
    elif isinstance(r, re_inters):
        rlist = r.re_list
        if len(rlist) <= 1:
            return False
        else:
            return (re_list_sorted(rlist) and re_list_nodups(rlist) and
                    no_tail_inters(rlist) and all_normal(rlist))
    elif isinstance(r, re_alter):
        rlist = r.re_list
        if len(rlist) <= 1:
            return False
        else:
            return (re_list_sorted(rlist) and re_list_nodups(rlist) and
                    no_tail_alter(rlist) and all_normal(rlist))
    elif isinstance(r, re_concat):
        if isinstance(r.re1, re_concat):
            return False
        elif isinstance(r.re1, re_empty):
            return False
        elif isinstance(r.re2, re_empty):
            return False
        elif isinstance(r.re1, re_epsilon):
            return False
        elif isinstance(r.re2, re_epsilon):
            return False
        else:
            return is_normal(r.re1) and is_normal(r.re2)
    else:
        raise TypeError("normal form check doesn't see the right type!")

#### Derivative construction
# Fold from right
def foldr(fun, re_list, init):
    return reduce(fun, reversed(re_list), init)

# Derivative of a regular expression with respect to a single symbol
def deriv(r, a):
    assert isinstance(r, re_deriv)
    assert isinstance(a, re_symbol)
    asym = a.char
    if isinstance(r, re_empty):
        return re_empty()
    elif isinstance(r, re_epsilon):
        return re_empty()
    elif isinstance(r, re_symbol):
        rsym = r.char
        return re_epsilon() if rsym == asym else re_empty()
    elif isinstance(r, re_star):
        return smart_concat(deriv(r.re, a), smart_star(r.re))
    elif isinstance(r, re_negate):
        return smart_negate(deriv(r.re, a))
    elif isinstance(r, re_concat):
        return smart_alter(
            smart_concat(deriv(r.re1, a), r.re2),
            smart_concat(nullable(r.re1), deriv(r.re2, a)))
    elif isinstance(r, re_alter):
        return foldr(lambda rs, s: smart_alter(rs, deriv(s, a)),
                     r.re_list,
                     re_empty())
    elif isinstance(r, re_inters):
        return foldr(lambda rs, s: smart_inters(rs, deriv(s, a)),
                     r.re_list,
                     re_negate(re_empty()))
    else:
        raise TypeError('unknown type in deriv')

# Derivative of a regular expression with respect to a string
def deriv_string(r, s):
    assert isinstance(r, re_deriv)
    assert isinstance(s, str)
    if len(s) == 0:
        return r
    else:
        a = re_symbol(s[0])
        w = s[1:]
        return deriv_string(deriv(r, a), w)

# Match a single string against a single regular expression
def match_string(r, s):
    assert isinstance(r, re_deriv)
    assert isinstance(s, str)
    if len(s) == 0:
        return re_to_bool(nullable(r))
    else:
        a = re_symbol(s[0])
        return match_string(deriv(r, a), s[1:])
