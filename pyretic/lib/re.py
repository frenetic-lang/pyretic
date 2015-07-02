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
from pyretic.evaluations.stat import Stat
import string
try:
    import pyretic.vendor
    import pydot as dot
except:
    print "Couldn't import pydot; dot visualization will not be possible."

# Sorting key macros
KEY_EMPTY   = -1
KEY_EPSILON = -2
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

    def re_string_repr(self):
        """ This is the representation of the regular expression only depending
        on the characters and combinators involved (no metadata). Each child
        class should override this method."""
        raise NotImplementedError

    def __hash__(self):
        return hash(self.re_string_repr())

    def __eq__(self, other):
        """ Each child class should override this method. """
        raise NotImplementedError

    def __ne__(self, other):
        return not self.__eq__(other)

# These are the basic building blocks that applications should use, before
# combining them with the combinators defined under the parent re_deriv class.
# epsilon, empty set, and a single symbol from the alphabet.
class re_base(re_deriv):
    """ Base class for the most basic elements of the language: epsilon, phi,
    and a single symbol from the alphabet.
    """
    def __init__(self, metadata=None, lst=True):
        """
        Initialize a basic element of the re language. There can be metadata
        associated with the basic element.

        :param metadata: optional metadata to attach to the basic expression
        :type metadata: 'a
        :param lst: boolean flag that denotes whether metadata is a list
        :type lst: boolean
        """
        super(re_base, self).__init__()
        if metadata:
            if lst:
                self.metadata = [metadata]
            else:
                self.metadata = metadata
        else:
            self.metadata = []

    def add_metadata(self, new_meta):
        """ Add new metadata to existing metadata list of the object. """
        assert isinstance(new_meta, list)
        self.metadata += new_meta

    def get_metadata(self):
        """ Get back metadata. """
        return self.metadata

    def equals_meta_structural(self, other):
        """ Return True if the other re equals self including metadata
        (structurally), otherwise False.
        """
        return self == other and self.metadata == other.metadata

    def equals_meta_by_id(self, other):
        """ Return True if the other re equals self including metadata (by id),
        else False.
        """
        return self == other and id(self.metadata) == id(other.metadata)

    def __repr__(self):
        if self.metadata:
            return self.re_string_repr() + ' (' + repr(self.metadata) + ')'
        else:
            return self.re_string_repr()

class re_epsilon(re_base):
    """ A regular expression that is equivalent to a zero-length string. """
    def __init__(self, metadata=None, lst=True):
        super(re_epsilon, self).__init__(metadata, lst)

    def __eq__(self, other):
        return isinstance(other, re_epsilon)

    def sort_key(self):
        return KEY_EPSILON

    def re_string_repr(self):
        return "epsilon"

class re_empty(re_base):
    """ The null regular expression, which matches nothing. """
    def __init__(self, metadata=None, lst=True):
        super(re_empty, self).__init__(metadata, lst)

    def __eq__(self, other):
        return isinstance(other, re_empty)

    def sort_key(self):
        return KEY_EMPTY

    def re_string_repr(self):
        return "^any"

class re_symbol(re_base):
    """ A symbol of the character set used by the regular language. """
    def __init__(self, char, metadata=None, lst=True):
        super(re_symbol, self).__init__(metadata, lst)
        self.char = char

    def __eq__(self, other):
        return (isinstance(other, re_symbol) and
                other.char == self.char)

    def sort_key(self):
        return self.char
        #return ord(self.char)

    def ml_ulex_repr(self):
        return self.char

    def re_string_repr(self):
        #return "'%s'"%self.char
        return str(self.char)

### The following classes are only to be used internally to represent various
### regular expression combinators as ASTs. They should *not* be used to
### construct regular expressions by applications.
class re_combinator(re_deriv):
    """ Abstract class for regular expressions which are formed by combining
    simpler regular expressions. """
    def __init__(self, re_list):
        self.re_list = re_list
        super(re_combinator, self).__init__()

    def equals_meta_structural(self, other):
        """ Return True if the other re equals self including metadata
        (structurally), otherwise False.
        """
        if self == other:
            return reduce(lambda acc, (x,y): (acc and
                          x.equals_meta_structural(y)),
                          zip(self.re_list, other.re_list),
                          True)
        else:
            return False

    def equals_meta_by_id(self, other):
        """ Return True if the other re equals self including metadata (by id),
        otherwise False.
        """
        if self == other:
            return reduce(lambda acc, (x,y): acc and x.equals_meta_by_id(y),
                          zip(self.re_list, other.re_list),
                          True)
        else:
            return False

class re_concat(re_combinator):
    """ Class for regular expressions with a topmost concatenation operator. """
    def __init__(self, re1, re2):
        self.re1 = re1
        self.re2 = re2
        super(re_concat, self).__init__([re1, re2])

    def __eq__(self, other):
        return (isinstance(other, re_concat) and
                self.re1 == other.re1 and
                self.re2 == other.re2 and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_CONCAT

    def ml_ulex_repr(self):
        return ('(' + self.re1.ml_ulex_repr() + ')(' +
                self.re2.ml_ulex_repr() + ')')


    def re_string_repr(self):
        return ('(' + self.re1.re_string_repr() + ').(' +
                self.re2.re_string_repr() + ')')

    def __repr__(self):
        return ('(' + repr(self.re1) + ') ^ (' +
                repr(self.re2) + ')')

class re_alter(re_combinator):
    """ Class for regular expressions with a topmost alternation operator. """
    def __init__(self, re_list):
        super(re_alter, self).__init__(re_list)

    def __eq__(self, other):
        return (isinstance(other, re_alter) and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_ALTER

    def ml_ulex_repr(self):
        words = map(lambda x: x.ml_ulex_repr(), self.re_list)
        return '(' + string.join(words, ')|(') + ')'


    def re_string_repr(self):
        words = map(lambda x: x.re_string_repr(), self.re_list)
        return '(' + string.join(words, ')|(') + ')'

    def __repr__(self):
        words = map(lambda x: repr(x), self.re_list)
        return '(' + string.join(words, ')|(') + ')'

class re_star(re_combinator):
    """ Class for regular expressions with a topmost Kleene star operator. """
    def __init__(self, re):
        self.re = re
        super(re_star, self).__init__([re])

    def __eq__(self, other):
        return (isinstance(other, re_star) and
                self.re == other.re and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_STAR

    def ml_ulex_repr(self):
        return '(' + self.re.ml_ulex_repr() + ')*'

    def re_string_repr(self):
        return '(' + self.re.re_string_repr() + ')*'

    def __repr__(self):
        return '(' + repr(self.re) + ')*'

class re_inters(re_combinator):
    """ Class for regular expressions with a topmost intersection operator. """
    def __init__(self, re_list):
        super(re_inters, self).__init__(re_list)

    def __eq__(self, other):
        return (isinstance(other, re_inters) and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_INTERS

    def ml_ulex_repr(self):
        words = map(lambda x: x.ml_ulex_repr(), self.re_list)
        return '(' + string.join(words, ')&(') + ')'

    def re_string_repr(self):
        words = map(lambda x: x.re_string_repr(), self.re_list)
        return '(' + string.join(words, ')&(') + ')'

    def __repr__(self):
        words = map(lambda x: repr(x), self.re_list)
        return '(' + string.join(words, ')&(') + ')'

class re_negate(re_combinator):
    """ Class for regular expressions with a topmost negation operator. """
    def __init__(self, re):
        self.re = re
        super(re_negate, self).__init__([re])

    def __eq__(self, other):
        return (isinstance(other, re_negate) and
                self.re == other.re and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_NEGATE

    def ml_ulex_repr(self):
        return '~(' + self.re.ml_ulex_repr() + ')'

    def re_string_repr(self):
        return '!(' + self.re.re_string_repr() + ')'

    def __repr__(self):
        return '!(' + repr(self.re) + ')'

# Nullable function
def nullable(r):
    """ Return re_epsilon if a regular expression r is nullable, else
    re_empty.

    :param r: the regex which is tested.
    :type r: re_deriv
    """
    def bool_to_re(b):
        return re_epsilon() if b else re_empty()
    def re_to_bool(r):
        if isinstance(r, re_epsilon):
            return True
        elif isinstance(r, re_empty):
            return False
        else:
            raise TypeError('re_to_bool expects re_epsilon or re_empty')
    
    assert isinstance(r, re_deriv)
    if isinstance(r, re_epsilon):
        return re_epsilon()
    elif isinstance(r, re_symbol):
        return re_empty()
    elif isinstance(r, re_empty):
        return re_empty()
    elif isinstance(r, re_concat):
        f = lambda x: re_to_bool(nullable(x))
        return bool_to_re(f(r.re1) and f(r.re2))
    elif isinstance(r, re_alter):
        return bool_to_re(reduce(lambda acc, s: acc or re_to_bool(nullable(s)),
                                 r.re_list,
                                 False))
    elif isinstance(r, re_star):
        return re_epsilon()
    elif isinstance(r, re_inters):
        return bool_to_re(reduce(lambda acc, s: acc and re_to_bool(nullable(s)),
                                 r.re_list,
                                 True))
    elif isinstance(r, re_negate):
        return bool_to_re(not re_to_bool(nullable(r.re)))
    else:
        raise TypeError('unexpected type for nullable!')

# Smart constructors, which enforce some useful representation invariants in the regular
# expressions they construct. In particular, the RE is flattened out as much as
# possible (e.g., no head constructor "and" in any r \in re if smart_and is
# called).

def re_sort(re_list):
    """ Sort a list of regular expressions. Uses the sort_key() function to sort
    through different regular expressions.
    """
    return sorted(re_list, key=lambda r: r.sort_key())

def re_nub(re_list):
    """ Function to remove duplicates in a *sorted* list of REs."""
    new_list = []
    prev_re = None
    for re in re_list:
        if re != prev_re:
            new_list.append(re)
            prev_re = re
        else:
            prev_re = aggregate_metadata(prev_re, re)
    return new_list

def aggregate_metadata(r, s):
    """ Put together metadata from two different re_base objects. """
    assert type(r) == type(s)
    if isinstance(r, re_base):
        new_meta = r.get_metadata() + s.get_metadata()
    if isinstance(r, re_symbol):
        assert r.char == s.char
        return re_symbol(r.char, metadata=new_meta, lst=False)
    elif isinstance(r, re_epsilon):
        return re_epsilon(metadata=new_meta, lst=False)
    elif isinstance(r, re_empty):
        return re_empty(metadata=new_meta, lst=False)
    else:
        # one of the non re_base types. No metadata to aggregate.
        return r

def smart_star(r):
    """ Smart star for regular expressions """
    if isinstance(r, re_star):
        return smart_star(r.re)
    elif isinstance(r, re_epsilon):
        return re_epsilon()
    elif isinstance(r, re_empty):
        return re_epsilon()
    else:
        return re_star(r)

def smart_negate(r):
    """ Smart negation of regular expressions """
    if isinstance(r, re_negate):
        return r.re
    else:
        return re_negate(r)

def is_empty(r):
    """ Determine if a regular expression r is empty. """
    return isinstance(r, re_empty)

def is_negated_empty(r):
    """ Determine if the negation of a regular expression is empty. """
    return isinstance(r, re_negate) and isinstance(r.re, re_empty)

def smart_inters(r, s):
    """ Smart intersection of regular expressions. """
    def r_empty_helper(r, s):
        """ Helper to return phi if r is empty, and s if r is ~phi, where phi is
        the empty set regular expression.
        """
        if is_empty(r):
            return re_empty()
        elif is_negated_empty(r):
            return s
        else:
            return None

    if r == s:
        return aggregate_metadata(r, s)
    elif isinstance(r, re_inters) and isinstance(s, re_inters):
        return re_inters(re_nub(re_sort(r.re_list + s.re_list)))
    elif r_empty_helper(r, s):
        return r_empty_helper(r, s)
    elif r_empty_helper(s, r):
        return r_empty_helper(s, r)
    elif isinstance(r, re_inters):
        return re_inters(re_nub(re_sort(r.re_list + [s])))
    elif isinstance(s, re_inters):
        return re_inters(re_nub(re_sort([r] + s.re_list)))
    else:
        return re_inters(re_nub(re_sort([r, s])))

def smart_alter(r, s):
    """ Smart alternation of regular expressions """
    def r_empty_helper(r, s):
        """ Helper to return s if r is empty, and ~phi if r is ~phi, where phi
        is the empty set regular expression.
        """
        if is_empty(r):
            return s
        elif is_negated_empty(r):
            return re_negate(re_empty())
        else:
            return None

    if r == s:
        return aggregate_metadata(r, s)
    elif isinstance(r, re_alter) and isinstance(s, re_alter):
        return re_alter(re_nub(re_sort(r.re_list + s.re_list)))
    elif r_empty_helper(r, s):
        return r_empty_helper(r, s)
    elif r_empty_helper(s, r):
        return r_empty_helper(s, r)
    elif isinstance(r, re_alter):
        return re_alter(re_nub(re_sort(r.re_list + [s])))
    elif isinstance(s, re_alter):
        return re_alter(re_nub(re_sort([r] + s.re_list)))
    else:
        return re_alter(re_nub(re_sort([r, s])))

def smart_concat(r, s):
    """ Smart concatenation for regular expressions """
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

### Normal form checking helper functions
def re_list_sorted(re_list):
    """ Check one aspect of "normality" of the form of the expression by
    checking for sorted order. """
    return re_list == re_sort(re_list)

def re_list_nodups(re_list):
    """ Check one aspect of "normality" of the form of the expression by
    ensuring that there are no duplicates in the list. """
    return re_list == re_nub(re_list)

def no_tail_inters(re_list):
    """ Check that there are no top-level intersections in the provided regular
    expression list."""
    def is_inters(r):
        return isinstance(r, re_inters)
    return reduce(lambda acc, x: acc and not is_inters(x),
                  re_list,
                  True)

def no_tail_alter(re_list):
    """ Check that there are no top-level alternations in the provided regular
    expression list."""
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
def foldr(fun, re_list, init):
    """ Fold from right """
    return reduce(fun, reversed(re_list), init)

def foldl(fun, re_list, init):
    """ Fold from left """
    return reduce(fun, re_list, init)

def deriv(r, a):
    """ Derivative of a regular expression with respect to a single symbol

    :param r: regular expression
    :type r: re_deriv
    :param a: a character with respect to which deriv is performed
    :type a: re_symbol
    """
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
        return foldl(lambda rs, s: smart_alter(rs, deriv(s, a)),
                     r.re_list,
                     re_empty())
    elif isinstance(r, re_inters):
        return foldl(lambda rs, s: smart_inters(rs, deriv(s, a)),
                     r.re_list,
                     re_negate(re_empty()))
    else:
        raise TypeError('unknown type in deriv')

def deriv_consumed(r, a):
    """ A version of the derivative function that also returns the list of
    `re_symbol`s that was consumed. The type of this function is
    re_deriv -> re_symbol -> (re_deriv * list re_symbol).
    """
    assert isinstance(r, re_deriv)
    assert isinstance(a, re_symbol)
    asym = a.char
    if isinstance(r, re_empty):
        return (re_empty(), [])
    elif isinstance(r, re_epsilon):
        return (re_empty(), [])
    elif isinstance(r, re_symbol):
        rsym = r.char
        if rsym == asym:
            return (re_epsilon(), r.get_metadata())
        else:
            return (re_empty(), [])
    elif isinstance(r, re_star):
        (d, s) = deriv_consumed(r.re, a)
        return (smart_concat(d, smart_star(r.re)), s)
    elif isinstance(r, re_negate):
        (d, s) = deriv_consumed(r.re, a)
        return (smart_negate(d), s)
    elif isinstance(r, re_concat):
        (d1, s1) = deriv_consumed(r.re1, a)
        (d2, s2) = deriv_consumed(r.re2, a)
        return (smart_alter(
            smart_concat(d1, r.re2),
            smart_concat(nullable(r.re1), d2)),
                s1 + (s2 if nullable(r.re1) == re_epsilon() else []))
    elif isinstance(r, re_alter):
        dslist = map(lambda x: deriv_consumed(x, a), r.re_list)
        return (foldl(lambda rs, s: smart_alter(rs, s[0]),
                      dslist, re_empty()),
                foldl(lambda ss, s: ss + s[1],
                      dslist, []))
    elif isinstance(r, re_inters):
        dslist = map(lambda x: deriv_consumed(x, a), r.re_list)
        """ The union of the consumed symbol list is just one
        interpretation; other interpretations are possible.
        """
        return (foldl(lambda rs, s: smart_inters(rs, s[0]),
                      dslist, re_negate(re_empty())),
                foldl(lambda ss, s: ss + s[1],
                      dslist, []))
    else:
        raise TypeError('unknown type in deriv')

def deriv_string(r, s):
    """ Derivative of a regular expression with respect to a string """
    assert isinstance(r, re_deriv)
    assert isinstance(s, str)
    if len(s) == 0:
        return r
    else:
        a = re_symbol(s[0])
        w = s[1:]
        return deriv_string(deriv(r, a), w)

def match_string(r, s):
    """ Match a single string against a single regular expression """
    assert isinstance(r, re_deriv)
    assert isinstance(s, str)
    if len(s) == 0:
        return True if nullable(r) == re_epsilon() else False
    else:
        a = re_symbol(s[0])
        return match_string(deriv(r, a), s[1:])

### DFA construction using derivatives
### basic transition table implementation

def get_state_label(i, re):
    """ Return a label which is to be used to represent the state in a DFA
    diagram. In general, the index i of the state is used, but representations
    of the regular expression (or vector) that the state represents can also be
    used, e.g.,

    return 'Q' + str(i) + '/' + repr(re)
    """
    return 'Q' + str(i)

class dfa_transition_table(object):
    """ A generic transition table for DFAs """
    def __init__(self, state_type, state_type_check_fun,
                 symbol_type, symbol_type_check_fun):
        self.re_to_transitions = {} # map: re -> (map: symbol -> re)
        self.state_type = state_type
        self.state_type_check_fun = state_type_check_fun
        self.symbol_type = symbol_type
        self.symbol_type_check_fun = symbol_type_check_fun

    def get_transitions(self):
        """ Get the set of edges (transitions) in the DFA as a list of
        tuples.
        """
        lst = []
        for re in self.re_to_transitions:
            for sym in self.re_to_transitions[re]:
                lst.append((re, self.re_to_transitions[re][sym], sym))
        return lst

    def get_num_transitions(self):
        return len(self.get_transitions())

    def add_transition(self, state, symbol, new_state):
        """ Add a new transition to the DFA """
        assert self.state_type_check_fun(state, self.state_type)
        assert self.state_type_check_fun(new_state, self.state_type)
        assert self.symbol_type_check_fun(symbol, self.symbol_type)
        if state in self.re_to_transitions:
            entry = self.re_to_transitions[state]
            if symbol in entry:
                # sanity check to ensure the destination states of the
                # transition are the same, if the transition already exists.
                assert entry[symbol] == new_state
            entry[symbol] = new_state
        else:
            self.re_to_transitions[state] = {}
            self.re_to_transitions[state][symbol] = new_state

    def contains_state(self, state):
        """ Return True if the DFA contains the argument state. """
        assert self.state_type_check_fun(state, self.state_type)
        return state in self.re_to_transitions.keys()

    def lookup_state_symbol(self, q, c):
        """ Lookup a transition from state `q` on symbol `c` """
        assert self.state_type_check_fun(q, self.state_type)
        assert self.symbol_type_check_fun(c, self.symbol_type)
        if q in self.re_to_transitions.keys():
            if c in self.re_to_transitions[q].keys():
                return self.re_to_transitions[q][c]
        return None

    def dot_add_transitions_to_graph(self, g, re_map):
        """ Add transitions in this table to the pydot graph object provided
        (g). This function also uses a numeric mapping from the state to a
        number provided in re_map.
        """
        for state in self.re_to_transitions.keys():
            tt_entry = self.re_to_transitions[state]
            src = get_state_label(re_map[state], state)
            for symbol in tt_entry:
                dstate = tt_entry[symbol]
                dst = get_state_label(re_map[dstate], dstate)
                g.add_edge(dot.Edge(src, dst, label=symbol))

    def __repr__(self):
        out = ''
        for state in self.re_to_transitions.keys():
            out += "** Transitions from state " + repr(state) + '\n'
            tt_entry = self.re_to_transitions[state]
            for edge in tt_entry.keys():
                out += (repr(state) + "  ---> " + repr(edge) +
                        " ---> " + repr(tt_entry[edge]) + '\n')
        return out

class re_transition_table(dfa_transition_table):
    """ The transition table for the DFA """
    def __init__(self):
        def symcheck(s, typ):
            return isinstance(s, typ)
            #return isinstance(s, typ) and len(s) == 1
        #super(re_transition_table, self).__init__(re_deriv,
         #                                         isinstance,
          #                                        str,
           #                                       symcheck)
        super(re_transition_table, self).__init__(re_deriv,
                                                  isinstance,
                                                  int,
                                                  symcheck)

        self.transition_to_metadata = {} # map: re -> (map: symbol -> metadata
                                         # list)

    def add_metadata(self, state, symbol, metadata_objs=None):
        """ Add a list of metadata objects to an existing transition in the
        DFA.
        """
        def create_meta_list_if_not_exists(meta_map, q, c):
            if q in meta_map:
                if not c in meta_map[q]:
                    meta_map[q][c] = []
            else:
                meta_map[q] = {}
                meta_map[q][c] = []

        def add_single_metadata(meta_list, new_meta):
            def equals(x, y):
                try:
                    return x == y
                except:
                    return id(x) == id(y)
            meta_exists = reduce(lambda acc, x: acc or equals(x, new_meta),
                                 meta_list,
                                 False)
            if not meta_exists:
                meta_list.append(new_meta)
                return new_meta
            else:
                return None

        assert isinstance(state, re_deriv)
        #assert isinstance(symbol, str) and len(symbol) == 1
        assert isinstance(symbol, int)
        create_meta_list_if_not_exists(self.transition_to_metadata,
                                       state, symbol)
        meta_list = self.transition_to_metadata[state][symbol]
        map(lambda x: add_single_metadata(meta_list, x), metadata_objs)

    def get_metadata(self, q, s):
        """ Get list of metadata of the objects corresponding to the transition
        from state `q` over the symbol `s`.
        """
        assert isinstance(q, re_deriv) and q in self.transition_to_metadata
        #assert (isinstance(s, str) and len(s) == 1 and
         #       s in self.transition_to_metadata[q])
        assert (isinstance(s, int) and
                s in self.transition_to_metadata[q])

        return self.transition_to_metadata[q][s]

    def __repr__(self):
        out = ''
        for state in self.re_to_transitions.keys():
            out += "** Transitions from state " + state.re_string_repr() + '\n'
            tt_entry = self.re_to_transitions[state]
            for edge in tt_entry.keys():
                out += (state.re_string_repr() + "  ---> " + repr(edge) +
                        " ---> " + tt_entry[edge].re_string_repr() + '\n')
                out += ("      on reading metadata: " +
                        str(self.transition_to_metadata[state][edge]) + '\n')
        return out

class dfa_state_table(object):
    """ A table of generic states in a DFA """
    def __init__(self, states, state_type,
                 state_type_check_fun, final_state_check_fun,
                 dead_state_check_fun):
        self.state_type = state_type
        self.state_type_check_fun = state_type_check_fun
        self.final_state_check_fun = final_state_check_fun
        self.dead_state_check_fun = dead_state_check_fun
        if states:
            for s in states:
                self.state_type_check_fun(s, self.state_type)
            self.re_table = set(states)
        else:
            self.re_table = set([])
        self.re_map   = {}
        self.si = 0
        self.state_list = []
        for s in self.re_table:
            self.re_map[s] = self.si
            self.state_list.append(s)
            assert self.state_list[self.si] == s
            self.si += 1

    def add_state(self, state):
        assert self.state_type_check_fun(state, self.state_type)
        assert not state in self.re_table
        self.re_table.add(state)
        self.re_map[state] = self.si
        self.state_list.append(state)
        assert self.state_list[self.si] == state
        self.si += 1

    def get_state_by_index(self, i):
        """ Given the numerical index of a state i, get the state. """
        return self.state_list[i]

    def contains_state(self, state):
        assert self.state_type_check_fun(state, self.state_type)
        return state in self.re_table

    def get_index(self, state):
        """ Get the numeric index associated with an RE state. """
        assert state in self.re_map
        return self.re_map[state]

    def get_num_states(self):
        return self.si

    def dot_add_states_to_graph(self, g):
        """ Add all the states in the pydot graph object provided (g). Requires
        pydot import to successfully work at module startup.
        """
        for q in self.re_map.keys():
            qi = str(self.re_map[q])
            if self.final_state_check_fun(q):
                qshape = 'doublecircle'
            else:
                qshape = 'circle'
            g.add_node(dot.Node(get_state_label(qi, q), shape=qshape))

    def __repr__(self):
        out = ""
        sorted_states = sorted(self.re_table, key=lambda x: self.re_map[x])
        for q in sorted_states:
            out += '  ' + str(self.re_map[q]) + ': ' + repr(q) + '\n'
        return out

    def is_accepting(self, q):
        """ Return True if state `q` is an accepting state."""
        return self.final_state_check_fun(q)

    def is_dead(self, q):
        """ Return if a state is dead. """
        return self.dead_state_check_fun(q)

    def get_dead_state(self):
        """ Return the (one) dead state in the state table. """
        dead_states = []
        for q in self.re_table:
            if self.dead_state_check_fun(q):
                dead_states.append(q)
        assert len(dead_states) <= 1
        if len(dead_states) == 1:
            return dead_states[0]
        else:
            return None

    def get_final_states(self):
        """ Get the list of final states of the DFA as a state table """
        f = []
        for q in self.re_table:
            if self.final_state_check_fun(q):
                f.append(q)
        return dfa_state_table(f, state_type=self.state_type,
                               state_type_check_fun=self.state_type_check_fun,
                               final_state_check_fun=self.final_state_check_fun)

class re_state_table(dfa_state_table):
    """ A table of RE states in the DFA """
    def __init__(self, states=None, re_to_exp=None,
                 state_type=re_deriv, state_type_check_fun=isinstance,
                 final_state_check_fun=lambda x: nullable(x) == re_epsilon(),
                 dead_state_check_fun=lambda x: x == re_empty()):
        super(re_state_table, self).__init__(states,
                                             state_type,
                                             state_type_check_fun,
                                             final_state_check_fun,
                                             dead_state_check_fun)
        # set up a mapping from state to a list of corresponding expressions, to
        # keep track of distinct expressions with respect to metadata (even if
        # same with respect to the regular expression itself).
        if re_to_exp:
            self.re_to_exp = re_to_exp
        else:
            self.re_to_exp = {}
            for q in self.re_table:
                self.re_to_exp[q] = [q]


    def __repr__(self):
        out = ""
        sorted_states = sorted(self.re_table, key=lambda x: self.re_map[x])
        for q in sorted_states:
            out += '  ' + str(self.re_map[q]) + ': ' + q.re_string_repr() + '\n'
            for exp in self.get_expressions(q):
                out += '    --  ' + repr(exp) + '\n'
        return out

    def add_state(self, state):
        super(re_state_table, self).add_state(state)
        self.re_to_exp[state] = []

    def add_expressions(self, q, exps):
        """ Add some new expressions to a pre-existing state `q`. Note that the
        new expressions need to be equal to the state under regular expression
        semantics, but may be different in terms of the metadata of their
        constituents.

        Returns None if all provided expressions are already in the list of
        expressions corresponding to the state (equality with respect to
        metadata), or the list of added expressions.
        """
        def add_expression(re_to_exp, q, exp):
            """ Add a single expression e to the state q. """
            assert isinstance(exp, re_deriv)
            for e in re_to_exp[q]:
                if e.equals_meta_structural(exp):
                    return None
            re_to_exp[q] += [exp]
            return exp

        assert isinstance(q, re_deriv)
        assert q in self.re_table and q in self.re_to_exp
        added_exps = []
        for e in exps:
            added = add_expression(self.re_to_exp, q, e)
            if added:
                added_exps.append(e)
        return added_exps

    def get_expressions(self, q):
        """ Get all re expressions corresponding to a state q. """
        assert q in self.re_table and q in self.re_to_exp
        return self.re_to_exp[q]

    def get_final_states(self):
        f = []
        for q in self.re_table:
            if self.final_state_check_fun(q):
                f.append(q)
        return re_state_table(f, state_type=self.state_type,
                              state_type_check_fun=self.state_type_check_fun,
                              final_state_check_fun=self.final_state_check_fun)

class dfa_base(object):
    def __init__(self, all_states, init_state, final_states, transition_table,
                 symbol_list, state_table_type, state_type,
                 state_type_check_fun, tt_type, dead_state_check_fun):
        """ Abstract DFA base class. """
        assert isinstance(all_states, state_table_type)
        assert state_type_check_fun(init_state, state_type)
        assert isinstance(final_states, state_table_type)
        assert isinstance(transition_table, tt_type)
        #is_strlist = lambda acc, x: acc and isinstance(x, str) and len(x) == 1
        is_strlist = lambda acc, x: acc and isinstance(x, int)
        assert reduce(is_strlist, symbol_list, True)
        self.all_states = all_states
        self.init_state = init_state
        self.final_states = final_states
        self.transition_table = transition_table
        self.symbol_list = symbol_list
        self.state_table_type = state_table_type
        self.state_type = state_type
        self.state_type_check_fun = state_type_check_fun
        self.tt_type = tt_type
        self.dead_state_check_fun = dead_state_check_fun

    def run_one_step(self, qcurr, instr):
        """ Run one step of the DFA from the current state `qcurr` and the
        remaining input string `instr`.
        """
        assert (self.state_type_check_fun(qcurr, self.state_type) and
                self.all_states.contains_state(qcurr))
        assert isinstance(instr, str) and len(instr) >= 1

        c = instr[0]
        assert c in self.symbol_list
        rest = instr[1:]
        new_state = self.transition_table.lookup_state_symbol(qcurr, c)
        return (new_state, rest)

    def run(self, instr):
        """ Run the input string `instr` through the DFA starting from the
        initial state, until either the input is completely consumed, or the DFA
        reaches the \epsilon or \phi state.
        """
        (qcurr, rest) = (self.init_state, instr)
        while rest != '' and not self.dead_state_check_fun(qcurr):
            (qcurr, rest) = self.run_one_step(qcurr, rest)
        return (qcurr, rest)

    def accepts(self, instr):
        """ Return True if the string `instr` is accepted by this automaton. """
        (qfinal, rest) = self.run(instr)
        if rest == '' and self.final_states.contains_state(qfinal):
            # full string read, and reached a final state
            return True
        elif self.dead_state_check_fun(qfinal) and len(rest) > 0:
            # automaton got into a "dead" state before reading the full string
            return False
        elif len(rest) == 0 and not self.final_states.contains_state(qfinal):
            # read the entire input, but not in a final state
            return False
        else:
            raise AssertionError('unexpected result after running DFA!\n' +
                                 'q: ' + repr(qfinal) +
                                 ' rest of input: ' + rest)

    def get_graph(self):
        """ Output a pydot graph object which represents the DFA. """
        g  = dot.Dot('re_dfa', graph_type='digraph')
        self.all_states.dot_add_states_to_graph(g)
        re_map = self.all_states.re_map
        self.transition_table.dot_add_transitions_to_graph(g, re_map)
        return g

    def dot_repr(self):
        """ Output a string representation of the DFA which when provided to the
        graphviz tool `dot` can be used to visualize this DFA. """
        g = self.get_graph()
        return g.to_string()

    def __repr__(self):
        out = ''
        out += "Alphabet list:\n" + repr(self.symbol_list) + '\n'
        out += "Initial state:\n  " + repr(self.init_state) + '\n'
        out += "States:\n" + repr(self.all_states)
        out += "Transition table:\n" + repr(self.transition_table)
        out += "Final states:\n" + repr(self.final_states)
        return out

class re_dfa(dfa_base):
    def __init__(self, all_states, init_state, final_states, transition_table,
                 symbol_list):
        super(re_dfa, self).__init__(all_states, init_state, final_states,
                                     transition_table, symbol_list,
                                     re_state_table, re_deriv, isinstance,
                                     re_transition_table,
                                     lambda x: x == re_empty())

def get_transition_exps_metadata(q, c, Q):
    """ Get a list of expressions of the new state that is reached by going
    from state `q` on reading symbol `c`. The data structure representing
    the state table is another parameter `Q`. The function returns a set of
    expressions for the new state that is reached, along with a list of
    metadata objects consumed in the transition.
    """
    assert isinstance(q, re_deriv)
    #assert isinstance(c, str) and len(c) == 1
    assert isinstance(c, int)
    exps = Q.get_expressions(q)
    sc = re_symbol(c)
    dst_expressions = []
    metadata_list = []
    for e in exps:
        (e_dst, meta) = deriv_consumed(e, sc)
        dst_expressions.append(e_dst)
        metadata_list += meta
    return (dst_expressions, metadata_list)

def typecheck_goto(q, c, tt, states, alphabet_list,
                   state_type, state_type_check_fun,
                   tt_type, states_table_type):
    """ Type-checking function invoked by goto. """
    assert state_type_check_fun(q, state_type)
    #assert isinstance(c, str) and len(c) == 1
    assert isinstance(c, int)
    assert isinstance(tt, tt_type)
    assert isinstance(states, states_table_type)
    #assert (len(filter(lambda x: isinstance(x, str) and len(x) == 1,
     #                  alphabet_list))
      #      == len(alphabet_list))
    assert (len(filter(lambda x: isinstance(x, int),
                       alphabet_list))
            == len(alphabet_list))

def goto(q, c, tt, states, alphabet_list):
    """ Explore the state q on the transition through the symbol c, and update
    the state transition table accordingly.
    """
    typecheck_goto(q, c, tt, states, alphabet_list, re_deriv, isinstance,
                   re_transition_table, re_state_table)

    sc = re_symbol(c)
    qc = deriv(q, sc)
    (exps, meta) = get_transition_exps_metadata(q, c, states)
    if not states.contains_state(qc):
        states.add_state(qc)
    added_exps = states.add_expressions(qc, exps)
    tt.add_transition(q, c, qc)
    tt.add_metadata(q, c, meta)
    if added_exps: # true if new state, or new expressions on existing state.
        explore(states, tt, qc, alphabet_list)

def typecheck_explore(states, tt, q, alphabet_list, state_table_type, tt_type,
                      state_type, state_type_check_fun):
    """ Type-checking function invoked by explore. """
    assert isinstance(states, state_table_type)
    assert isinstance(tt, tt_type)
    assert state_type_check_fun(q, state_type)
    #assert (len(filter(lambda x: isinstance(x, str) and len(x) == 1,
     #                  alphabet_list))
      #      == len(alphabet_list))
    assert (len(filter(lambda x: isinstance(x, int),
                       alphabet_list))
            == len(alphabet_list))


def explore(states, tt, q, alphabet_list):
    """ Explore all the transitions through any symbol in alphabet_list on the
    state q.
    """
    typecheck_explore(states, tt, q, alphabet_list, re_state_table,
                      re_transition_table, re_deriv, isinstance)
    for symbol in alphabet_list:
        goto(q, symbol, tt, states, alphabet_list)

def make_null_DFA():
    """ This is a "null" DFA, which is returned if there are no input regular
    expressions to make DFA functions. """
    q0 = re_empty()
    states = re_state_table([q0])
    tt = re_transition_table()
    f = re_state_table([])
    alphabet_list = []
    return re_dfa(states, q0, f, tt, alphabet_list)

def makeDFA(r, alphabet_list):
    """ Make a DFA from a regular expression r. """
    assert isinstance(r, re_deriv)
    q0 = r
    tt = re_transition_table()
    states = re_state_table([q0])
    explore(states, tt, q0, alphabet_list)
    f = states.get_final_states()
    return re_dfa(states, q0, f, tt, alphabet_list)

### Vector regular expressions
def list_isinstance(l, typ):
    """ Equivalent of isinstance, but on a list of items of a given type. """
    return reduce(lambda acc, x: acc and isinstance(x, typ), l, True)

def tuple_from_list(l):
    return reduce(lambda acc, x: acc + (x,), l, ())

def list_from_tuple(t):
    return reduce(lambda acc, z: acc + [z], t, [])

class re_vector_state_table(dfa_state_table):
    def __init__(self, states=None):
        """ Class for table of states which are vectors of regular
        expressions. """
        def tuple_has_final_state(qtuple):
            return reduce(lambda acc, x: acc or nullable(x) == re_epsilon(),
                          qtuple, False)

        def tuple_is_dead_state(qtuple):
            return reduce(lambda acc, x: acc and x == re_empty(), qtuple, True)

        super(re_vector_state_table, self).__init__(
            states,
            re_deriv,
            list_isinstance,
            tuple_has_final_state,
            tuple_is_dead_state)

    def get_final_states(self):
        f = []
        for q in self.re_table:
            if self.final_state_check_fun(q):
                f.append(q)
        return re_vector_state_table(f)

    def get_accepting_exps_ordinal(self, q):
        """ Given a vector state q, return a list of ordinal number of the re
        components of the state that are accepting strings there."""
        assert list_isinstance(q, re_deriv)
        ordinal_list = []
        for index in range(0, len(q)):
            qcomp = q[index]
            if nullable(qcomp) == re_epsilon():
                ordinal_list.append(index)
        return ordinal_list

class re_vector_transition_table(dfa_transition_table):
    def __init__(self, component_dfas):
        """ Transition table class when the states are vectors of regular
        expressions. """
        def symcheck(c, typ):
            return isinstance(c, typ)
            #return isinstance(c, typ) and len(c) == 1
        
        #super(re_vector_transition_table, self).__init__(
         #   re_deriv,
          #  list_isinstance,
           # str,
            #symcheck)

        super(re_vector_transition_table, self).__init__(
            re_deriv,
            list_isinstance,
            int,
            symcheck)
        self.component_dfas = component_dfas

    def get_metadata(self, qvec, c):
        """ Get metadata on a vector transition using the scalar DFAs & their
        transition metadata.
        """
        #assert isinstance(c, str) and len(c) == 1
        assert isinstance(c, int)
        meta_list = []
        for i in range(0, len(qvec)):
            q = qvec[i]
            dfa = self.component_dfas[i]
            states = dfa.all_states
            tt = dfa.transition_table
            meta_list.append(tt.get_metadata(q, c))
        return tuple_from_list(meta_list)

class re_vector_dfa(dfa_base):
    def __init__(self, all_states, init_state, final_states, transition_table,
                 symbol_list):
        """ DFA of states which are vectors of regular expressions. """
        def check_dead_state(x):
            return reduce(lambda q, acc: acc and q == re_empty(), x, True)

        super(re_vector_dfa, self).__init__(all_states, init_state,
                                            final_states, transition_table,
                                            symbol_list, re_vector_state_table,
                                            re_deriv, list_isinstance,
                                            re_vector_transition_table,
                                            check_dead_state)

def deriv_vector(r, a):
    """ Derive a regular vector `r` with respect to an re_symbol `a`. """
    assert list_isinstance(r, re_deriv)
    assert isinstance(a, re_symbol)
    s = []
    for exp in r:
        s.append(deriv(exp, a))
    return tuple_from_list(s)

def goto_vector(q, c, tt, states, alphabet_list):
    """ Explore the (vector) state q on the transition through the symbol c, and
    update the (vector) state transition table accordingly.
    """
    typecheck_goto(q, c, tt, states, alphabet_list, re_deriv, list_isinstance,
                   re_vector_transition_table, re_vector_state_table)

    sc = re_symbol(c)
    qc = deriv_vector(q, sc)
    if states.contains_state(qc):
        tt.add_transition(q, c, qc)
    else:
        states.add_state(qc)
        tt.add_transition(q, c, qc)
        explore_vector(states, tt, qc, alphabet_list)

def explore_vector(states, tt, q, alphabet_list):
    """ Explore all the transitions through any symbol in alphabet_list on the
    state q.
    """
    typecheck_explore(states, tt, q, alphabet_list, re_vector_state_table,
                      re_vector_transition_table, re_deriv, list_isinstance)
    for symbol in alphabet_list:
        goto_vector(q, symbol, tt, states, alphabet_list)

@Stat.elapsed_time
def makeDFA_vector(re_list, alphabet_list):
    """ Make a DFA from a list of regular expressions `re_list`. """
    assert list_isinstance(re_list, re_deriv)
    if len(re_list) == 0:
        return make_null_DFA()
    component_dfas = tuple_from_list(map(lambda x: makeDFA(x, alphabet_list),
                                         re_list))
    q0 = tuple_from_list(re_list)
    tt = re_vector_transition_table(component_dfas)
    states = re_vector_state_table([q0])
    explore_vector(states, tt, q0, alphabet_list)
    f = states.get_final_states()
    return re_vector_dfa(states, q0, f, tt, alphabet_list)
