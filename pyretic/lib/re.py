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

    def __hash__(self):
        return hash(self.re_string_repr())

    def __ne__(self, other):
        return not self.__eq__(other)

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

    def re_string_repr(self):
        return "epsilon"

    def __repr__(self):
        return self.re_string_repr()

class re_empty(re_deriv):
    def __init__(self):
        super(re_empty, self).__init__()

    def __eq__(self, other):
        return isinstance(other, re_empty)

    def sort_key(self):
        return KEY_EMPTY

    def re_string_repr(self):
        return "phi"

    def __repr__(self):
        return self.re_string_repr()

class re_symbol(re_deriv):
    def __init__(self, char):
        self.char = char
        super(re_symbol, self).__init__()

    def __eq__(self, other):
        return (isinstance(other, re_symbol) and
                other.char == self.char)

    def sort_key(self):
        return ord(self.char)

    def re_string_repr(self):
        return self.char

    def __repr__(self):
        return self.re_string_repr()

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

    def re_string_repr(self):
        return '(' + repr(self.re1) + ')^(' + repr(self.re2) + ')'

    def __repr__(self):
        return self.re_string_repr()

class re_alter(re_combinator):
    def __init__(self, re_list):
        super(re_alter, self).__init__(re_list)

    def __eq__(self, other):
        return (isinstance(other, re_alter) and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_ALTER

    def re_string_repr(self):
        words = map(lambda x: repr(x), self.re_list)
        return '(' + string.join(words, ') | (') + ')'

    def __repr__(self):
        return self.re_string_repr()

class re_star(re_deriv):
    def __init__(self, re):
        self.re = re
        super(re_star, self).__init__()

    def __eq__(self, other):
        return (isinstance(other, re_star) and
                self.re == other.re)

    def sort_key(self):
        return KEY_STAR

    def re_string_repr(self):
        return '(' + repr(self.re) + ')*'

    def __repr__(self):
        return self.re_string_repr()

class re_inters(re_combinator):
    def __init__(self, re_list):
        super(re_inters, self).__init__(re_list)

    def __eq__(self, other):
        return (isinstance(other, re_inters) and
                self.re_list == other.re_list)

    def sort_key(self):
        return KEY_INTERS

    def re_string_repr(self):
        words = map(lambda x: repr(x), self.re_list)
        return '(' + string.join(words, ') & (') + ')'

    def __repr__(self):
        return self.re_string_repr()

class re_negate(re_deriv):
    def __init__(self, re):
        self.re = re
        super(re_negate, self).__init__()

    def __eq__(self, other):
        return (isinstance(other, re_negate) and
                self.re == other.re)

    def sort_key(self):
        return KEY_NEGATE

    def re_string_repr(self):
        return '~(' + repr(self.re) + ')'

    def __repr__(self):
        return self.re_string_repr()

# Nullable function
def nullable(r):
    """ Return re_epsilon if a regular expression r is nullable, else
    re_empty. """
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

# helpers to determine if expression is empty, or inverse of empty
def is_empty(r):
    return isinstance(r, re_empty)

def is_negated_empty(r):
    return isinstance(r, re_negate) and isinstance(r.re, re_empty)

# smart intersection of regular expressions
def smart_inters(r, s):
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
        return r
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

# smart alternation of regular expressions
def smart_alter(r, s):
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
        return r
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
            return (re_epsilon(), [r])
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
        return (foldr(lambda rs, s: smart_alter(rs, s[0]),
                      dslist, re_empty()),
                foldr(lambda ss, s: ss + s[1],
                      dslist, []))
    elif isinstance(r, re_inters):
        dslist = map(lambda x: deriv_consumed(x, a), r.re_list)
        """ The union of the consumed symbol list is just one
        interpretation; other interpretations are possible.
        """
        return (foldr(lambda rs, s: smart_inters(rs, s[0]),
                      dslist, re_negate(re_empty())),
                foldr(lambda ss, s: ss + s[1],
                      dslist, []))
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
        return True if nullable(r) == re_epsilon() else False
    else:
        a = re_symbol(s[0])
        return match_string(deriv(r, a), s[1:])

### DFA construction using derivatives
### basic transition table implementation

def get_state_label(i, re):
    return 'Q' + str(i) + '/' + repr(re)

class re_transition_table(object):
    """ The transition table for the DFA """
    def __init__(self):
        self.re_to_transitions = {} # map: re -> (map: symbol -> re)
        self.re_to_symbols = {} # map: re -> (map: symbol -> re_symbol list)

    def add_transition(self, state, symbol, new_state, symbol_objs=None):
        def add_hash_entry(htable, key1, key2, error_msg, new_obj):
            if key1 in htable:
                entry = htable[key1]
                if key2 in entry:
                    raise AssertionError(error_msg)
                htable[key1][key2] = new_obj
            else:
                htable[key1] = {}
                htable[key1][key2] = new_obj

        assert isinstance(state, re_deriv)
        assert isinstance(symbol, str) and len(symbol) == 1
        assert isinstance(new_state, re_deriv)
        add_hash_entry(self.re_to_transitions, state, symbol,
                       "Symbol already in transition table for this state!",
                       new_state)
        add_hash_entry(self.re_to_symbols, state, symbol,
                       "re_symbols already in table for this state + symbol!",
                       symbol_objs)

    def contains_state(self, state):
        assert isinstance(state, re_deriv)
        return state in self.re_to_transitions.keys()

    def lookup_state_symbol(self, q, c):
        assert isinstance(q, re_deriv)
        assert isinstance(c, str) and len(c) == 1

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
                out += (repr(state) + "  ---> " + repr(edge) + " ---> " +
                        repr(tt_entry[edge]) + '\n')
        return out

class re_state_table(object):
    """ A table of existing RE states in the DFA """
    def __init__(self, states=None):
        if states:
            self.re_table = set(states)
        else:
            self.re_table = set([])
        self.re_map   = {}
        self.si = 0
        for s in self.re_table:
            self.re_map[s] = self.si
            self.si += 1

    def add_state(self, state):
        assert isinstance(state, re_deriv)
        assert not state in self.re_table
        self.re_table.add(state)
        self.re_map[state] = self.si
        self.si += 1

    def contains_state(self, state):
        assert isinstance(state, re_deriv)
        return state in self.re_table

    def get_index(self, state):
        """ Get the numeric index associated with an RE state. """
        assert state in self.re_map
        return self.re_map[state]

    def dot_add_states_to_graph(self, g):
        """ Add all the states in the pydot graph object provided (g). Requires
        pydot import to successfully work at module startup.
        """
        for q in self.re_map.keys():
            qi = str(self.re_map[q])
            if nullable(q) == re_epsilon():
                qshape = 'doublecircle'
            else:
                qshape = 'circle'
            g.add_node(dot.Node(get_state_label(qi, q), shape=qshape))

    def __repr__(self):
        out = ""
        for q in self.re_table:
            out += '  ' + repr(q) + ":" + str(self.re_map[q]) + '\n'
        return out

    def get_final_states(self):
        f = []
        for q in self.re_table:
            if nullable(q) == re_epsilon():
                f.append(q)
        return re_state_table(f)

class re_dfa(object):
    def __init__(self, all_states, init_state, final_states, transition_table,
                 symbol_list):
        assert isinstance(all_states, re_state_table)
        assert isinstance(init_state, re_deriv)
        assert isinstance(final_states, re_state_table)
        assert isinstance(transition_table, re_transition_table)
        assert isinstance(symbol_list, str)
        self.all_states = all_states
        self.init_state = init_state
        self.final_states = final_states
        self.transition_table = transition_table
        self.symbol_list = symbol_list

    def run_one_step(self, qcurr, instr):
        """ Run one step of the DFA from the current state `qcurr` and the
        remaining input string `instr`.
        """
        assert (isinstance(qcurr, re_deriv) and
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
        while rest != '' and qcurr != re_empty():
            (qcurr, rest) = self.run_one_step(qcurr, rest)
        return (qcurr, rest)

    def accepts(self, instr):
        """ Return True if the string `instr` is accepted by this automaton. """
        (qfinal, rest) = self.run(instr)
        if rest == '' and self.final_states.contains_state(qfinal):
            # full string read, and reached a final state
            return True
        elif qfinal == re_empty() and len(rest) > 0:
            # automaton got into a "dead" state before reading the full string
            return False
        elif len(rest) == 0 and not self.final_states.contains_state(qfinal):
            # read the entire input, but not in a final state
            return False
        else:
            raise AssertionError('unexpected result after running DFA!\n' +
                                 'q: ' + repr(qfinal) +
                                 ' rest of input: ' + rest)

    def dot_repr(self):
        """ Output a string which when provided to the graphviz tool `dot` can
        be used to visualize this DFA.
        """
        g  = dot.Dot('my_dfa_name', graph_type='digraph')
        self.all_states.dot_add_states_to_graph(g)
        re_map = self.all_states.re_map
        self.transition_table.dot_add_transitions_to_graph(g, re_map)
        return g.to_string()

    def __repr__(self):
        out = ''
        out += "Alphabet list:\n" + repr(self.symbol_list) + '\n'
        out += "Initial state:\n  " + repr(self.init_state) + '\n'
        out += "States:\n" + repr(self.all_states)
        out += "Transition table:\n" + repr(self.transition_table)
        out += "Final states:\n" + repr(self.final_states)
        return out

def goto(q, c, tt, states, alphabet_list):
    """ Explore the state q on the transition through the symbol c, and update
    the state transition table accordingly.
    """
    assert isinstance(q, re_deriv)
    assert isinstance(c, str) and len(c) == 1
    assert isinstance(tt, re_transition_table)
    assert isinstance(states, re_state_table)
    assert (len(filter(lambda x: isinstance(x, str) and len(x) == 1,
                       alphabet_list))
            == len(alphabet_list))

    sc = re_symbol(c)
    (qc, objs) = deriv_consumed(q, sc)
    if states.contains_state(qc):
        tt.add_transition(q, c, qc, objs)
    else:
        states.add_state(qc)
        tt.add_transition(q, c, qc, objs)
        explore(states, tt, qc, alphabet_list)

def explore(states, tt, q, alphabet_list):
    """ Explore all the transitions through any symbol in alphabet_list on the
    state q.
    """
    assert isinstance(states, re_state_table)
    assert isinstance(tt, re_transition_table)
    assert isinstance(q, re_deriv)
    assert (len(filter(lambda x: isinstance(x, str) and len(x) == 1,
                       alphabet_list))
            == len(alphabet_list))

    for symbol in alphabet_list:
        goto(q, symbol, tt, states, alphabet_list)

def makeDFA(r, alphabet_list):
    """ Make a DFA from a regular expression r. """
    assert isinstance(r, re_deriv)
    q0 = r
    tt = re_transition_table()
    states = re_state_table([q0])
    explore(states, tt, q0, alphabet_list)
    f = states.get_final_states()
    return re_dfa(states, q0, f, tt, alphabet_list)
