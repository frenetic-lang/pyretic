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
from pyretic.lib.query import counts, packets

import subprocess
import pyretic.vendor
import pydot

#############################################################################
### Basic classes for generating path atoms and creating path expressions ###
#############################################################################

TOKEN_START_VALUE = 48 # start with printable ASCII for visual inspection ;)

class CharacterGenerator:
    """ Generate characters to represent equivalence classes of existing match
    predicates. `get_token` returns the same token value as before if a policy
    already seen (and hence recorded in its map) is provided to it.
    """
    token = TOKEN_START_VALUE
    default_toktype = "ingress"
    toktypes = [default_toktype]
    filter_to_token = {} # toktype -> (filter -> token)
    token_to_filter = {} # toktype -> (token -> filter)
    token_to_tokens = {} # toktype -> (token -> token list)
    token_to_toktype = {} # token -> toktype

    @classmethod
    def clear(cls):
        cls.token = TOKEN_START_VALUE
        cls.toktypes = [cls.default_toktype]
        cls.filter_to_token = {cls.default_toktype: {}}
        cls.token_to_filter = {cls.default_toktype: {}}
        cls.token_to_tokens = {cls.default_toktype: {}}
        cls.token_to_toktype = {}

    @classmethod
    def has_nonempty_intersection(cls, p1, p2):
        """Return True if policies p1, p2 have an intesection which is
        drop. Works by generating the classifiers for the intersection of the
        policies, and checking if there are anything other than drop rules.
        """
        def get_classifier(p):
            if p._classifier:
                return p._classifier
            return p.generate_classifier()

        int_class = get_classifier(p1 & p2)
        for rule in int_class.rules:
            if not drop in rule.actions:
                return True
        return False

    @classmethod
    def __ensure_toktype(cls, toktype):
        if not toktype in cls.toktypes:
            cls.toktypes.append(toktype)
            cls.filter_to_token[toktype] = {}
            cls.token_to_filter[toktype] = {}

    @classmethod
    def __add_new_token(cls, pol, toktype):
        new_token = cls.__new_token__()
        cls.__ensure_toktype(toktype)
        cls.filter_to_token[toktype][pol] = new_token
        cls.token_to_filter[toktype][new_token] = pol
        cls.token_to_toktype[new_token] = toktype
        return new_token

    @classmethod
    def __add_new_filter(cls, new_filter, toktype):
        # The algorithm below ensures that matches are disjoint before adding
        # them. Basically, each character that is present in the path
        # expressions represents a mutually exclusive packet match.
        diff_list = drop
        new_intersecting_tokens = []
        for existing_filter in cls.token_to_filter[toktype].values():
            if cls.has_nonempty_intersection(existing_filter, new_filter):
                tok = cls.filter_to_token[toktype][existing_filter]
                if cls.has_nonempty_intersection(existing_filter, ~new_filter):
                    # do actions below only if the existing filter has some
                    # intersection with, but is not completely contained in, the
                    # new filter.
                    del cls.filter_to_token[toktype][existing_filter]
                    del cls.token_to_filter[toktype][tok]
                    new_tok1 = cls.__add_new_token(existing_filter &
                                                   ~new_filter, toktype)
                    new_tok2 = cls.__add_new_token(existing_filter &
                                                   new_filter, toktype)
                    cls.token_to_tokens[toktype][tok] = [new_tok1, new_tok2]
                    new_intersecting_tokens.append(new_tok2)
                else:
                    # i.e., if existing filter is completely contained in new one.
                    new_intersecting_tokens.append(tok)
                # add existing_filter into list of policies to be subtracted as
                # long as there is some intersection.
                if diff_list == drop:
                    diff_list = existing_filter
                else:
                    diff_list = diff_list | existing_filter
        # add the new_filter itself, differenced by all the intersecting parts.
        if diff_list != drop: # i.e., if there was intersection with existing filters
            new_token = cls.__new_token__()
            new_disjoint_token = []
            if cls.has_nonempty_intersection(new_filter, ~diff_list):
                # i.e., if the intersections didn't completely make up the new filter
                new_disjoint_token.append(cls.__add_new_token(new_filter &
                                                              ~diff_list,
                                                              toktype))
            cls.token_to_tokens[toktype][new_token] = (new_intersecting_tokens +
                                                       new_disjoint_token)
            cls.token_to_toktype[new_token] = toktype
        else:
            # i.e., if there was no intersection at all with existing filters
            new_token = cls.__add_new_token(new_filter, toktype)
        return new_token

    @classmethod
    def get_filter_from_token(cls, tok, toktype=None):
        if not toktype:
            toktype = cls.default_toktype
        if tok in cls.token_to_filter[toktype]:
            return cls.token_to_filter[toktype][tok]
        elif tok in cls.token_to_tokens[toktype]:
            toklist = cls.token_to_tokens[toktype][tok]
            tok0 = toklist[0]
            output_filter = cls.get_filter_from_token(tok0, toktype)
            for new_tok in toklist[1:]:
                output_filter = (output_filter |
                                 cls.get_filter_from_token(new_tok, toktype))
            return output_filter
        else:
            raise TypeError

    @classmethod
    def get_filter_from_edge_label(cls, edge_label, negated):
        """Recursive search in token_to_tokens, or just direct return from
        token_to_filter, for any token.
        """
        def get_single_token_filter(tok):
            """ Grab filter for the given token from whichever toktype class it
            might be part of.
            """
            assert tok in cls.token_to_toktype
            toktype = cls.token_to_toktype[tok]
            assert tok in cls.token_to_filter[toktype]
            return cls.token_to_filter[toktype][tok]

        tok0 = cls.get_token_from_char(edge_label[0])
        output_filter = get_single_token_filter(tok0)
        for char in edge_label[1:]:
            tok = cls.get_token_from_char(char)
            output_filter = output_filter | get_single_token_filter(tok)
        if not negated:
            return output_filter
        else:
            return ~output_filter

    @classmethod
    def get_token(cls, pol, toktype=None, nonoverlapping_filters=True):
        if not toktype:
            toktype = cls.default_toktype
        if nonoverlapping_filters:
            if pol in cls.filter_to_token[toktype]:
                return cls.filter_to_token[toktype][pol]
            else:
                return cls.__add_new_filter(pol, toktype)
        else:
            return cls.__add_new_token(pol, toktype)

    @classmethod
    def get_char_from_token(cls, tok):
        try:
            return chr(tok)
        except:
            return unichr(tok)

    @classmethod
    def get_token_from_char(cls, char):
        return ord(char)

    @classmethod
    def char_in_lexer_language(cls, char):
        return char in ['*','+','|','{','}','(',
                       ')','-','^','.','&','?',
                       '"',"'",'%','$',',','/',"\\",
                        '=','>','<']

    @classmethod
    def __new_token__(cls):
        cls.token += 1
        char = cls.get_char_from_token(cls.token)
        if cls.char_in_lexer_language(char):
            return cls.__new_token__()
        return cls.token

    @classmethod
    def get_terminal_expression(cls, expr):
        """Get an expression of token characters corresponding only to
        non-overlapping filters from a given expression.
        """
        def get_terminal_expr_for_char(c):
            if cls.char_in_lexer_language(c):
                return c
            tok = cls.get_token_from_char(c)
            assert tok in cls.token_to_toktype
            toktype = cls.token_to_toktype[tok]
            if not tok in cls.token_to_tokens[toktype]:
                assert tok in cls.token_to_filter[toktype]
                return c
            else:
                terminal_expr = '('
                for tok2 in cls.token_to_tokens[toktype][tok]:
                    c2 = cls.get_char_from_token(tok2)
                    terminal_expr += get_terminal_expr_for_char(c2) + '|'
                terminal_expr = terminal_expr[:-1] + ')'
                return terminal_expr

        new_expr = ''
        for c in expr:
            new_expr += get_terminal_expr_for_char(c)
        return new_expr


class path(Query):
    """A way to query packets or traffic volumes satisfying regular expressions
    denoting paths of located packets.

    :param a: path atom used to construct this path element
    :type atom: atom
    """
    def __init__(self, a=None, expr=None, paths=None):
        if a:
            assert isinstance(a, abstract_atom)
            self.atom = a
            self.expr = CharacterGenerator.get_char_from_token(self.atom.token)
        elif expr:
            assert isinstance(expr, str)
            self.expr = expr
        elif paths:
            self.paths = paths
        else:
            raise RuntimeError
        super(path, self).__init__()
        self.bucket_instance = FwdBucket() # default bucket type

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

        TODO(ngsrinivas): It just looks wrong to use '+' instead of '*', but
        unfortunately there is no unary (prefix or postfix) '*' operator in
        python.
        """
        return path_star(self)

    @classmethod
    def clear(cls):
        cls.re_list = []
        cls.paths_list = []
        cls.path_to_bucket = {}

    @classmethod
    def append_re_without_intersection(cls, new_re, p):
        du = dfa_utils
        i = 0
        diff_re_list = []
        length = len(cls.re_list)
        for i in range(0, length):
            existing_re = cls.re_list[i]
            if du.re_equals(existing_re, new_re):
                cls.paths_list[i] += [p]
                return False
            elif du.re_belongs_to(existing_re, new_re):
                cls.paths_list[i] += [p]
                diff_re_list.append(existing_re)
            elif du.re_has_nonempty_intersection(existing_re, new_re):
                # separate out the intersecting and non-intersecting parts
                # non-intersecting part first:
                cls.re_list[i] = '(' + existing_re + ') & ~(' + new_re + ')'
                # create a new expression for the intersecting part:
                intersection_re = '(' + existing_re + ') & (' + new_re + ')'
                cls.re_list.append(intersection_re)
                cls.paths_list.append(cls.paths_list[i] + [p])
                diff_re_list.append(existing_re)
            # Finally, we do nothing if there is no intersection at all.
            i += 1
        # So far we've handled intersecting parts with existing res. Now deal
        # with the intersecting parts of the new re.
        new_nonintersecting_re = new_re
        if diff_re_list:
            all_intersecting_parts = reduce(lambda x,y: x + '|' + y,
                                            diff_re_list)
            if not du.re_belongs_to(new_re, all_intersecting_parts):
                # there's some part of the new expression that's not covered by
                # any of the existing expressions.
                new_nonintersecting_re = ('(' + new_re + ') & ~(' +
                                          all_intersecting_parts + ')')
            else:
                # the new expression was already covered by (parts) of existing
                # expressions, and we've already added path references for those.
                return False
        # add just the non-overlapping parts of the new re to the re_list.
        cls.re_list.append(new_nonintersecting_re)
        cls.paths_list.append([p])
        return True

    @classmethod
    def finalize(cls, p):
        """Add a path into the set of final path queries that will be
        compiled. This is explicitly needed since at the highest level there is
        no AST for the paths.

        :param p: path to be finalized for querying (and hence compilation).
        :type p: path
        """
        # ensure finalization structures exist
        try:
            if cls.re_list and cls.paths_list and cls.path_to_bucket:
                pass
        except:
            cls.re_list = [] # str list
            cls.paths_list = [] # path list list
            cls.path_to_bucket = {} # dict path: bucket

        # modify finalization structures to keep track of newly added expression
        expr = CharacterGenerator.get_terminal_expression(p.expr)
        cls.append_re_without_intersection(expr, p)
        cls.path_to_bucket[p] = p.bucket_instance

    @classmethod
    def get_policy_fragments(cls):
        """Generates tagging and counting policy fragments to use with the
        returned general network policy.
        """
        du = dfa_utils
        cg = CharacterGenerator
        dfa = du.regexes_to_dfa(cls.re_list, '/tmp/pyretic-regexes.txt')

        def set_tag(val):
            if int(val) != 0:
                return modify({'vlan_id': int(val), 'vlan_pcp': 0})
            else:
                return modify({'vlan_id': None, 'vlan_pcp': None})

        def match_tag(val):
            if int(val) == 0:
                return match({'vlan_id': 0xffff, 'vlan_pcp': 0})
            return match({'vlan_id': int(val), 'vlan_pcp': 0})

        tagging_policy = drop
        untagged_packets = identity
        counting_policy = drop
        edge_list = du.get_edges(dfa)

        for edge in edge_list:
            # generate tagging fragment
            src = du.get_state_id(du.get_edge_src(edge, dfa))
            dst = du.get_state_id(du.get_edge_dst(edge, dfa))
            [edge_label, negated] = du.get_edge_label(edge)
            transit_match = cg.get_filter_from_edge_label(edge_label, negated)
            tagging_match = match_tag(src) & transit_match
            tagging_policy += (tagging_match >> set_tag(dst))
            untagged_packets = untagged_packets & ~tagging_match

            # generate counting fragment, if accepting state.
            dst_state = du.get_edge_dst(edge, dfa)
            if du.is_accepting(dst_state):
                accepted_token = du.get_accepted_token(dst_state)
                paths = cls.paths_list[accepted_token]
                for p in paths:
                    bucket = cls.path_to_bucket[p]
                    counting_policy += ((match_tag(src) & transit_match) >>
                                        bucket)

        # preserve untagged packets as is for forwarding.
        tagging_policy += untagged_packets

        # remove all tags before passing on to hosts.
        untagging_policy = ((egress_network() >>
                             modify(vlan_id=None,vlan_pcp=None)) +
                            (~egress_network()))
        return [tagging_policy, untagging_policy, counting_policy]

    @classmethod
    def compile(cls, path_pols):
        """Stitch together the "single packet policy" and "path policy" and
        return the globally effective network policy.

        :param path_pols: a list of path queries
        :type path_pols: path list
        :param single_pkt_pol: main forwarding (single pkt) policy set by
        application
        :type single_pkt_pol: Policy
        """
        for p in path_pols:
            cls.finalize(p)
        return cls.get_policy_fragments()


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
        assert isinstance(other, atom)
        return atom(self.policy & other.policy)

    def __add__(self, other):
        # This won't actually work because the '+' operation results in an
        # object of type parallel, which is not a Filter.
        assert isinstance(other, atom)
        return atom(self.policy + other.policy)

    def __sub__(self, other):
        assert isinstance(other, atom)
        return atom((~other.policy) & self.policy)

    def __invert__(self):
        return atom(~(self.policy))


class atom(abstract_atom):
    """A concrete "ingress" match atom."""
    def __init__(self, m):
        self.token = CharacterGenerator.get_token(m, toktype="ingress",
                                                  nonoverlapping_filters=True)
        super(atom, self).__init__(m)


class path_alternate(path):
    """ Alternation of paths. """
    def __init__(self, paths_list):
        self.__check_type(paths_list)
        super(path_alternate, self).__init__(paths=paths_list)

    def __check_type(self, paths):
        for p in paths:
            assert isinstance(p, path)

    @property
    def expr(self):
        paths = self.paths
        if len(paths) > 1:
            expr = reduce(lambda x, y: x + '|(' + y.expr + ')', paths[1:],
                          '(' + paths[0].expr + ')')
            expr = '(' + expr + ')'
        elif len(paths) == 1:
            expr = paths[0]
        else:
            expr = ''
        return expr


class path_star(path):
    """ Kleene star on a path. """
    def __init__(self, p):
        self.__check_type(p)
        super(path_star, self).__init__(paths=[p])

    def __check_type(self, p):
        assert isinstance(p, path)

    @property
    def expr(self):
        expr = '(' + self.paths[0].expr + ')*'
        return expr


class path_concat(path):
    """ Concatenation of paths. """
    def __init__(self, paths_list):
        self.__check_type(paths_list)
        super(path_concat, self).__init__(paths=paths_list)

    @property
    def expr(self):
        return reduce(lambda x, y: x + y.expr, self.paths, '')

    def __check_type(self, paths):
        for p in paths:
            assert isinstance(p, path)


class egress_atom(abstract_atom):
    """An atom that denotes a match on a packet after the forwarding decision
    has been made. It can always be substituted by a normal ("ingress") atom at
    the next hop, unless the packet is egressing the network. Hence, it may be
    noted that this is only necessary (apart from expressive power, of course)
    to match on packets that egress the network.
    """
    def __init__(self, m):
        self.token = CharacterGenerator.get_token(pol, toktype="egress",
                                                  nonoverlapping_filters=True)
        super(egress_atom, self).__init__(m)


class drop_atom(abstract_atom):
    """An atom that matches on packets that were dropped by the forwarding
    policy.
    """
    def __init__(self, m):
        self.token = CharacterGenerator.get_token(pol, toktype="drop",
                                                  nonoverlapping_filters=True)
        super(drop_atom, self).__init__(m)


#############################################################################
###        Utilities to get data into ml-ulex, and out into DFA           ###
#############################################################################

class dfa_utils:

    @classmethod
    def get_lexer_input(cls, re_list):
        """Return a string formatted such that ml-ulex could take it as input for
        generating a scanner.

        :param re_list: list of regular expressions in ml-ulex format.
        :type re_list: str list
        """
        lex_input = ''
        expr_num = 0
        for r in re_list:
            lex_input += (r + ' => ( T.expr_' + str(expr_num) + ' );')
            lex_input += '\n'
            expr_num += 1
        return lex_input

    @classmethod
    def write_string(cls, string, filename):
        """Write the provided input string into a file.

        :param string: string input to be written into temporary file.
        :type string: str
        :param filename: name of file to be written into
        :type filename: str
        """
        try:
            f = open(filename, 'w')
            f.write(string)
            f.close()
        except:
            print error
            print "There was an error in writing the input to file!"

    @classmethod
    def run_ml_ulex(cls, inp_file):
        try:
            output = subprocess.check_output(["ml-ulex", "--dot", inp_file])
        except subprocess.CalledProcessError:
            print "ERROR: There was an error in running ml-ulex!"
        return output

    @classmethod
    def sort_states(cls, states_list):
        get_index = lambda s: int(s.get_name()[1:])
        cmpfunc = lambda x, y: cmp(get_index(x), get_index(y))
        return sorted(states_list, cmpfunc)

    @classmethod
    def print_dfa(cls, g):
        """Print the extracted DFA from the dot file.

        :param g: graph object extracted from pydot.
        :type g: Graph (pydot class)
        """
        output = "States:\n"
        states_list = [n for n in g.get_node_list() if n.get_name() != 'graph']
        for node in cls.sort_states(states_list):
            output += node.get_name()
            if cls.is_accepting(node):
                output += ': accepting state for expression '
                output += str(cls.get_accepted_token(node))
            output += "\n"
        output += "\nTransitions:"
        for edge in g.get_edge_list():
            src = edge.get_source()
            dst = edge.get_destination()
            label = edge.get_label()
            output += (src + ' --> ' + label + ' --> ' + dst + '\n')
        print output
        return output

    @classmethod
    def get_state_id(cls, s):
        return (s.get_name())[1:]

    @classmethod
    def get_states(cls, g):
        return [n for n in g.get_node_list() if n.get_name() != 'graph']

    @classmethod
    def get_edge_src(cls, e, g):
        """Get the source node object of an edge.

        :param e: edge object
        :type e: Edge
        :param g: graph object
        :type g: Graph
        """
        return g.get_node(e.get_source())[0]

    @classmethod
    def get_edge_dst(cls, e, g):
        return g.get_node(e.get_destination())[0]

    @classmethod
    def get_edge_label(cls, e):

        def get_chars_in_range(low, high):
            chars = ''
            cg = CharacterGenerator
            for t in range(ord(low), ord(high)):
                chars += cg.get_char_from_token(t)
            return chars

        def get_enumerated_labels(label):
            """Get enumerated labels from a character class representation, with
            potential abbreviations of ranges.
            """
            label_sets = label.split('-')
            num_ranges = len(label_sets)
            if num_ranges == 1:
                enumerated_label = label
            else:
                enumerated_label = ''
                num_ranges = len(label_sets)
                for i in range(0, num_ranges):
                    if len(label_sets[i]) == 0:
                        raise RuntimeError # expect valid character classes.
                    enumerated_label += label_sets[i][:-1]
                    if i < (num_ranges-1):
                        enumerated_label += (get_chars_in_range(
                                label_sets[i][-1],
                                label_sets[i+1][0]))
                    else:
                        # last character isn't part of any more ranges.
                        enumerated_label += label_sets[i][-1]
            if len(enumerated_label) > 2 and enumerated_label[0] == '[':
                enumerated_label = enumerated_label[1:-1]
            negated = (enumerated_label[0] == '^')
            if negated:
                enumerated_label = enumerated_label[1:]
            return [enumerated_label, negated]

        return get_enumerated_labels(e.get_label()[1:-1])

    @classmethod
    def get_edges(cls, g):
        return g.get_edge_list()

    @classmethod
    def get_num_states(cls, g):
        return len(cls.get_states(g))

    @classmethod
    def get_num_transitions(cls, g):
        return len(g.get_edge_list())

    @classmethod
    def is_accepting(cls, s):
        return s.get_shape() == '"doublecircle"'

    @classmethod
    def get_accepted_token(cls, s):
        assert cls.is_accepting(s)
        return int(s.get_label().split('/')[1].split('"')[0])

    @classmethod
    def get_num_accepting_states(cls, g):
        states_list = cls.get_states(g)
        num = 0
        for node in cls.sort_states(states_list):
            if cls.is_accepting(node):
                num += 1
        return num

    @classmethod
    def regexes_to_dfa(cls, re_list, tmp_ml_ulex_file):
        lexer_str = cls.get_lexer_input(re_list)
        cls.write_string(lexer_str, tmp_ml_ulex_file)
        ml_ulex_out = cls.run_ml_ulex(tmp_ml_ulex_file)
        tmp_dot  = tmp_ml_ulex_file + ".dot"
        return pydot.graph_from_dot_file(tmp_dot)

    @classmethod
    def intersection_is_null(cls, re1, re2, tmp_file='/tmp/pyretic-regexes-int.txt'):
        """Determine if the intersection of two regular expressions is null.

        :param re1, re2: regular expressions in string format
        :type re1, re2: str
        """
        re = ['(' + re1 + ') & (' + re2 + ')']
        dfa = cls.regexes_to_dfa(re, tmp_file)
        return (cls.get_num_accepting_states(dfa) == 0)

    @classmethod
    def re_equals(cls, re1, re2):
        """Determine if two regular expressions are equal."""
        nre1 = '~(' + re1 + ')'
        nre2 = '~(' + re2 + ')'
        return (cls.intersection_is_null(re1, nre2) and
                cls.intersection_is_null(nre1, re2))

    @classmethod
    def re_belongs_to(cls, re1, re2):
        """Return True if re1 is a subset of re2 (including equals), and False
        otherwise.
        """
        nre2 = '~(' + re2 + ')'
        return cls.intersection_is_null(re1, nre2)

    @classmethod
    def re_has_nonempty_intersection(cls, re1, re2):
        return not cls.intersection_is_null(re1, re2)
