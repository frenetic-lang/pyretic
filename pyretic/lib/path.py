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

from pyretic.core.language import Filter, match, Query, FwdBucket, CountBucket
from pyretic.lib.query import counts, packets
import subprocess
import pyretic.vendor
import pydot

#############################################################################
### Basic classes for generating path atoms and creating path expressions ###
#############################################################################

class CharacterGenerator:
    """ Generate characters to represent equivalence classes of existing match
    predicates. `get_token` returns the same token value as before if a policy
    already seen (and hence recorded in its map) is provided to it.
    """
    token = 32 # start with printable ASCII for visual inspection ;)
    filter_to_token = {}
    token_to_filter = {}
    
    @classmethod
    def get_token(cls, pol):
        if pol in cls.filter_to_token:
            return cls.filter_to_token[pol]
        else:
            new_token = cls.__new_token__()
            cls.filter_to_token[pol] = new_token
            cls.token_to_filter[new_token] = pol
            return new_token

    @classmethod
    def get_char_from_token(cls, tok):
        try:
            return chr(tok)
        except:
            return unichr(tok)

    @classmethod
    def char_in_lexer_language(cls, chr):
        return chr in ['*','+','|','{','}','(',')','-','^','.','&','?']

    @classmethod
    def __new_token__(cls):
        cls.token += 1
        char = cls.get_char_from_token(cls.token)
        if cls.char_in_lexer_language(char):
            return cls.__new_token__()
        return cls.token


class path(Query):
    """A way to query packets or traffic volumes satisfying regular expressions
    denoting paths of located packets.

    :param a: path atom used to construct this path element
    :type atom: atom
    """
    def __init__(self, a=None, expr=None):
        if a:
            assert isinstance(a, atom)
            self.atom = a
            self.expr = CharacterGenerator.get_char_from_token(self.atom.token)
        elif expr:
            assert isinstance(expr, str)
            self.expr = expr
        else:
            raise RuntimeError

    def __xor__(self, other):
        """Implementation of the path concatenation operator ('^')"""
        assert isinstance(other, path)
        return path(expr=(self.expr + other.expr))

    def __or__(self, other):
        """Implementation of the path alternation operator ('|')"""
        assert isinstance(other, path)
        return path(expr=('(' + self.expr + ')|(' + other.expr + ')'))

    def __pos__(self):
        """Implementation of the Kleene star operator.

        TODO(ngsrinivas): It just looks wrong to use '+' instead of '*', but
        unfortunately there is no unary (prefix or postfix) '*' operator in
        python.
        """
        return path(expr=('(' + self.expr + ')*'))


class atom(path, Filter):
    """A single atomic match in a path expression.
    
    :param m: a Filter (or match) object used to initialize the path atom.
    :type match: Filter
    """
    def __init__(self, m):
        assert isinstance(m, Filter)
        self.policy = m
        self.token = CharacterGenerator.get_token(m)
        super(atom, self).__init__(a=self)

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
            if node.get_shape() == '"doublecircle"':
                output += ': accepting state for expression '
                token_line = node.get_label().split('/')[1].split('"')[0]
                output += token_line
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
    def get_num_states(cls, g):
        states_list = [n for n in g.get_node_list() if n.get_name() != 'graph']
        return len(states_list)

    @classmethod
    def get_num_transitions(cls, g):
        return len(g.get_edge_list())

    @classmethod
    def get_num_accepting_states(cls, g):
        states_list = [n for n in g.get_node_list() if n.get_name() != 'graph']
        num = 0
        for node in cls.sort_states(states_list):
            if node.get_shape() == '"doublecircle"':
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
    def intersection_is_null(cls, re1, re2, tmp_file):
        """Determine if the intersection of two regular expressions is null.

        :param re1, re2: regular expressions in string format
        :type re1, re2: str
        """
        re = ['(' + re1 + ') & (' + re2 + ')']
        return (cls.get_num_states(cls.regexes_to_dfa(re, tmp_file)) == 1)

