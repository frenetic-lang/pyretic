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

# Data type definitions
class re_deriv:
    def __init__(self):
        pass

class re_epsilon(re_deriv):
    def __init__(self):
        pass

class re_empty(re_deriv):
    def __init__(self):
        pass

class re_symbol(re_deriv):
    def __init__(self, char):
        self.char = char

class re_combinator(re_deriv):
    def __init__(self, re1, re2):
        self.re1 = re1
        self.re2 = re2

class re_concat(re_combinator):
    def __init__(self, re1, re2):
        super(re_concat, self).__init__(re1, re2)

class re_alter(re_combinator):
    def __init__(self, re1, re2):
        super(re_alter, self).__init__(re1, re2)

class re_star(re_deriv):
    def __init__(self, re):
        self.re = re

class re_inters(re_combinator):
    def __init__(self, re1, re2):
        super(re_inters, self).__init__(re1, re2)

class re_negate(re_deriv):
    def __init__(self, re):
        self.re = re

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
        return bool_to_re(re_to_bool(nullable(r.re1)) and 
                          re_to_bool(nullable(r.re2)))
    elif isinstance(r, re_alter):
        return bool_to_re(re_to_bool(nullable(r.re1)) or
                          re_to_bool(nullable(r.re2)))
    elif isinstance(r, re_star):
        return re_epsilon()
    elif isinstance(r, re_inters):
        return bool_to_re(re_to_bool(nullable(r.re1)) and 
                          re_to_bool(nullable(r.re2)))
    elif isinstance(r, re_negate):
        return bool_to_re(not re_to_bool(nullable(r.re)))
    else:
        raise TypeError

# Derivative of a regular expression with respect to a single symbol
def deriv(r, a):
    assert isinstance(r, re_deriv)
    assert isinstance(a, re_symbol)
    asym = a.char
    if isinstance(r, re_epsilon):
        return re_empty()
    elif isinstance(r, re_symbol):
        rsym = r.char
        return re_epsilon() if rsym == asym else re_empty()
    elif isinstance(r, re_empty):
        return re_empty()
    elif isinstance(r, re_concat):
        return re_alter(
            re_concat(deriv(r.re1, a), r.re2),
            re_concat(nullable(r.re1), deriv(r.re2, a)))
    elif isinstance(r, re_star):
        return re_concat(deriv(r.re1, a), r)
    elif isinstance(r, re_alter):
        return re_alter(deriv(r.re1, a), deriv(r.re2, a))
    elif isinstance(r, re_inters):
        return re_inters(deriv(r.re1, a), deriv(r.re2, a))
    elif isinstance(r, re_negate):
        return re_negate(deriv(r.re, a))
    else:
        raise TypeError

# Derivative of a regular expression with respect to a string
def deriv_string(r, s):
    assert isinstance(r, re_deriv)
    assert isinstance(s, str)
    if len(s) == 0:
        return r
    else:
        a = re_symbol(s[0])
        return deriv(deriv_string(r, s[1:]), a)

# Match a single string against a single regular expression
def match_string(r, s):
    assert isinstance(r, re_deriv)
    assert isinstance(s, str)
    if len(s) == 0:
        return re_to_bool(nullable(r))
    else:
        a = re_symbol(s[0])
        return match_string(deriv(r, a), s[1:])
