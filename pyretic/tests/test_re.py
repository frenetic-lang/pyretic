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

def test_deriv():
    # Declare some basic re's first
    eps = re_epsilon()
    phi = re_empty()
    a = re_symbol('a')
    b = re_symbol('b')
    c = re_symbol('c')

    # write some regular expressions for later testing
    r1 = (a | b) ^ (+c)
    r2 = a | (b | a)
    l = [r1, r2]

    # check derivative equality
    assert deriv(phi, a) == phi
    assert deriv(eps, a) == phi
    assert deriv(b, a) == phi
    assert deriv(b, b) == eps
    assert deriv(a ^ b, a) == b
    assert deriv(+r1, a) == (deriv(r1,a) ^ +r1)
    assert deriv(~c, c) == ~eps
    
# Just in case: keep these here to run unit tests in vanilla python
if __name__ == "__main__":
    test_normal_forms()
    test_smart_constructors()
    test_deriv()

    print "If this message is printed without errors before it, we're good."
    print "Also ensure all unit tests are listed above this line in the source."

