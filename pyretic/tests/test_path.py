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
cg = CharacterGenerator()

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

### Basic checks on creating and manipulating path atoms ###

def test_atom_creation():
    m1 = match(srcip=ip1) & match(switch=2)
    a1 = atom(m1)
    assert a1.policy == m1

def test_atom_and():
    a1 = atom(match(srcip=ip1))
    a2 = atom(match(switch=1))
    assert (a1 & a2).policy == (match(srcip=ip1) & match(switch=1))

def test_atom_negate():
    a1 = atom(match(srcip=ip1))
    assert (~a1).policy == (~match(srcip=ip1))

# TODO(ngsrinivas): skipping test_atom_or and test_atom_difference, since these
# two don't work currently. Adding two atoms will result in a TypeError (it
# results in a `parallel` type, not a `Filter` type), and difference
# implementation is just buggy in the language right now.

