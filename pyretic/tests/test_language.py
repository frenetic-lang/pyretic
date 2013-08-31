
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
# author: Cole Schlesinger (cschlesi@cs.princeton.edu)                         #
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
from pyretic.lib.std import (ARP_TYPE, IP_TYPE)

### Match tests ###

def test_covers_self_1():
    assert match().covers(match())

def test_covers_self_2():
    assert match(dstip='10.0.0.1').covers(match(dstip='10.0.0.1'))


### Classifier tests ###

# Initialization

def test_empty_initialization():
    c = Classifier([])
    assert c.rules == []

def test_single_initialization():
    c = Classifier([Rule(match(), [drop])])
    assert c.rules == [Rule(match(), [drop])]

def test_repeat_initialization():
    c1 = Classifier([Rule(match(), [drop])])
    c2 = Classifier([Rule(match(), [drop])])
    assert c2.rules == [Rule(match(), [drop])]


# Sequencing

def test_invert_action_true():
    act = modify(srcip='10.0.0.1')
    pkts = match(srcip='10.0.0.1')
    m3 = Classifier()._invert_action(act, pkts)
    assert m3 == true

def test_invert_action_false_1():
    act = drop
    pkts = match(srcip='10.0.0.1')
    m3 = Classifier()._invert_action(act, pkts)
    assert m3 == false

def test_invert_action_false_2():
    act = modify(srcip='0')
    pkts = match(srcip='10.0.0.1')
    m3 = Classifier()._invert_action(act, pkts)
    assert m3 == false

def test_invert_action_incomparable():
    act = modify(srcip='10.0.0.1')
    pkts = match(dstip='10.0.0.2')
    m3 = Classifier()._invert_action(act, pkts)
    assert m3 == match(dstip='10.0.0.2')

def test_sequencing_drop_fwd():
    c1 = Classifier([Rule(match(), [drop])])
    c2 = Classifier([Rule(match(), [fwd(1)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [Rule(match(), [drop])]

def test_sequencing_fwd_drop():
    c1 = Classifier([Rule(match(), [drop])])
    c2 = Classifier([Rule(match(), [fwd(1)])])
    c3 = c2 >> c1
    print c3
    assert c3.rules == [Rule(match(), [drop])]

def test_sequencing_fwd_fwd():
    c1 = Classifier([Rule(match(), [fwd(1)])])
    c2 = Classifier([Rule(match(), [fwd(2)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [Rule(match(), [fwd(2)])]



# Optimization

def test_remove_shadow_cover_single():
    c = Classifier([Rule(match(), [drop]), Rule(match(), [drop])])
    c = c.remove_shadowed_cover_single()
    print c
    assert c.rules == [Rule(match(), [drop])]

