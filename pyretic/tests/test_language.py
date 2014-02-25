
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
from pyretic.core.packet import *
from pyretic.lib.std import *

import pytest

### Equality tests ###

def test_list_equality_1():
    assert [match(switch=1),match(dstip='10.0.0.1')] == [match(switch=1),match(dstip='10.0.0.1')]

def test_list_equality_2():
    assert [match(switch=1),match(dstip='10.0.0.1')] != [match(dstip='10.0.0.1'),match(switch=1)]

def test_modify_equality_1():
    assert modify(outport=1) == modify(outport=1)

def test_modify_equality_2():
    assert modify(outport=1, srcip='10.0.0.1') == modify(outport=1, srcip='10.0.0.1')

def test_parallel_equality_1():
    assert parallel([modify(outport=1)]) == parallel([modify(outport=1)])

def test_parallel_equality_2():
    p1 = parallel([modify(srcip='10.0.0.1'), modify(outport=1)]) 
    p2 = parallel([modify(srcip='10.0.0.1'), modify(outport=1)])
    assert p1 == p2

def test_rule_equality():
    assert Rule(match(inport=1), [drop]) == Rule(match(inport=1), [drop])

def test_rule_list_equality():
    l1 = [ Rule(match(inport=1), [drop]), Rule(identity, [identity]) ]
    l2 = [ Rule(match(inport=1), [drop]), Rule(identity, [identity]) ]
    assert l1 == l2


### Match tests ###

def test_covers_1():
    assert identity.covers(identity)

def test_covers_2():
    assert match(dstip='10.0.0.1').covers(match(dstip='10.0.0.1'))

def test_covers_3():
    assert not match(inport=1).covers(identity)

# TODO check this test
def test_most_specific_prefix_matching():
    c1 = if_(
            match(srcip='10.0.0.1'), modify(outport=2), 
                if_(
                    match(srcip=IPPrefix('10.0.0.0/16')), modify(outport=3),
                    passthrough
                )
            ).compile()
    print c1
    assert c1.rules != [
        Rule(match(srcip='10.0.0.1'), [modify(outport=2)]),
        Rule(match(srcip='10.0.0.0/16'), [modify(outport=3)]),
        Rule(identity, [drop])]


### Classifier tests ###

# Initialization

def test_empty_initialization():
    c = Classifier([])
    assert c.rules == []

def test_single_initialization():
    c = Classifier([Rule(identity, [drop])])
    assert c.rules == [Rule(identity, [drop])]

def test_repeat_initialization():
    c1 = Classifier([Rule(identity, [drop])])
    c2 = Classifier([Rule(identity, [drop])])
    assert c2.rules == [Rule(identity, [drop])]


# Sequencing

def test_empty_sequential_composition():
    assert sequential() == identity

def test_commute_test_true():
    act = modify(srcip='10.0.0.1')
    pkts = match(srcip='10.0.0.1')
    m3 = Classifier()._commute_test(act, pkts)
    assert m3 == true

def test_commute_test_false_1():
    act = drop
    pkts = match(srcip='10.0.0.1')
    m3 = Classifier()._commute_test(act, pkts)
    assert m3 == false

def test_commute_test_false_2():
    act = modify(srcip='0')
    pkts = match(srcip='10.0.0.1')
    m3 = Classifier()._commute_test(act, pkts)
    assert m3 == false

def test_commute_test_incomparable():
    act = modify(srcip='10.0.0.1')
    pkts = match(dstip='10.0.0.2')
    m3 = Classifier()._commute_test(act, pkts)
    assert m3 == match(dstip='10.0.0.2')

def test_commute_id():
    act = identity
    pkts = match(outport=2)
    m3 = Classifier()._commute_test(act, pkts)
    assert m3 == pkts

def test_sequencing_drop_fwd():
    c1 = Classifier([Rule(identity, [drop])])
    c2 = Classifier([Rule(identity, [modify(outport=1)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [Rule(identity, [drop])]

def test_sequencing_fwd_drop():
    c1 = Classifier([Rule(identity, [drop])])
    c2 = Classifier([Rule(identity, [modify(outport=1)])])
    c3 = c2 >> c1
    print c3
    assert c3.rules == [Rule(identity, [drop])]

def test_sequencing_fwd_fwd():
    c1 = Classifier([Rule(identity, [modify(outport=1)])])
    c2 = Classifier([Rule(identity, [modify(outport=2)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [Rule(identity, [modify(outport=2)])]

def test_sequencing_fwd_fwd_shadow():
    c1 = Classifier([Rule(identity, [modify(outport=1)])])
    c2 = Classifier([Rule(identity, [modify(outport=2)]), Rule(identity, [modify(outport=3)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [Rule(identity, [modify(outport=2)])]

def test_sequencing_fwd_fwd_fwd_1():
    c1 = Classifier([Rule(identity, [modify(outport=1)])])
    c2 = Classifier([Rule(identity, [modify(outport=2), modify(outport=3)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [Rule(identity, [modify(outport=2), modify(outport=3)])]

def test_sequencing_fwd_fwd_fwd_2():
    c1 = Classifier([Rule(identity, [modify(outport=1), modify(outport=2)])])
    c2 = Classifier([Rule(identity, [modify(outport=3)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [Rule(identity, [modify(outport=3), modify(outport=3)])]

def test_sequencing_mod_fwd():
    c1 = Classifier([Rule(identity, [modify(dstip='10.0.0.1', dstport=22)])])
    c2 = Classifier([Rule(match(dstip='10.0.0.1'), [modify(outport=3)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [Rule(identity, [modify(dstip='10.0.0.1', dstport=22, outport=3)])]

def test_sequencing_fwd_mod():
    c1 = Classifier([Rule(identity, [modify(outport=3)])])
    c2 = Classifier([Rule(match(srcip='192.168.1.1'), [modify(srcip='10.0.0.1', srcport=1)])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [
        Rule(match(srcip='192.168.1.1'), [modify(srcip='10.0.0.1', srcport=1, outport=3)]),
        Rule(identity, [drop]) ]

def test_sequencing_match_match():
    c1 = Classifier([Rule(match(inport=1), [identity]), Rule(true, [drop])])
    c2 = Classifier([Rule(match(outport=2), [identity]), Rule(true, [drop])])
    c3 = c1 >> c2
    print c3
    assert c3.rules == [
        Rule(match(inport=1, outport=2), [identity]),
        Rule(match(inport=1), [drop]),
        Rule(true, [drop]) ]


# Parallel

def test_empty_parallel_composition():
    assert parallel() == drop


# Intersection

def test_intersect_1():
    assert match(inport=1).intersect(match(outport=2)) == match(inport=1, outport=2)


# Compilation

def test_nested_1():
    pol = match(inport=1) >> match(outport=2) >> modify(outport=3)
    classifier = pol.compile()
    print classifier
    assert classifier.rules == [
        Rule(match(inport=1, outport=2), [modify(outport=3)]),
        Rule(match(inport=1), [drop]),
        Rule(true, [drop]) ]

def test_if_compilation_1():
    pol = if_(true, modify(outport=1), modify(outport=2))
    classifier = pol.compile()
    assert classifier.rules == [
        Rule(true, [modify(outport=1)]) ]

def test_if_compilation_2():
    pol = if_(false, modify(outport=1), modify(outport=2))
    classifier = pol.compile()
    assert classifier.rules == [
        Rule(true, [modify(outport=2)]) ]

def test_if_compilation_3():
    pol = if_(match(inport=2), modify(outport=1), modify(outport=2))
    classifier = pol.compile()
    assert classifier.rules == [
        Rule(match(inport=2), [modify(outport=1)]),
        Rule(true, [modify(outport=2)]) ]

def test_if_compilation_4():
    pol = if_(match(inport=2), modify(outport=1), match(inport=4) >> modify(outport=2))
    classifier = pol.compile()
    print classifier
    assert classifier.rules == [
        Rule(match(inport=2), [modify(outport=1)]),
        Rule(match(inport=4), [modify(outport=2)]),
        Rule(true, [drop]) ]

def test_if_compilation_5():
    pol = if_(match(inport=2), modify(outport=1), modify(outport=3) + modify(outport=2))
    classifier = pol.compile()
    print classifier
    assert classifier.rules == [
        Rule(match(inport=2), [modify(outport=1)]),
        Rule(true, [modify(outport=3), modify(outport=2)]) ]

def test_if_compilation_x():
    mac1 = EthAddr('00:00:00:00:00:01')
    mac2 = EthAddr('00:00:00:00:00:02')
    macB = EthAddr('FF:FF:FF:FF:FF:FF')
    ip1 = IPAddr('10.0.0.1')
    ip2 = IPAddr('10.0.0.2')
    p = IPAddr('10.0.0.11')
    pol = if_(
            match(srcip=ip1),
            modify(srcip=p),
            if_(
              match(dstip=p),
              modify(dstip=ip1)))
    classifier = pol.compile()
    print pol.policy
    print classifier
    assert classifier.rules == [
        Rule(match(srcip=ip1), [modify(srcip=p)]),
        Rule(match(dstip=p), [modify(dstip=ip1)]),
        Rule(true, [identity]) ]


# Bug 1

class TestBug1:

    class TestEnv:
        def __init__(self):
            self.mac1 = EthAddr('00:00:00:00:00:01')
            self.mac2 = EthAddr('00:00:00:00:00:02')
            self.macB = EthAddr('FF:FF:FF:FF:FF:FF')
            self.ip1 = IPAddr('10.0.0.1')
            self.ip2 = IPAddr('10.0.0.2')
            self.p = IPAddr('10.0.0.11')

            self.mod = if_(
                         match(srcip=self.ip1),
                         modify(srcip=self.p),
                         if_(
                           match(dstip=self.p),
                           modify(dstip=self.ip1)))
            self.route = (
              ((match(dstmac=self.mac1) | match(dstmac=self.macB)) >> fwd(1)) +
              ((match(dstmac=self.mac2) | match(dstmac=self.macB)) >> fwd(2)) )

            self.policy = self.mod >> self.route
            self.classifier = self.policy.compile()

    @pytest.fixture
    def e(self):
        return self.TestEnv()

    # ARP request from h1.
    def test_bug_1(self, e):
        pkt = Packet({'srcmac':e.mac1,
                      'dstmac':e.macB,
                      'srcip':e.ip1,
                      'ethtype':ARP_TYPE})

        assert_out_pkts = set([
          Packet({'srcmac':e.mac1,
                  'dstmac':e.macB,
                  'srcip':e.p,
                  'ethtype':ARP_TYPE,
                  'outport':1}),
          Packet({'srcmac':e.mac1,
                  'dstmac':e.macB,
                  'srcip':e.p,
                  'ethtype':ARP_TYPE,
                  'outport':2})
          ])
        pol_out = e.policy.eval(pkt)
        class_out = e.classifier.eval(pkt)

        assert pol_out == class_out
        assert pol_out == assert_out_pkts

    # ARP response from h2 to h1.
    def test_bug_2(self, e):
        pkt = Packet({'srcmac':e.mac2,
                      'dstmac':e.mac1,
                      'srcip':e.ip2,
                      'dstip':e.p,
                      'ethtype':ARP_TYPE})

        assert_out_pkts = set([
          Packet({'srcmac':e.mac2,
                  'dstmac':e.mac1,
                  'srcip':e.ip2,
                  'dstip':e.ip1,
                  'ethtype':ARP_TYPE,
                  'outport':1})
          ])
        pol_out = e.policy.eval(pkt)
        class_out = e.classifier.eval(pkt)

        assert pol_out == class_out
        assert pol_out == assert_out_pkts

    # Ping from h1 to h2.
    def test_bug_3(self, e):
        pkt = Packet({'srcmac':e.mac1,
                      'dstmac':e.mac2,
                      'srcip':e.ip1,
                      'dstip':e.ip2,
                      'ethtype':IP_TYPE})

        assert_out_pkts = set([
          Packet({'srcmac':e.mac1,
                  'dstmac':e.mac2,
                  'srcip':e.p,
                  'dstip':e.ip2,
                  'ethtype':IP_TYPE,
                  'outport':2})
          ])
        pol_out = e.policy.eval(pkt)
        class_out = e.classifier.eval(pkt)

        assert pol_out == class_out
        assert pol_out == assert_out_pkts

    # Ping from h2 to h1.
    def test_bug_4(self, e):
        pkt = Packet({'srcmac':e.mac2,
                      'dstmac':e.mac1,
                      'srcip':e.ip2,
                      'dstip':e.p,
                      'ethtype':IP_TYPE})

        assert_out_pkts = set([
          Packet({'srcmac':e.mac2,
                  'dstmac':e.mac1,
                  'srcip':e.ip2,
                  'dstip':e.ip1,
                  'ethtype':IP_TYPE,
                  'outport':1})
          ])
        pol_out = e.policy.eval(pkt)
        class_out = e.classifier.eval(pkt)

        assert pol_out == class_out
        assert pol_out == assert_out_pkts

def test_match_compilation():
    pol = match(inport=1)
    classifier = pol.compile()
    assert classifier.rules == [
        Rule(match(inport=1), [identity]),
        Rule(identity, [drop]) ]

def test_negation_compilation():
    pol = ~match(inport=1)
    classifier = pol.compile()
    assert classifier.rules == [
        Rule(match(inport=1), [drop]),
        Rule(identity, [identity]) ]

def test_fwd_compilation():
    pol = fwd(1)
    classifier = pol.compile()
    assert classifier.rules == [Rule(identity, [modify(outport=1)])]

def test_match_fwd():
    pol = match(inport=1) >> fwd(2)
    classifier = pol.compile()
    print classifier
    assert classifier.rules == [
        Rule(match(inport=1), [modify(outport=2)]),
        Rule(identity, [drop]) ]

def test_xfwd_compilation():
    pol = xfwd(1)
    print pol.policy
    classifier = pol.compile()
    print classifier.rules
    assert classifier.rules == [
        Rule(match(inport=1), [drop]),
        Rule(identity, [modify(outport=1)]) ]

class FakeNetwork(Network):
    pass

def test_flood_compilation():
    pol = flood()
    topo = Topology()
    topo.add_switch('s1')
    topo.add_port('s1', 1, True, True)
    topo.add_port('s1', 2, True, True)
    pol.set_network(FakeNetwork(topo))
    
    classifier = pol.compile()
    print pol.policy
    print classifier
    assert classifier.rules == [
        Rule(match(switch='s1', inport=1), [modify(outport=2)]),
        Rule(match(switch='s1', inport=2), [modify(outport=1)]),
        Rule(match(switch='s1'), [modify(outport=1), modify(outport=2)]),
        Rule(identity, [drop]) ]

# Optimization

def test_remove_shadow_cover_single():
    c = Classifier([Rule(identity, [drop]), Rule(identity, [drop])])
    c = c.remove_shadowed_cover_single()
    print c
    assert c.rules == [Rule(identity, [drop])]

def test_optimize_bug_1():
    classifier = Classifier([
        Rule(match(inport=1), [modify(outport=1)]),
        Rule(identity, [drop]) ])
    print 'classifier:'
    print classifier
    print 'classifier.optimize():'
    print classifier.optimize()
    assert classifier == classifier.optimize()
