
import pytest

from tests.common import *




################################################################################
# Predicates
################################################################################


def test_Predicate_eval():
    p = packets[0]
    assert all_packets.eval(p)
    assert not no_packets.eval(p)

    assert match(srcip="1.2.3.4").eval(packets[1])
    assert match(srcip="1.2.3.*").eval(packets[1])
    assert match(srcip=IP("1.2.3.4")).eval(packets[1])
    assert match(srcip=IPWildcard("1.2.*.4")).eval(packets[1])
    assert not match(dstport=30).eval(packets[1])
    assert match(dstport=Port(700)).eval(packets[1])


def test_Action():
    assert not drop.eval(packets[1])
    p = get_single_packet(modify(srcport=100, dstport=100), packets[1])
    assert p.srcport == 100 and p.dstport == 100

def test_Composition():
    comp_pol1 = modify(dstport=1) >> (match(dstport=1) & match(srcport=30) & fwd(100))
    assert get_single_packet(comp_pol1, packets[1]).outport == Port(100)
    
    comp_pol2 = modify(vinport=None, vswitch=None) >> ((match(vinport=1) | match(vswitch=1)) & fwd(100))
    assert not comp_pol2.eval(packets[1]._push(vswitch=1, vinport=1))

    

def test_fwd():
    for packet in packets:
        assert get_single_packet(fwd(1), packet).outport == Port(1)


def test_copy():
    p = packets[1]._push(switch=10)
    p_ = p._push(vswitch=10)
    assert get_single_packet(move(vswitch="switch"), p) == p_


    
################################################################################
# Test networks
################################################################################

def test_Network():
    n = Network()
    n.init_events()
    assert not n.policy.eval(packets[0])

    n_fork = fork_sub_network(n)
    n_fork.install_policy(fwd(10))

    assert isinstance(n.policy, Policy)

    import time
    time.sleep(0.01)

    assert get_single_packet(n.policy, packets[0]).outport == Port(10)

    
