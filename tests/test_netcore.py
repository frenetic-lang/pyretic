
import pytest

from tests.common import *
from frenetic.netcore import *
from frenetic.netcore import _
from frenetic.network import *


################################################################################
# Matchable junk
################################################################################

w = Wildcard(8)(bitarray("00000000"), bitarray("00000000"))
w2 = Wildcard(8)(bitarray("00000000"), bitarray("11111111"))

def test_Wildcard_match():
    assert w <= w
    assert w2 > w

def test_Wildcard_intersect():
    assert w & w2 == w2 & w

def test_MatchExact():
    return MatchExact(Switch)(10).match(Switch(10))

ip = IPWildcard("1.2.3.*")
ip2 = IPWildcard("1.2.3.4", "255.255.255.0")

def test_IPWildcard():    
    assert ip == ip2
    assert ip <= ip2
    assert ip2 <= ip
    assert not ip != ip2
    
    assert ip2 == IPWildcard("1.2.3.8", "255.255.255.0")
    assert not IPWildcard("255.255.255.255").match(IP("255.255.255.252"))


################################################################################
# Predicates
################################################################################


def test_Predicate_eval():
    p = packets[0]
    assert all_packets.eval(p)
    assert not no_packets.eval(p)

    assert (_.srcip == "1.2.3.4").eval(packets[1])
    assert (_.srcip == "1.2.3.*").eval(packets[1])
    assert (_.srcip == IP("1.2.3.4")).eval(packets[1])
    assert (_.srcip == IPWildcard("1.2.*.4")).eval(packets[1])
    assert not (_.dstport == 30).eval(packets[1])
    assert (_.dstport == Port(700)).eval(packets[1])


def test_Action():
    assert not drop.packets_to_send(packets[1])
    p = modify(srcport=100, dstport=100).packets_to_send(packets[1])[0]
    assert p.srcport == 100 and p.dstport == 100


let_pol1 = let(modify(dstport=1), lambda p: ((_.dstport == 700) & (p.dstport == 1)) & fwd(100))

def test_Let():
    assert let_pol1.packets_to_send(packets[1])[0].outport == Port(100)
    assert let_pol1.packets_to_send(packets[1])[0].dstport == 700

comp_pol1 = modify(dstport=1) >> ((_.dstport == 1) & (_.srcport == 30) & fwd(100))
    
def test_Composition():
    assert comp_pol1.packets_to_send(packets[1])[0].outport == Port(100)

def test_fwd():
    for packet in packets:
        assert fwd(1).packets_to_send(packet)[0].outport == Port(1)
    
def test_match_ips():
    assert (_.dstip == "127.0.0.1").eval(packets[1])
    assert (_.dstip == "127.*.*.*").eval(packets[1])
    assert (_.dstip == "*.*.*.1").eval(packets[1])
    assert (_.dstip == "127.0.0.1/32").eval(packets[1])
    assert (_.dstip == "127.0.0.255/24").eval(packets[1])
    assert not (_.dstip == "124.0.0.255/24").eval(packets[1])
    assert (_.dstip == "127.0.0.255/24").eval(packets[1])
    assert (_.dstip == ("127.0.0.255", 24)).eval(packets[1])
    assert (_.dstip == ("127.0.0.255", "255.255.255.0")).eval(packets[1])
    assert (_.dstip == "127.0.0.255/255.255.255.0").eval(packets[1])

    assert _.meow.is_missing().eval(packets[1])
    assert not _.srcip.is_missing().eval(packets[1])
    
def test_match_ints():    
    assert (_.srcport == 30).eval(packets[1])
    assert not (_.srcport == 31).eval(packets[1])
    assert not (_.srcport == "1000100010001000").eval(packets[1])
    assert not (_.srcport == "???????????????1").eval(packets[1])
    assert     (_.srcport == "????????????????").eval(packets[1])
    assert     (_.srcport == "???????????1111?").eval(packets[1])
    assert     (_.srcport == "0000000000011110").eval(packets[1])
    
    
################################################################################
# Test networks
################################################################################

def test_in_place():
    pass

def test_Network():
    n = Network()
    assert not n.get_policy().packets_to_send(packets[0])

    n_fork = fork_sub_network(n)
    n_fork.install_policy(fwd(10))

    assert isinstance(n.get_policy(), Policy)

    import time

    time.sleep(1)

    assert n.get_policy().packets_to_send(packets[0])[0].outport == Port(10) 
    
    
    
