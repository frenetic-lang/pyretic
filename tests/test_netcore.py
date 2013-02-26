
import pytest

from tests.common import *



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

def test_match_ips():
    assert match(dstip="127.0.0.1").eval(packets[1])
    assert match(dstip="127.*.*.*").eval(packets[1])
    assert match(dstip="*.*.*.1").eval(packets[1])
    assert match(dstip="127.0.0.1/32").eval(packets[1])
    assert match(dstip="127.0.0.255/24").eval(packets[1])
    assert not match(dstip="124.0.0.255/24").eval(packets[1])
    assert match(dstip="127.0.0.255/24").eval(packets[1])
    assert match(dstip=("127.0.0.255", 24)).eval(packets[1])
    assert match(dstip=("127.0.0.255", "255.255.255.0")).eval(packets[1])
    assert match(dstip="127.0.0.255/255.255.255.0").eval(packets[1])

    assert match(meow=None).eval(packets[1])
    assert not match(srcip=None).eval(packets[1])
    
def test_match_ints():    
    assert match(srcport=30).eval(packets[1])
    assert not match(srcport=31).eval(packets[1])
    assert not match(srcport="1000100010001000").eval(packets[1])
    assert not match(srcport="???????????????1").eval(packets[1])
    assert     match(srcport="????????????????").eval(packets[1])
    assert     match(srcport="???????????1111?").eval(packets[1])
    assert     match(srcport="0000000000011110").eval(packets[1])


def test_copy():
    p = packets[1]._push(switch=10)
    p_ = p._push(vswitch=10)
    assert get_single_packet(move(vswitch="switch"), p) == p_


# Test virtualization
#


def _test_tri_topos():
    from virttopos.triangle_bfs import vinfo, get_ingress_policy, get_physical_policy, setup_virtual_network
    
    user_policy = fwd(3)

    p = packets[2]._push(switch=1, inport=1)
    p2 = p._push(vswitch=1, vinport=1)

    assert get_single_packet(get_ingress_policy(), p) == p2

    p3 = p._modify(switch=1, inport=1)

    p4 = p3._push(outport=3)
    assert get_single_packet(user_policy, p3) == p4

    p5 = p2._push(voutport=3)
    # Can't do this, need a testing mechanism for it!
    # assert get_single_packet(let(passthrough, lambda x: headers_to_post_vheaders(vlan_db, x)), p2) 

    p6 = p5._push(outport=3)
    assert get_single_packet(get_physical_policy(), p5) == p6

    p7 = p6._modify(vswitch=None, vinport=None, voutport=None,
                                 vlan=vlan_db[3][(Switch(1), Port(1), Port(3))])
    
    vp = vheaders_to_vlan_policy(vlan_db)
    p7_ = get_single_packet(vp, p6)
    assert p7_ == p7
    

    n = Network()
    vn = setup_virtual_network(n)
    vn.install_policy(user_policy)

    import time
    time.sleep(0.01)

    pol = n.policy
    p7_ = get_single_packet(pol, p)
    assert p7_ == p7

    
def test_linear_topos():
    from virttopos.linear_4_bfs import vmap, setup_virtual_network

    user_policy = fwd(3)
    
    p = packets[2]._push(switch=1, inport=1)
    
    n = Network()
    vn = setup_virtual_network(n)
    vn.install_policy(user_policy)

    import time
    time.sleep(0.01)

    pol = n.policy
    
    p_ = get_single_packet(pol, p)
    
    assert p_.switch == Switch(1)
    assert p_.outport == Port(2)

    # Now lets test the second packet. Can it get to the third hop?
    p2 = p_._modify(switch=2, outport=None, inport=2)
    p2_ = get_single_packet(pol, p2)
    
    assert p2_.switch == Switch(2)
    assert p2_.outport == Port(3) 

    # Third hop.
    p3 = p2_._modify(switch=3, outport=None, inport=2)
    p3_ = get_single_packet(pol, p3)
    
    assert p3_.switch == Switch(3)
    assert p3_.outport == Port(1)

    assert not hasattr(p3_, "vtag") # was the vlan successfully removed?
    assert not hasattr(p3_, "vinport") # was the vlan successfully removed?
    
    
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

    
