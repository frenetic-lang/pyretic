
from frenetic.net import *
from frenetic.netcore import *

h = Header(srcip=IP("1.2.3.4"))
p = Packet(h, 32, None)

w = Wildcard(bitarray("00000000"))
w2 = Wildcard(bitarray("00000000"), bitarray("11111111"))

ip = IPWildcard("1.2.3.*")
ip2 = IPWildcard("1.2.3.4", "255.255.255.0")

def test_Wildcard_match():
    assert w <= w
    assert w2 > w

def test_Wildcard_intersect():
    assert w & w2 == w2 & w

def test_MatchExact():
    return MatchExact(Switch(10)).match_object(Switch(10))

def test_IPWildcard():    
    assert ip == ip2
    assert ip <= ip2
    assert ip2 <= ip
    assert not ip != ip2
    
    assert ip2 == IPWildcard("1.2.3.8", "255.255.255.0")
    assert not IPWildcard("255.255.255.255").match_object(IP("255.255.255.252"))
    
def test_Predicate_eval():
    assert eval(PredTop(), p)
    assert not eval(PredBottom(), p)
    assert eval(PredMatch("srcip", Wildcard(IP("1.2.3.4").to_bits())), p)
    assert eval(PredMatch("srcip", IPWildcard("1.2.3.*")), p)
    assert eval(PredMatch("srcip", IPWildcard("1.2.3.4", "255.255.255.0")), p)

act = ActMod({"srcport": FixedInt(30, 16)})
pol = PredMatch("srcip", IPWildcard("1.2.3.*")) >> act

def test_Action():
    assert not mod_packet(ActDrop(), p)
    assert mod_packet(act, p)[0].header["srcport"] == FixedInt(30, 16)
    assert len(mod_packet(act + act, p)) == 2
    
def test_Policy():
    assert eval(pol, p) == act

lact = ActMod({"switch": Switch(10)})
l = PolLet("x", pol, "srcport", PredMatch("x", MatchExact(FixedInt(30, 16))) >> lact)

def test_Let():
    assert eval(l, p) == ActMod({"switch": Switch(10)})

ipol = PredMatch("switch", MatchExact(Switch(10))) >> ActMod({"switch": Switch(25)})
cpol = l * ipol

def test_Composition():
    assert mod_packet(eval(cpol, p), p)[0].header["switch"] == Switch(25)
