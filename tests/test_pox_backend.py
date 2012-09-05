
import pytest

from pox.lib.packet import *
from pox.openflow.libopenflow_01 import *

from frenetic.netcore import *
from frenetic.netcore_lib import *
from frenetic.pox_backend import *

act = mod(outport=10)

ping_pkt = ethernet('\xff\xff\xff\xff\xff\xff\xea4\xe2\xed\x1e\x8a\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xea4\xe2\xed\x1e\x8a\n\x00\x00\x02\x00\x00\x00\x00\x00\x00\n\x00\x00\x03')
match = ofp_match.from_packet(ping_pkt)

hdr = header(srcmac="AC-AF-FF-00-BC-a1",
             dstmac="bc-23-00-00-00-00",
             type = ethernet.LLDP_TYPE)

def test_header_match_involution():
    assert pyretic_header_to_pox_match(pox_match_to_pyretic_header(match)) == match

def test_match_header_involution():
    assert pox_match_to_pyretic_header(pyretic_header_to_pox_match(hdr)) == hdr

def text_propagate():
    ping_hdr = pox_match_to_pyretic_header(match)
    assert propagate_header_to_payload(ping_hdr, ping_pkt) == ping_pkt.pack()

    eth = "ab:cd:ef:00:00"
    ping_pkt_2.src = EthAddr(eth)
    
    assert propagate_header_to_payload(ping_hdr.update(srcmac=MAC(eth)), ping_pkt) == ping_pkt_2 
    
 
    
# def test_compile_action():
#   assert compile_action(drop) == []
#   assert compile_action(act) == [ofp_action_output(port=10)]

# def test_compile_bad_actions():
#   with pytest.raises(Exception):
#     compile_action(mod(blah=30, outport=10)) # fake header
#   with pytest.raises(Exception):
#     compile_action(mod(srcip="1.2.3.5")) # mod without outport
#   with pytest.raises(Exception):
#     compile_action(mod(srcip="1.2.3.5", outport=10) +
#                    mod(dstport=12, outport=10)) # action without subset relationship
    
