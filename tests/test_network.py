
################################################################################
# The Frenetic Project                                                         #
# frenetic@frenetic-lang.org                                                   #
################################################################################
# Licensed to the Frenetic Project by one or more contributors. See the        #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Frenetic Project licenses this        #
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

import pytest


from tests.common import *

from frenetic.netcore import *
from frenetic.network import *
from frenetic.virt import *

################################################################################
# Fixed width friends
################################################################################
    
def test_FixedInt_bitarray():
    i1 = FixedInt(32)("00000000000000000000000000000000")
    assert i1.to_bits().to01() == "00000000000000000000000000000000"
    
    i2 = FixedInt(32)(0)
    assert i2.to_bits().to01() == "00000000000000000000000000000000"

    assert i1 == i2
    
    i = FixedInt(16)(222)
    assert i.to_bits().to01() == "0000000011011110"

    assert i1 != i

def test_FixedInt_operators():
    i1 = FixedInt(16)(222)
    i2 = FixedInt(16)(111)
    i3 = i1 + i2
    
    assert i3.width == 16

def test_FixedInt_mismatch():
    i1 = FixedInt(16)(222)
    i2 = FixedInt(32)(111)

    with pytest.raises(Exception):
        i1 + i2

def test_Switch():
    assert repr(Switch(2)) == "<switch 2>"

    
def test_Port():
    p = Port(Bucket())

    assert not p.is_real()

    p = Port(10)

    assert p.is_real()
    assert Port(p).is_real()

    assert int(p) == 10
    

def test_MAC():
    MAC("09-00-2B-00-00-04")
    MAC("00000001" * 6)
    MAC(FixedInt(48)(3))


def test_MAC_fail():
    with pytest.raises(Exception):
        MAC(FixedInt(32)(3))
    

def test_MAC_fail():
    with pytest.raises(Exception):
        MAC("09-00-2B-00-00")

        
def test_IP():
    assert IP("1.5.3.2") != IP(IP("1.3.5.7"))

    
def test_IP_fail():
    with pytest.raises(Exception):
        IP("1.3.3.5heytest")
    
################################################################################
# Packets and headers and stuff
################################################################################

def test_packet_modify():
    p0 = packets[0].update_header_fields(switch=10)

    for attr in packets[0].header:
        if attr == "switch":
            assert getattr(p0, attr) == Switch(10)
        else:
            assert getattr(p0, attr) == getattr(packets[0], attr)

    p0 = packets[0].update_header_fields(srcmac="01:01:01:01:01:05")

    for attr in packets[0].header:
        if attr == "srcmac":
            assert getattr(p0, attr) == MAC("01:01:01:01:01:05")
        else:
            assert getattr(p0, attr) == getattr(packets[0], attr)

def test_vlan():
    """setting the vlan should always work"""
    import random
    for packet in packets:
        r = random.randint(1, 2**12-1)
        p1 = packet.update_header_fields(vlan=r)
        p2 = Packet(p1._get_payload())
        assert p1.vlan == r
        # XXX need a better test for this
        # assert real_packets_equal(p1, p2), "did the setting actually work?"
