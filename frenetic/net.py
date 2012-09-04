
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

"""Frenetic networking structures and NOX wrappers"""

# This module is designed for import *.

import array 
import struct

from frenetic import util
from frenetic.util import Record, Case, frozendict

from bitarray import bitarray


__all__ = ["Header", "Packet", "FixedInt", "IP", "MAC", "Switch"]

################################################################################
# Network Structures
################################################################################

class Header(frozendict):
    """Expected fields:
    switch location srcmac dstmac dltype vlan vlan_pcp srcip dstip
    protocol srcport dstport"""

class Packet(Record):
    """Class representing packets (insightful, huh)"""

    _fields = "header size payload time"

    def __new__(cls, header, size, payload, time=None):
        time = time or util.current_time()
        return Record.__new__(cls, header, size, payload, time)
        
   
class PortEvent(Record):
    """Represents port events (insightful, huh)"""

    _fields = "switch number name enabled linkup"
    
    def __repr__(self):
        ## XXX Mininet Hack.  Right now, the only way to generate port
        ## status changes is through the enabled field.  For a real
        ## implementation the conditional should be (enabled && linkup)
        up = "Up" if self.enabled is True else "Down"
        return "PortEvent(%s, %s, %s, %s)" % (self.switch, self.number, self.name, up)

        
#
# Utility network structures
        

def FixedInt(width_):
    class FixedInt_(int):
        width = width_
        
        def __new__(cls, value):
            if isinstance(value, basestring):
                assert len(value) == cls.width
                i = int.__new__(cls, value, 2)
            else:
                i = int.__new__(cls, value)
            return i

        # TODO this is slow.
        def to_bits(self):
            return bitarray(bin(self)[2:self.width+2].zfill(self.width))

        def __add__(self, v):
            return FixedInt(self.width)(int.__add__(self, v))

        def __sub__(self, v):
            return FixedInt(self.width)(int.__sub__(self, v))

        def __mul__(self, v):
            return FixedInt(self.width)(int.__mul__(self, v))

        def __div__(self, v):
            return FixedInt(self.width)(int.__div__(self, v))

        def __mod__(self, v):
            return FixedInt(self.width)(int.__mod__(self, v))

        def __and__(self, v):
            return FixedInt(self.width)(int.__and__(self, v))

        def __or__(self, v):
            return FixedInt(self.width)(int.__or__(self, v))

        def __xor__(self, v):
            return FixedInt(self.width)(int.__xor__(self, v))

        def __pow__(self, v):
            return FixedInt(self.width)(int.__pow__(self, v))

        def __rshift__(self, v):
            return FixedInt(self.width)(int.__lshift__(self, v))

        def __lshift__(self, v):
            return FixedInt(self.width)(int.__rshift__(self, v))

        def __abs__(self):
            return FixedInt(self.width)(int.__abs__(self))

        def __invert__(self):
            return FixedInt(self.width)(int.__invert__(self))

        def __pos__(self):
            return FixedInt(self.width)(int.__pos__(self))

        def __neg__(self):
            return FixedInt(self.width)(int.__or__(self))

        def __repr__(self):
            return int.__repr__(self) + "#" + str(self.width)
            
    FixedInt_.__name__ += repr(FixedInt_.width)
    return FixedInt_
    
        
class Switch(Record):
    _fields = "switch_int"

    width = 8
    
    def __repr__(self):
        return "<switch %s>" % self.switch_int

    def __int__(self):
        return self.switch_int
    
    def to_bits(self):
        b = bitarray()
        b.frombytes(struct.pack("!B", self.switch_int))
        return b

class Location(Record):
    _fields = "at port"

    # At is "in" or "out"
    # Port is an int

    width = 9

    def __repr__(self):
        return "<loc %s %s>" % (self.at, self.port)

    # XXX double check
    def to_bits(self):
        b = bitarray()
        b.insert(0, self.at == "out")
        b.frombytes(struct.pack("!B", self.port))
        return b
        

class MAC(Record):
  _fields = "macbytes"
  width = 48

  def to_bits(self):
    b = bitarray()
    b.frombytes(self.macbytes)
    return b
    

# XXX what should this fundamentally be?
class IP(Record):
    _fields = "ipbytes"

    width = 32
    
    def __new__(cls, ip):
        import socket
        
        if len(ip) != 4:
            ip = socket.inet_aton(ip)

        return Record.__new__(cls, ip)
        
    def __repr__(self):
        import socket
        return socket.inet_ntoa(self.ipbytes)
       
    def to_bits(self):
        b = bitarray()
        b.frombytes(self.ipbytes)
        return b


        

    
