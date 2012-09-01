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

import array 
import struct
from abc import ABCMeta, abstractmethod

from frenetic import util, netcore
from frenetic.util import Record, Case, frozendict

from bitarray import bitarray


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
        

class FixedInt(int):
    def __new__(cls, value, width):
        if isinstance(value, basestring):
            assert len(value) == width
            i = int.__new__(cls, value, 2)
        else:
            i = int.__new__(cls, value)

        i.width = width
        return i
            
    # TODO this is slow.
    def to_bits(self):
        return bitarray(bin(self)[2:self.width+2].zfill(self.width))

    def __add__(self, v):
        return FixedInt(int.__add__(self, v), self.width)

    def __sub__(self, v):
        return FixedInt(int.__sub__(self, v), self.width)

    def __mul__(self, v):
        return FixedInt(int.__mul__(self, v), self.width)

    def __div__(self, v):
        return FixedInt(int.__div__(self, v), self.width)

    def __mod__(self, v):
        return FixedInt(int.__mod__(self, v), self.width)
        
    def __and__(self, v):
        return FixedInt(int.__and__(self, v), self.width)

    def __or__(self, v):
        return FixedInt(int.__or__(self, v), self.width)

    def __xor__(self, v):
        return FixedInt(int.__xor__(self, v), self.width)
        
    def __pow__(self, v):
        return FixedInt(int.__pow__(self, v), self.width)

    def __rshift__(self, v):
        return FixedInt(int.__lshift__(self, v), self.width)

    def __lshift__(self, v):
        return FixedInt(int.__rshift__(self, v), self.width)
        
    def __abs__(self):
        return FixedInt(int.__abs__(self), self.width)

    def __invert__(self):
        return FixedInt(int.__invert__(self), self.width)

    def __pos__(self):
        return FixedInt(int.__pos__(self), self.width)

    def __neg__(self):
        return FixedInt(int.__or__(self), self.width)

    
        
class Switch(int):
    def __repr__(self):
        return "<switch %s>" % self
    
    def to_bits(self):
        return bitarray(struct.pack("!L", self))
        

class Location(Record):
    _fields = "at port"

    # At is "in" or "out"
    # Port is an int

    def __repr__(self):
        return "<loc %s %s>" % (self.at, self.port)

    # XXX double check
    def to_bits(self):
        b = bitarray()
        b.insert(0, self.at == "out")
        b.frombytes(struct.pack("!B", self.port))
        return b
        

class MAC(str):
    def to_bits(self):
        return bitarray(self)


# XXX what should this fundamentally be?
class IP(str):
    def __repr__(self):
        pass

    def to_bits(self):
        pass
    


class bitarray_mac(bitarray):
    def __str__(self):
        return nox_packet_utils.array_to_octstr(self.tobytes())
    
class bitarray_ip(bitarray):
    """Expects input to be 32 bits"""
    def __str__(self):
        return nox_packet_utils.ip_to_str(struct.unpack("!L", self.tobytes())[0])


################################################################################
# NOX Operations
################################################################################

class Backend(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def add_microflow(self, header, action, timeout=None):
        pass

    @abstractmethod
    def remove_microflow(self, header):
        pass

    @abstractmethod
    def query_microflow(self, header):
        pass

    @abstractmethod
    def perform_action(self, action):
        pass

    @abstractmethod
    def nuke_switches(self, switches):
        pass
        
    

