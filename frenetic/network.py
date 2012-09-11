
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


from abc import ABCMeta, abstractmethod, abstractproperty
from bitarray import bitarray
import struct
from numbers import Integral

from frenetic import util, generators as gs
from frenetic.util import frozendict, Data

import pox.lib.addresses as packetaddr
import pox.openflow.libopenflow_01 as of
from pox.lib import packet as packetlib
import socket

################################################################################
# Fixed width stuff
################################################################################

class FixedWidth(object):
    __metaclass__ = ABCMeta

    width = abstractproperty()

    @abstractmethod
    def to_bits(self):
        """Convert this to a bitarray."""

    @abstractmethod
    def __eq__(self, other):
        pass

    @abstractmethod
    def __ne__(self, other):
        pass

        
@util.cached
def Bits(width_):
    class Bits_(object):
        width = width_

        @classmethod
        def is_bitstring(cls, value):
            return isinstance(value, basestring) and len(value) == cls.width and set(value) <= set("10")

        def __init__(self, bits):
            if self.is_bitstring(bits):
                bits = bitarray(bits)
            elif isinstance(bits, FixedWidth):
                bits = bits.to_bits()

            if not isinstance(bits, bitarray):
                raise ValueError
                
            self._bits = bits
            
            super(Bits_, self).__init__()

        def to_bits(self):
            return self._bits

        def __hash__(self):
            return hash(self.to_bits().tobytes())

        def __eq__(self, other):
            return self.to_bits() == other.to_bits()

        def __ne__(self, other):
            return self.to_bits() != other.to_bits()
            
    FixedWidth.register(Bits_)
    Bits_.__name__ += repr(width_)
    return Bits_


@util.cached
def FixedInt(width_):
    class FixedInt_(int):
        width = width_
        
        def __new__(cls, value):
            if Bits(cls.width).is_bitstring(value):
                return super(FixedInt_, cls).__new__(cls, value, 2)
            else:
                assert isinstance(value, Integral)
                return super(FixedInt_, cls).__new__(cls, value)
            
        # TODO this is slow.
        def to_bits(self):
            return bitarray(bin(self)[2:self.width+2].zfill(self.width))

        def __add__(self, v):
            assert self.width == v.width
            return self.__class__(int.__add__(self, v))

        def __sub__(self, v):
            assert self.width == v.width
            return self.__class__(int.__sub__(self, v))

        def __mul__(self, v):
            assert self.width == v.width
            return self.__class__(int.__mul__(self, v))

        def __div__(self, v):
            assert self.width == v.width
            return self.__class__(int.__div__(self, v))

        def __mod__(self, v):
            assert self.width == v.width
            return self.__class__(int.__mod__(self, v))

        def __and__(self, v):
            assert self.width == v.width
            return self.__class__(int.__and__(self, v))

        def __or__(self, v):
            assert self.width == v.width
            return self.__class__(int.__or__(self, v))

        def __xor__(self, v):
            assert self.width == v.width
            return self.__class__(int.__xor__(self, v))

        def __pow__(self, v):
            assert self.width == v.width
            return self.__class__(int.__pow__(self, v))

        def __rshift__(self, v):
            assert self.width == v.width
            return self.__class__(int.__lshift__(self, v))

        def __lshift__(self, v):
            assert self.width == v.width
            return self.__class__(int.__rshift__(self, v))

        def __abs__(self):
            assert self.width == v.width
            return self.__class__(int.__abs__(self))

        def __invert__(self):
            assert self.width == v.width
            return self.__class__(int.__invert__(self))

        def __pos__(self):
            assert self.width == v.width
            return self.__class__(int.__pos__(self))

        def __neg__(self):
            assert self.width == v.width
            return self.__class__(int.__or__(self))

        def __repr__(self):
            return int.__repr__(self) + "#" + str(self.width)

    FixedWidth.register(FixedInt_)
    FixedInt_.__name__ += repr(FixedInt_.width)
    return FixedInt_

    
class Port(Data("port_or_bucket")):
    width = 65 # TODO make this more robust?
    flood_port = 2**(width-1)-1
     
    def __new__(cls, port_or_bucket):
        # NOT allowed to init with a bitarray.
        if isinstance(port_or_bucket, Port):
            return port_or_bucket
        else:
            assert isinstance(port_or_bucket, (Integral, Bucket))
            return super(Port, cls).__new__(cls, port_or_bucket)

    def is_real(self):
        return not isinstance(self.port_or_bucket, Bucket)
        
    def __repr__(self):
        return "<%s port %s>" % ("real" if self.is_real() else "fake", int(self))

    def to_bits(self):
        b = bitarray()
        b.append(not self.is_real())
        b.frombytes(struct.pack("!Q", int(self)))
        return b

    def get_bucket(self):
        """Redundant, but a nice extra check."""
        assert isinstance(self.port_or_bucket, Bucket)
        return self.port_or_bucket

    def __hash__(self):
        return hash(self.port_or_bucket)
    
    def __int__(self):
        if self.is_real():
            return self.port_or_bucket
        else:
            return id(self.port_or_bucket)
FixedWidth.register(Port)


class Switch(Bits(16)):
    def __init__(self, dpid):
        try:
            return super(Switch, self).__init__(dpid)
        except ValueError:
            assert isinstance(dpid, Integral)
            b = bitarray()
            b.frombytes(struct.pack("!H", dpid))
            
            return super(Switch, self).__init__(b)
            
        raise ValueError
        
    def __repr__(self):
        return "<switch %s>" % int(self)

    def __int__(self):
        return struct.unpack("!H", self.to_bits().tobytes())[0]

        
class MAC(Bits(48)):
    def __init__(self, mac):
        try:
            return super(MAC, self).__init__(mac)
        except ValueError:
            assert isinstance(mac, basestring)
            
            b = bitarray()
            if len(mac) == 6:
                b.frombytes(mac)
            else:
                import re
                m = re.match(r"""(?xi)
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})[:-]+
                             ([0-9a-f]{1,2})
                             """, mac)
                if not m:
                    raise ValueError
                else:
                    b.frombytes(struct.pack("!BBBBBB", *(int(s, 16) for s in m.groups())))
            
            return super(MAC, self).__init__(b)
            
        raise ValueError

    def __repr__(self):
        bs = self.to_bits().tobytes()
        parts = struct.unpack("!BBBBBB", bs)
        mac = ":".join(hex(part)[2:].zfill(2) for part in parts)
        return mac

        
class IP(Bits(32)):
    def __init__(self, ip):
        try:
            return super(IP, self).__init__(ip)
        except ValueError as e:
            assert isinstance(ip, basestring)
            
            b = bitarray()

            if len(ip) == 4:
                b.frombytes(ip)
            else:
                b.frombytes(socket.inet_aton(ip))
            
            return super(IP, self).__init__(b)

        raise ValueError
        
    def __repr__(self):
        return socket.inet_ntoa(self.to_bits().tobytes())
    
################################################################################
#
################################################################################

class Packet(Data("header payload")):
    def __new__(self, data):
        h = {}
        p = packetlib.ethernet(data)

        h["srcmac"] = p.src.toRaw()
        h["dstmac"] = p.dst.toRaw()

        p = p.next

        if isinstance(p, packetlib.vlan):
          h["vlan"] = p.id
          h["vlan_pcp"] = p.pcp
          p = p.next

        if isinstance(p, packetlib.ipv4):
          h["srcip"] = p.srcip.toRaw()
          h["dstip"] = p.dstip.toRaw()
          h["protocol"] = p.protocol
          h["tos"] = p.tos
          p = p.next

          if isinstance(p, packetlib.udp) or isinstance(p, packetlib.tcp):
            h["srcport"] = p.srcport
            h["dstport"] = p.dstport
          elif isinstance(p, packetlib.icmp):
            h["srcport"] = p.type
            h["dstport"] = p.code
        elif isinstance(p, packetlib.arp):
          if p.opcode <= 255:
            h["protocol"] = p.opcode
            h["srcip"] = p.protosrc.toRaw()
            h["dstip"] = p.protodst.toRaw()

        return super(Packet, self).__new__(self, h, data)

    def update_header_fields(self, **kwargs):
        return self._replace(header=util.merge_dicts_deleting(self.header, kwargs))

    def _get_fields(self):
        pass

    def _get_type(self):
        p = packetlib.ethernet(self._get_payload())
        return lift_fixedwidth_kv("type", p.type)

    def _has_vlan_header(self):
        return hasattr(self, "vlan") and hasattr(self, "vlan_pcp")
        
    def _get_payload(self):
        packet = p = packetlib.ethernet(self.payload)

        p.src = packetaddr.EthAddr(self.srcmac.to_bits().tobytes())
        p.dst = packetaddr.EthAddr(self.dstmac.to_bits().tobytes())

        if self._has_vlan_header():
            if isinstance(p.next, packetlib.vlan):
                p = p.next
            else:
                # Make a vlan header
                old_eth_type = p.type
                p.type = 0x8100
                p.next = packetlib.vlan(next = p.next)
                p = p.next
                p.eth_type = old_eth_type
            p.id = int(getattr(self, "vlan", 0))
            p.pcp = int(getattr(self, "vlan_pcp", 0))
        else:
            if isinstance(p.next, packetlib.vlan):
                p.type = p.next.eth_type # Restore encapsulated eth type
                p.next = p.next.next # Remove vlan from header

        p = p.next

        if isinstance(p, packetlib.ipv4):
            p.srcip = packetaddr.IPAddr(self.srcip.to_bits().tobytes())
            p.dstip = packetaddr.IPAddr(self.dstip.to_bits().tobytes())
            p.protocol = int(self.protocol)
            p.tos = int(self.tos)
            p = p.next

            if isinstance(p, packetlib.udp) or isinstance(p, packetlib.tcp):
                p.srcport = int(self.srcport)
                p.dstport = int(self.dstport)
            elif isinstance(p, packetlib.icmp):
                p.type = int(self.srcport)
                p.code = int(self.dstport)
        elif isinstance(p, packetlib.arp):
            p.opcode = int(self.protocol)
            p.protosrc = packetaddr.IPAddr(self.srcip.to_bits().tobytes())
            p.protodst = packetaddr.IPAddr(self.dstip.to_bits().tobytes())

        return p.pack()
        
    def __repr__(self):
        l = []
        size = max(map(len, self.header)) + 3
        for k in sorted(self.header):
            l.append("%s:%s%s" % (k, " " * (size - len(k)), getattr(self, k)))
        return "\n".join(l)

    def __getattr__(self, attr):
        return lift_fixedwidth_kv(attr, self.header[attr])

class Bucket(gs.Event):
    """A safe place for packets!"""
    def __init__(self, fields=[], time=None):
        self.fields = fields
        self.time = time
        super(Bucket, self).__init__()

################################################################################
# Lifts
################################################################################

header_to_fixedwidth_lift = dict(
    switch=Switch,
    inport=Port,
    outport=Port,
    vswitch=Switch,
    vinport=Port,
    voutport=Port,
    srcmac=MAC,
    dstmac=MAC,
    vlan=FixedInt(12),
    vlan_pcp=FixedInt(3),
    srcip=IP,
    dstip=IP,
    srcport=FixedInt(16),
    dstport=FixedInt(16),
    protocol=FixedInt(8),
    tos=FixedInt(6),
    type=FixedInt(16),)

def lift_fixedwidth_kv(k, v):
    cls = header_to_fixedwidth_lift.get(k)
    if cls is None:
        assert isinstance(v, FixedWidth)
        return v
    else:
        if not isinstance(v, tuple):
            v = (v,)
        return cls(*v)
