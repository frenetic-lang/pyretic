
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
        b.frombytes(struct.pack("!q", int(self)))
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
            super(Switch, self).__init__(dpid)
        except:
            assert isinstance(dpid, Integral)
            b = bitarray()
            b.frombytes(struct.pack("!H", dpid))
            
            super(Switch, self).__init__(b)
        
    def __repr__(self):
        return "<switch %s>" % int(self)

    def __int__(self):
        return struct.unpack("!H", self.to_bits().tobytes())[0]

        
class MAC(Bits(48)):
    def __init__(self, mac):
        try:
            super(MAC, self).__init__(mac)
        except:
            if isinstance(mac, basestring):
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
            
            super(MAC, self).__init__(b)

    def __repr__(self):
        bs = self.to_bits().tobytes()
        parts = struct.unpack("!BBBBBB", bs)
        mac = ":".join(hex(part)[2:].zfill(2) for part in parts)
        return mac

        
class IP(Bits(32)):
    def __init__(self, ip):
        try:
            super(IP, self).__init__(ip)
        except:
            assert isinstance(ip, basestring)
            
            b = bitarray()

            if len(ip) == 4:
                b.frombytes(ip)
            else:
                b.frombytes(socket.inet_aton(ip))
            
            super(IP, self).__init__(b)
        
    def __repr__(self):
        return socket.inet_ntoa(self.to_bits().tobytes())
    
################################################################################
#
################################################################################

class Header(frozendict):
    def __init__(self, arg={}, **kwargs):
        if isinstance(arg, basestring):
            packet = packetlib.ethernet(arg)
            match = of.ofp_match.from_packet(packet)
            arg = _pox_match_to_header(match)
            
        d = lift_fixedwidth_dict(util.merge_dicts_deleting(arg, kwargs))
            
        return super(Header, self).__init__(d)

class Packet(Data("header payload")):
    def __new__(cls, payload, **kwargs):
        return super(Packet, cls).__new__(cls, Header(payload, **kwargs), payload)

    def update_header_fields(self, **kwargs):
        header = Header(util.merge_dicts_deleting(self.header, kwargs))
        payload = _propagate_header_to_payload(header, self.payload)
        return self.replace(header=header, payload=payload)

    def __getattr__(self, attr):
        return self.header[attr]

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

def lift_fixedwidth_dict(d):
    r = {}
    # Factor this logic out?

    if d.get("type") == 0x8100 or "vlan" in d or "vlan_pcp" in d:
        d["type"] = 0x8100
        d.setdefault("vlan", 0)
        d.setdefault("vlan_pcp", 0)
        
    for k, v in d.iteritems():
        v2 = lift_fixedwidth_kv(k, v)
        r[k] = v2
    return r

################################################################################
# Internal
################################################################################

def _header_to_pox_match(h):
    match = of.ofp_match()

    if "inport" in h:
        match.in_port = int(h["inport"])

    if "srcmac" in h:
        match.dl_src = packetaddr.EthAddr(h["srcmac"].to_bits().tobytes())
    
    if "dstmac" in h:
        match.dl_dst = packetaddr.EthAddr(h["dstmac"].to_bits().tobytes())

    if "type" in h:
        match.dl_type = int(h["type"])
        if match.dl_type == 0x8100:
            match.dl_vlan = int(h["vlan"])
            match.dl_vlan_pcp = int(h["vlan_pcp"])

    if "srcip" in h:
        match.nw_src = packetaddr.IPAddr(h["srcip"].to_bits().tobytes())
    
    if "dstip" in h:
        match.nw_dst = packetaddr.IPAddr(h["dstip"].to_bits().tobytes())
    
    if "protocol" in h:
        match.nw_proto = int(h["protocol"])

    if "tos" in h:
        match.nw_tos = int(h["tos"])

    if "srcport" in h:
        match.tp_src = int(h["srcport"])

    if "dstport" in h:
        match.tp_dst = int(h["dstport"])
    
    return match

def _pox_match_to_header(match):
    h = {}
    
    if match.in_port is not None:
        h["inport"] = match.in_port

    if match.dl_src is not None:
        h["srcmac"] = match.dl_src.toRaw()

    if match.dl_dst is not None:
        h["dstmac"] = match.dl_dst.toRaw()

    if match.dl_type is not None:
        h["type"] = match.dl_type

    if match.dl_type == 0x8100:
        h["vlan"] = match.dl_vlan
        h["vlan_pcp"] = match.dl_vlan_pcp

    if match.nw_src is not None:
        h["srcip"] = match.nw_src.toRaw()

    if match.nw_dst is not None:
        h["dstip"] = match.nw_dst.toRaw()

    if match.nw_proto is not None:
        h["protocol"] = match.nw_proto

    if match.nw_tos is not None:
        h["tos"] = match.nw_tos

    if match.tp_src is not None:
        h["srcport"] = match.tp_src

    if match.tp_dst is not None:
        h["dstport"] = match.tp_dst
        
    return h

def _propagate_header_to_payload(h, data):
    packet = p = packetlib.ethernet(data)
    match = _header_to_pox_match(h)

    p.src = match.dl_src
    p.dst = match.dl_dst

    # Set the VLAN
    if match.dl_type == 0x8100:
        if isinstance(p.next, packetlib.vlan):
            p = p.next
        else:
            old_eth_type = p.type
            p.type = 0x8100
            p.next = packetlib.vlan(next = p.next)
            p = p.next
            p.eth_type = old_eth_type
        p.id = match.dl_vlan
        p.pcp = match.dl_vlan_pcp
    else:
        pass # XXX is this right?
        
    p = p.next
  
    if isinstance(p, packetlib.ipv4):
        p.srcip = match.nw_src
        p.dstip = match.nw_dst
        p.protocol = match.nw_proto
        p.tos = match.nw_tos
        p = p.next

        if isinstance(p, packetlib.udp) or isinstance(p, packetlib.tcp):
            p.srcport = match.tp_src
            p.dstport = match.tp_dst
        elif isinstance(p, packetlib.icmp):
            p.type = match.tp_src
            p.code = match.tp_dst
    elif isinstance(p, packetlib.arp):
        p.opcode = match.nw_proto
        if p.opcode <= 255:
            p.protosrc = match.nw_src
            p.protodst = match.nw_dst

    return packet.pack()
