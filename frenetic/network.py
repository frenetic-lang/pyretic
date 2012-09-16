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
import socket
import struct
from abc import ABCMeta, abstractmethod, abstractproperty
from numbers import Integral
from itertools import chain

from bitarray import bitarray

from frenetic import util, generators as gs
from frenetic.util import Data


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
    class FixedInt_(long):
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
            return self.__class__(long.__add__(self, v))

        def __sub__(self, v):
            assert self.width == v.width
            return self.__class__(long.__sub__(self, v))

        def __mul__(self, v):
            assert self.width == v.width
            return self.__class__(long.__mul__(self, v))

        def __div__(self, v):
            assert self.width == v.width
            return self.__class__(long.__div__(self, v))

        def __mod__(self, v):
            assert self.width == v.width
            return self.__class__(long.__mod__(self, v))

        def __and__(self, v):
            assert self.width == v.width
            return self.__class__(long.__and__(self, v))

        def __or__(self, v):
            assert self.width == v.width
            return self.__class__(long.__or__(self, v))

        def __xor__(self, v):
            assert self.width == v.width
            return self.__class__(long.__xor__(self, v))

        def __pow__(self, v):
            assert self.width == v.width
            return self.__class__(long.__pow__(self, v))

        def __rshift__(self, v):
            assert self.width == v.width
            return self.__class__(long.__lshift__(self, v))

        def __lshift__(self, v):
            assert self.width == v.width
            return self.__class__(long.__rshift__(self, v))

        def __abs__(self):
            assert self.width == v.width
            return self.__class__(long.__abs__(self))

        def __invert__(self):
            assert self.width == v.width
            return self.__class__(long.__invert__(self))

        def __pos__(self):
            assert self.width == v.width
            return self.__class__(long.__pos__(self))

        def __neg__(self):
            assert self.width == v.width
            return self.__class__(long.__or__(self))

        def __repr__(self):
            return long.__repr__(self) + "#" + str(self.width)

    FixedWidth.register(FixedInt_)
    FixedInt_.__name__ += repr(FixedInt_.width)
    return FixedInt_

    
class Port(Data("port_or_bucket")):
    width = 65 # TODO make this more robust?
    
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
# Packet and tools
################################################################################

class Packet(Data("header")):
    def _get_field(self, field):
        return self.header.get(field, ())
        
    def _push(self, d_={}, **kwargs):
        d = util.merge_dicts(d_, kwargs)
        h = dict(self.header)
        for k, v in d.iteritems():
            assert not hasattr(self.__class__, k), "field not settable"
            if v is not None:
                v = lift_fixedwidth(k, v)
            h[k] = (v,) + self._get_field(k)
        return self._replace(header=util.frozendict(h))
        
    def _pop(self, arg=[], *args):
        if isinstance(arg, basestring):
           arg = (arg,)
        args = chain(arg, args)
        h = dict(self.header)
        for field in args:
            v = self._get_field(field)
            assert len(v) > 0, "can't pop only value"
            h[field] = v[1:]
        return self._replace(header=util.frozendict(h))
        
    def _modify(self, d_={}, **kwargs):
        d = util.merge_dicts(d_, kwargs)
        return self._pop(d).push(d)

    def __getattr__(self, attr):
        v = self._get_field(attr)
        if not v or v[0] is None:
            raise AttributeError
        return v[0]

    def __repr__(self):
        l = []
        size = max(map(len, self.header)) + 3
        for k, v in sorted(self.header.iteritems()):
            if v:
                l.append("%s:%s%s" % (k, " " * (size - len(k)), v))
        return "\n".join(l)

        
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
    vtag=FixedInt(64),
    isotag=FixedInt(64),
    srcmac=MAC,
    dstmac=MAC,
    srcip=IP,
    dstip=IP,
    srcport=FixedInt(16),
    dstport=FixedInt(16),
    protocol=FixedInt(8),
    tos=FixedInt(6),
    type=FixedInt(16),)

def lift_fixedwidth(k, v):
    cls = header_to_fixedwidth_lift.get(k)
    if cls is None:
        assert isinstance(v, FixedWidth)
        return v
    else:
        if not isinstance(v, tuple):
            v = (v,)
        return cls(*v)
