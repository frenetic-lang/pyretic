
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

# This module is designed for import *.

import socket
import struct

from bitarray import bitarray


from frenetic.util import Data, merge_dicts
from frenetic import netcore_lib as nl

################################################################################
# Header types
################################################################################

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
            return self.__class__(int.__add__(self, v))

        def __sub__(self, v):
            return self.__class__(int.__sub__(self, v))

        def __mul__(self, v):
            return self.__class__(int.__mul__(self, v))

        def __div__(self, v):
            return self.__class__(int.__div__(self, v))

        def __mod__(self, v):
            return self.__class__(int.__mod__(self, v))

        def __and__(self, v):
            return self.__class__(int.__and__(self, v))

        def __or__(self, v):
            return self.__class__(int.__or__(self, v))

        def __xor__(self, v):
            return self.__class__(int.__xor__(self, v))

        def __pow__(self, v):
            return self.__class__(int.__pow__(self, v))

        def __rshift__(self, v):
            return self.__class__(int.__lshift__(self, v))

        def __lshift__(self, v):
            return self.__class__(int.__rshift__(self, v))

        def __abs__(self):
            return self.__class__(int.__abs__(self))

        def __invert__(self):
            return self.__class__(int.__invert__(self))

        def __pos__(self):
            return self.__class__(int.__pos__(self))

        def __neg__(self):
            return self.__class__(int.__or__(self))

        def __repr__(self):
            return int.__repr__(self) + "#" + str(self.width)
            
    FixedInt_.__name__ += repr(FixedInt_.width)
    return FixedInt_
        
class Switch(Data("switch_int")):
    width = 8
    
    def __repr__(self):
        return "<switch %s>" % self.switch_int

    def __int__(self):
        return self.switch_int
    
    def to_bits(self):
        b = bitarray()
        b.frombytes(struct.pack("!B", self.switch_int))
        return b

class MAC(Data("macbytes")):
    width = 48

    def to_bits(self):
        b = bitarray()
        b.frombytes(self.macbytes)
        return b

class IP(Data("ipbytes")):
    width = 32
    
    def __new__(cls, ip):
        if len(ip) != 4:
            ip = socket.inet_aton(ip)

        return super(IP, cls).__new__(cls, ip)
        
    def __repr__(self):
        return socket.inet_ntoa(self.ipbytes)
       
    def to_bits(self):
        b = bitarray()
        b.frombytes(self.ipbytes)
        return b

################################################################################
# Wildcards
################################################################################

def str_to_wildcard(s):
    "Make a wildcard from a string."
    prefix = bitarray(s.replace("?", "0"))
    mask = bitarray(s.replace("1", "0").replace("?", "1"))
    return nl.Wildcard(len(prefix))(prefix, mask)

def is_wildcard_str(value, width):
    return isinstance(value, basestring) and len(value) == width and set(value) <= set("?10")

_match_exact_cache = {}
def MatchExact(match_cls):
    try:
        return _match_exact_cache[match_cls]
    except:
        class MatchExact_(nl.Wildcard(match_cls.width)):
            def __new__(cls, *v):
                bits = match_cls(*v).to_bits()
                return super(MatchExact_, cls).__new__(cls, bits, bitarray([False] * cls.width))

        MatchExact_.__name__ += match_cls.__name__
        
        _match_exact_cache[match_cls] = MatchExact_
        return MatchExact_

class IPWildcard(nl.Wildcard(32)):
    def __new__(cls, ipexpr, mask=None):
        parts = ipexpr.split("/")

        if len(parts) == 2:
            ipexpr = parts[0]
            try:
                mask = int(parts[1], 10)
            except ValueError:
                mask = parts[1]
        elif len(parts) != 1:
            raise ValueError

        if mask is None:
            prefix = bitarray()
            mask = bitarray(32)
            (a, b, c, d) = ipexpr.split(".")
            mask.setall(False)
            if a == "*":
                mask[0:8] = True
                prefix.extend("00000000")
            else:
                prefix.frombytes(struct.pack("!B", int(a)))
            if b == "*":
                mask[8:16] = True
                prefix.extend("00000000")
            else:
                prefix.frombytes(struct.pack("!B", int(b)))
            if c == "*":
                mask[16:24] = True
                prefix.extend("00000000")
            else:
                prefix.frombytes(struct.pack("!B", int(c)))
            if d == "*":
                mask[24:32] = True
                prefix.extend("00000000")
            else:
                prefix.frombytes(struct.pack("!B", int(d)))
            
            return super(IPWildcard, cls).__new__(cls, prefix, mask)
        elif isinstance(mask, int):
            prefix = IP(ipexpr).to_bits()
            bmask = bitarray(32)
            bmask.setall(True)
            bmask[0:mask] = False
            return super(IPWildcard, cls).__new__(cls, prefix, bmask)
        else:
            prefix = IP(ipexpr).to_bits()
            mask = IP(mask).to_bits()
            mask.invert() 
            return super(IPWildcard, cls).__new__(cls, prefix, mask)


################################################################################
# Header information
################################################################################

_common_header_info = dict(
    switch=(Switch, MatchExact(Switch)),
    inport=(FixedInt(16), MatchExact(FixedInt(16))),
    outport=(FixedInt(16), MatchExact(FixedInt(16))),
    srcmac=(MAC, MatchExact(MAC)),
    dstmac=(MAC, MatchExact(MAC)),
    vlan=(FixedInt(12), MatchExact(FixedInt(12))),
    vlan_pcp=(FixedInt(3), MatchExact(FixedInt(3))),
    srcip=(IP, IPWildcard),
    dstip=(IP, IPWildcard),
    srcport=(FixedInt(16), MatchExact(FixedInt(16))),
    dstport=(FixedInt(16), MatchExact(FixedInt(16))),
    protocol=(FixedInt(8), MatchExact(FixedInt(8))),
    tos=(FixedInt(6), MatchExact(FixedInt(6))),
    type=(FixedInt(16), MatchExact(FixedInt(16))))

def lift_kv(k, v, i):
    # TODO: assert that we have the right classes
    
    info = _common_header_info.get(k)

    if v is None or isinstance(v, nl.Matchable):
        return (k, v)
    if info is None:
        assert isinstance(v, nl.Matchable)
        return (k, v)
    else:
        cls = info[i]
        if is_wildcard_str(v, cls.width):
            return (k, str_to_wildcard(v))
        else:
            if not isinstance(v, tuple):
                v = (v,)
            return (k, cls(*v))

def lift_dict(d, i):
    r = {}
    for k, v in d.iteritems():
        (k2, v2) = lift_kv(k, v, i)
        r[k2] = v2
    return r
     
################################################################################
# Predicates and policies
################################################################################

all_packets = nl.PredTop
no_packets = nl.PredBottom
let = nl.PolLet
    
def match(k, v):
    """A matching helper."""
    (k, v) = lift_kv(k, v, 1)
    return nl.PredMatch(k, v)

def match_missing(key):
    return match(key, None)
        
def switch_p(k): return match("switch", k)
def inport_p(k): return match("inport", k)
def outport_p(k): return match("outport", k)
def srcmac_p(k): return match("srcmac", k)
def dstmac_p(k): return match("dstmac", k)
def protocol_p(k): return match("protocol", k)
def type_p(k): return match("type", k)
def tos_p(k): return match("tos", k)
def vlan_p(k): return match("vlan", k)
def vlan_pcp_p(k): return match("vlan_pcp", k)
def srcip_p(k): return match("srcip", k)
def dstip_p(k): return match("dstip", k)
def srcport_p(k): return match("srcport", k)
def dstport_p(k): return match("dstport", k)

drop = nl.DropPolicy()

class mod(nl.ModPolicy):
    def __new__(cls, arg={}, **keys):
        raw_mapping = merge_dicts(arg, keys)
        mapping = lift_dict(raw_mapping, 0)
        return super(mod, cls).__new__(cls, mapping)

    def __call__(self, arg={}, **keys):
        raw_mapping = merge_dicts(arg, keys)
        mapping = lift_dict(raw_mapping, 0)
        return self.__class__(self.mapping.update(mapping))

def fwd(port, arg={}, **keys):
    keys["outport"] = port
    return mod(arg, **keys) 

flood = fwd(65535)
        
################################################################################
# Monitoring helpers
################################################################################

def bucket(fields=(), time=None):
    return nl.Bucket(fields, time)

def query(network, pred, fields=(), time=None):
    b = nl.Bucket(fields, time)
    b.ph = network.new_policy_handle()
    b.ph.install(pred >> fwd(b))
    return b
