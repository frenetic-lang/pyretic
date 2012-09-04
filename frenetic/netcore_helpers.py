
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

from bitarray import bitarray as _bitarray
from frenetic import netcore, net

# Wildcards
#

class IPWildcard(netcore.Wildcard):
    width = 32
    
    def __new__(cls, ipexpr, mask=None):
        import struct
        
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
            prefix = _bitarray()
            mask = _bitarray(32)
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
            
            return netcore.Wildcard.__new__(cls, prefix, mask)

        elif isinstance(mask, int):
            prefix = net.IP(ipexpr).to_bits()
            bmask = _bitarray(32)
            bmask.setall(True)
            bmask[0:mask] = False
            
            return netcore.Wildcard.__new__(cls, prefix, bmask)
        else:
            prefix = net.IP(ipexpr).to_bits()
            mask = net.IP(mask).to_bits()
            
            mask.invert()

            return netcore.Wildcard.__new__(cls, prefix, mask)

# Header info
#

_common_header_info = dict(
  switch=(net.Switch, netcore.MatchExact(net.Switch)),
  inport=(net.FixedInt(16), netcore.MatchExact(net.FixedInt(16))),
  outport=(net.FixedInt(16), netcore.MatchExact(net.FixedInt(16))),
  srcmac=(net.MAC, netcore.MatchExact(net.MAC)),
  dstmac=(net.MAC, netcore.MatchExact(net.MAC)),
  vlan=(net.FixedInt(12), netcore.MatchExact(net.FixedInt(12))),
  vlan_pcp=(net.FixedInt(3), netcore.MatchExact(net.FixedInt(3))),
  srcip=(net.IP, IPWildcard),
  dstip=(net.IP, IPWildcard),
  srcport=(net.FixedInt(16), netcore.MatchExact(net.FixedInt(16))),
  dstport=(net.FixedInt(16), netcore.MatchExact(net.FixedInt(16))),)


# Predicate helpers
#

all_packets = netcore.PredTop
no_packets = netcore.PredBottom
let = netcore.PolLet
    
def match(key, value):
    """A matching helper."""
    info = _common_header_info.get(key)

    if value is None or info is None or isinstance(value, netcore.Wildcard):
        return netcore.PredMatch(key, value)
    else:
        cls = info[1]
        if netcore.is_wildcard_str(value, cls.width):
            return netcore.PredMatch(key, netcore.str_to_wildcard(value))
        else:
            if not isinstance(value, tuple):
                value = (value,)
            return netcore.PredMatch(key, cls(*value))

def match_missing(key):
    return match(key, None)
        
def switch_p(k): return match("switch", k)
def inport_p(k): return match("inport", k)
def outport_p(k): return match("outport", k)
def srcmac_p(k): return match("srcmac", k)
def dstmac_p(k): return match("dstmac", k)
def vlan_p(k): return match("vlan", k)
def vlan_pcp_p(k): return match("vlan_pcp", k)
def srcip_p(k): return match("srcip", k)
def dstip_p(k): return match("dstip", k)
def srcport_p(k): return match("srcport", k)
def dstport_p(k): return match("dstport", k)

# Action helpers
#

drop = netcore.ActDrop()

class mod(netcore.ActMod):
    def __new__(cls, arg=None, **keys):
        raw_mapping = {}
        if arg is not None:
            raw_mapping.update(arg)
        raw_mapping.update(keys)

        mapping = {}
        for k, v in raw_mapping.iteritems():
            info = _common_header_info.get(k)
            if v is None or info is None and isinstance(v, netcore.Wildcard):
                mapping[k] = v
            else:
                mapping_cls = info[0]
                if not isinstance(v, tuple):
                    v = (v,)
                mapping[k] = mapping_cls(*v)
            
        return netcore.ActMod.__new__(cls, mapping)

        
class fwd(mod):
    def __new__(cls, port, arg=None, **keys):
        keys["outport"] = port
        return mod.__new__(cls, arg, **keys) 

        
class flood(mod):
    def __new__(cls, port, arg=None, **keys):
        keys["outport"] = 65535 # flood
        return mod.__new__(cls, arg, **keys) 

        
