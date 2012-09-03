
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

from frenetic import netcore, net


all_packets = netcore.PredTop
no_packets = netcore.PredBottom
let = PolLet

# TODO more friendly.
match = PredMatch

def switch_p(k): return match("switch", k)
def inport_p(k): return match("location", "0" + k)
def outport_p(k): return match("location", "1" + k)
def srcmac_p(k): return match("srcmac", k)
def dstmac_p(k): return match("vlan", k)
def dltype_p(k): return match("dltype", k)
def vlan_p(k): return match("vlan", k)
def vlan_pcp_p(k): return match("vlan_pcp", k)
def srcip_p(k): return match("srcip", k)
def dstip_p(k): return match("dstip", k)
def protocol_p(k): return match("protocol", k)
def srcport_p(k): return match("srcport", k)
def dsrport_p(k): return match("dsrport", k)

class fwd(ActMod):
    def __new__(cls, port):
        return ActMod.__new__(cls, {"location": net.Location("out", port)})
