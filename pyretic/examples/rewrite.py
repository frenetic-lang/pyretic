
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
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


################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet:  mininet.sh --topo single,3                                         #
# test:     pingall and check for following connectivity pattern               #
#           h1 -> h2 h3                                                        # 
#           h2 -> X h3                                                         #
#           h3 -> X h2                                                         #
#           all hosts should also be able to ping 10.0.0.11                    #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

mac1 = EthAddr('00:00:00:00:00:01')
mac2 = EthAddr('00:00:00:00:00:02')
mac3 = EthAddr('00:00:00:00:00:03')
macB = EthAddr('FF:FF:FF:FF:FF:FF')
ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')
p = IPAddr('10.0.0.11')

modify = (if_(match(srcip=ip1),modify(srcip=p)) >> 
          if_(match(dstip=p),modify(dstip=ip1))    )
              
l2route = (((match(dstmac=mac1) | match(dstmac=macB)) >> fwd(1)) +
           ((match(dstmac=mac2) | match(dstmac=macB)) >> fwd(2)) +
           ((match(dstmac=mac3) | match(dstmac=macB)) >> fwd(3)) )

l3route = ((match(dstip=ip1) >> fwd(1)) +
           (match(dstip=ip2) >> fwd(2)) +
           (match(dstip=ip3) >> fwd(3)) )

policy = modify >> l2route

def main():
    return policy




