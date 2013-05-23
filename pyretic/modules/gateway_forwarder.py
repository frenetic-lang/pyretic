
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
# see any of gateway examples                                                  #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.modules.arp import arp, translate, ARP


def gateway_addr(subnet):
    return IP('.'.join(subnet.split('/')[0].split('.')[:-1]) + '.1')

def gateway_forwarder(subnet1,subnet2,host_macs):
    gw_mac = MAC('AA:AA:AA:AA:AA:AA')
    gw_mapping = {gateway_addr(subnet1) : gw_mac, 
                  gateway_addr(subnet2) : gw_mac}
    print gw_mapping
    subnet1_to_subnet2 = match(inport=1) & match(dstip=subnet2)
    subnet2_to_subnet1 = match(inport=2) & match(dstip=subnet1)
    subnet_forwarder = subnet1_to_subnet2[fwd(2)] + subnet2_to_subnet1[fwd(1)]
    return if_(ARP,
               arp(gw_mapping),
               translate(host_macs) >> subnet_forwarder)
