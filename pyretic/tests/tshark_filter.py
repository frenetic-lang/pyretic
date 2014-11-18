################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
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

import re

def __get_frame_len(line):
    return line.split(',')[0]

def __get_ip_srcip(line):
    return line.split(',')[1]

def __get_ip_dstip(line):
    return line.split(',')[2]

def __get_arp_srcip(line):
    return line.split(',')[3]

def __get_arp_dstip(line):
    return line.split(',')[4]

def get_bytes(l):
    return int(__get_frame_len(l))

def get_bytes_cooked_capture(l):
    return int(__get_frame_len(l))-2

def ip_pkt_srcip(target_ip):
    return lambda l: __get_ip_srcip(l) == target_ip

def ip_pkt_dstip(target_ip):
    return lambda l: __get_ip_dstip(l) == target_ip

def arp_pkt_srcip(target_ip):
    return lambda l: __get_arp_srcip(l) == target_ip

def arp_pkt_dstip(target_ip):
    return lambda l: __get_arp_dstip(l) == target_ip

def pkt_srcip(target_ip):
    return lambda l: ((__get_ip_srcip(l) == target_ip) or
                      (__get_arp_srcip(l) == target_ip))

def pkt_dstip(target_ip):
    return lambda l: ((__get_ip_dstip(l) == target_ip) or
                      (__get_arp_dstip(l) == target_ip))
