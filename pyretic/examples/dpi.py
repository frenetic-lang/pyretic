
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
# mininet: mininet.sh (or other single subnet network)                         #
# test:    packet contents will be printed for each packet sent                #
#          to generate a packets with a payload try                            #
#          h1 hping3 -c 10 -d 100 -E ~/pyretic/mininet/test_payload.txt -S h2  #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

def printer(pkt):
    print "------packet--------"
    print pkt
    if pkt['ethtype'] == IP_TYPE:
        print "Ethernet packet, try to decode"
        raw_bytes = [ord(c) for c in pkt['raw']]
        print "ethernet payload is %d" % pkt['payload_len']    
        eth_payload_bytes = raw_bytes[pkt['header_len']:]   
        print "ethernet payload is %d bytes" % len(eth_payload_bytes)
        ip_version = (eth_payload_bytes[0] & 0b11110000) >> 4
        ihl = (eth_payload_bytes[0] & 0b00001111)
        ip_header_len = ihl * 4
        ip_payload_bytes = eth_payload_bytes[ip_header_len:]
        ip_proto = eth_payload_bytes[9]
        print "ip_version = %d" % ip_version
        print "ip_header_len = %d" % ip_header_len
        print "ip_proto = %d" % ip_proto
        print "ip payload is %d bytes" % len(ip_payload_bytes)
        if ip_proto == 0x06:
            print "TCP packet, try to decode"
            tcp_data_offset = (ip_payload_bytes[12] & 0b11110000) >> 4
            tcp_header_len = tcp_data_offset * 4
            print "tcp_header_len = %d" % tcp_header_len
            tcp_payload_bytes = ip_payload_bytes[tcp_header_len:]
            print "tcp payload is %d bytes" % len(tcp_payload_bytes)
            if len(tcp_payload_bytes) > 0:
                print "payload:\t",
                print ''.join([chr(d) for d in tcp_payload_bytes])
        elif ip_proto == 0x11:
            print "UDP packet, try to decode"
            udp_header_len = 8
            print "udp_header_len = %d" % udp_header_len
            udp_payload_bytes = ip_payload_bytes[udp_header_len:]
            print "udp payload is %d bytes" % len(udp_payload_bytes)
            if len(udp_payload_bytes) > 0:
                print "payload:\t",
                print ''.join([chr(d) for d in udp_payload_bytes])
        elif ip_proto == 0x01:
            print "ICMP packet"
        else:
            print "Unhandled packet type"

def dpi():
  q = packets()
  q.register_callback(printer)
  return q

### Main ###

def main():
    return (match(srcmac=EthAddr('00:00:00:00:00:01')) >> dpi()) + flood()

