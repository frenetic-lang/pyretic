#!/usr/bin/python

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

import re
import sys

### Run on output file of tcpdump to get counts, e.g.,
# $ sudo tcpdump -i any -U -e not ip6 -P in > packet_dump
# $ tcpdump_parser.py packet_dump

ON_ANY=True

if __name__ == '__main__':

    file_name = sys.argv[1]

    packet_count = 0
    l2_byte_count = 0
    l3_byte_count = 0

    mac_p = re.compile('00:00:00:00:00:((0[1-9])|([1-9][0-9]))')
    # http://stackoverflow.com/questions/7579668/understanding-tcpdump-trace-with-ethernet-headers
    #    rcv_code_p = re.compile('P$')
    localhost_p = re.compile('localhost*')
    layer_p = re.compile('length ([0-9]+):')
    len_p = re.compile('length ([0-9]+)')

    f = open(file_name,'r')
    for line in f.xreadlines():
        layers = layer_p.split(line)
        if len(layers) < 3:
            continue
        l2,l2_len,l3 = layers[0:3]
        tokens = l2.split()
        rcv_code='Out'
        if ON_ANY:
            (time, rcv_code, ethaddr),oui,l2_rest = tokens[:3],tokens[3]+' '+tokens[4],tokens[5:]
        else:
            (time, ethaddr),oui,l2_rest = tokens[:2],tokens[2]+' '+tokens[3],tokens[4:]
        if time == 'version':
            continue
        if oui == '(oui Unknown)':
            continue
        tokens = l3.split()
        if localhost_p.match(tokens[0]):
            continue

        l3 = ' '.join(tokens[0:-2])
        l3_len = tokens[-1]
        
        packet_count += 1
        if ON_ANY:  # packets captured on pseudo-interface (linux cooked capture) have an extra 2 bytes of header
            l2_byte_count += (int(l2_len)-2)
        else:
            l2_byte_count += int(l2_len)
        l3_byte_count += int(l3_len)

    print '(packet, byte) counts: [%d, %d]' % (packet_count,l2_byte_count)
