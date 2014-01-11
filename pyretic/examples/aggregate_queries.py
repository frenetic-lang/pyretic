
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
# mininet: mininet.sh --topo=clique,5,5 (or other single subnet network)       #
# test:    updated network traffic statistics should be printed every second   #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner
from datetime import datetime

def packet_count_printer(counts):
    print "----counts------"
    print counts

def packet_counts():
  q = count_packets(1,['srcip','dstip'])
  q.register_callback(packet_count_printer)
  return q

def byte_count_printer(n):
    print "----bytes------"
    print n

def byte_counts():
  q = count_bytes(1,['srcip','dstip'])
  q.register_callback(byte_count_printer)
  return q

def proactive_counts():
    q = counts(2.5,['srcip','dstip'])
    q.register_callback(proactive_counts_printer)
    return q

def proactive_counts_printer(counts):
    print "----proactive counts----"
    print datetime.now().time().isoformat()
    if counts:
        for pred, pkt_byte_count in counts.iteritems():
            print pred, ':', pkt_byte_count
    else:
        print '{}'

### Main ###

def main():
#    return (packet_counts() +
#            byte_counts() +
#            mac_learner())
    return (proactive_counts() + mac_learner())
