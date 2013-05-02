
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
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

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.examples.mac_learner import mac_learner


### 50 ways to write your packet monitor ###

def printer(pkt):
  print pkt

def dpi():
  q = packets(None,[])
  q.register_callback(printer)
  return q


@dynamic
def monitor_packets(self):
    @self.query(all_packets)
    def f(pkt):
        print "I see packet:"
        print pkt
        print "---------------"

@dynamic
def monitor_packets_less_decorated(self):
    def f(pkt):
        print "(less_decorated) I see packet:"
        print pkt
        print "---------------"
    self.query(all_packets)(f)


def monitor_packets_undecorated():
    def monitor_packets_undecorated_fn(self):
        def f(pkt):
            print "(undecorated_fn) I see packet:"
            print pkt
            print "---------------"
        self.query(all_packets)(f)
    return dynamic(monitor_packets_undecorated_fn)

@dynamic
def monitor_packets_explicit(self):
    b = packets()
    self.policy |= b
    @b.register_callback
    def f(pkt):
        print "(explicit_packets) I see packet:"
        print pkt
        print "---------------"

def monitor_packets_lowest_level_syntax():
    b = packets()
    def f(pkt):
        print "(lowest_level_syntax) I see packet:"
        print pkt  
        print "---------------" 
    b.register_callback(f)
    return b


### packet monitoring w/ other packets types ###

class monitor_packets_limit_by_src_dst(MutablePolicy):
    def __init__(self, limit=None):
        self.limit = limit

    def set_network(self, network):
        @self.query_limit(all_packets,limit,['srcip','dstip'])
        def f(pkt):
            if self.limit:
                print "(limit %d) I see packet:" % limit
            else:
                print "(no limit) I see packet:" 
        print pkt
        print "---------------"
        MutablePolicy.set_network(self, network)
    
@dynamic
def monitor_unique_packets(self):
    @self.query_unique(all_packets,['payload'])
    def f(pkt):
        print "I see unique packet:"
        print pkt
        print "---------------"

@dynamic
def monitor_packet_count(self):
    @self.query_count(all_packets,3)
    def f(count):
        print "%s packets seen" % count
        
@dynamic
def monitor_grouped_packet_count(self):
    group_by = ['srcmac','dstmac','switch','srcip','vlan_tos']
    @self.query_count(all_packets,4,group_by)
    def f(count):
        print "count grouped by %s" % group_by
        for (k,v) in count.items():
            print "%d:  %s" % (v,k)


### Examples ###

def all_monitor_modules():
    return monitor_packets()                           \
        | monitor_packets_explicit()         \
        | monitor_packets_less_decorated()          \
        | monitor_packets_undecorated()()           \
        | monitor_packets_lowest_level_syntax()     \
        | monitor_packets_limit_by_src_dst(limit=3) \
        | monitor_unique_packets()                  \
        | monitor_grouped_packet_count()            \
        | mac_learner()

def summary_modules():
    return monitor_grouped_packet_count()  \
        | mac_learner()

def lowest_level_syntax():                      
    return monitor_packets_lowest_level_syntax()  \
        | flood()


### Main ###

def main():
    return summary_modules()

