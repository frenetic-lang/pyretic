
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

from frenetic.lib import *
from examples.learning_switch import learning_switch

@policy_decorator
def monitor_packets(self):
    @self.query(all_packets)
    def f(pkt):
        print "I see packet:"
        print pkt
        print "---------------"

@policy_decorator
def monitor_packets_less_decorated(self):
    def f(pkt):
        print "(less decorated) I see packet:"
        print pkt
        print "---------------"
    self.query(all_packets)(f)


def monitor_packets_undecorated():
    def monitor_packets_undecorated_fn(self):
        def f(pkt):
            print "(undecorated) I see packet:"
            print pkt
            print "---------------"
        self.query(all_packets)(f)
    return policy_decorator(monitor_packets_undecorated_fn)

@policy_decorator
def monitor_packets_explicit_bucket(self):
    b = bucket()
    self.policy |= b
    @b.when
    def f(pkt):
        print "(explicit) I see packet:"
        print pkt
        print "---------------"

@policy_decorator
def monitor_packets_limit_by_src_dst(self,**kwargs):
    try:    limit = self.kwargs['limit']
    except: limit = None
    @self.query_limit(all_packets,limit,['srcip','dstip'])
    def f(pkt):
        if limit:  print "(limit %d) I see packet:" % limit
        else:      print "(no limit) I see packet:" 
        print pkt
        print "---------------"
    
@policy_decorator
def monitor_unique_packets(self):
    @self.query_unique(all_packets,['payload'])
    def f(pkt):
        print "I see unique packet:"
        print pkt
        print "---------------"

@policy_decorator
def monitor_packet_count(self):
    @self.query_count(all_packets,3)
    def f(count):
        print "%s packets seen" % count
        
@policy_decorator
def monitor_grouped_packet_count(self):
    group_by = ['srcmac','dstmac','switch','srcip','vlan_tos']
    @self.query_count(all_packets,4,group_by)
    def f(count):
        print "count grouped by %s" % group_by
        for (k,v) in count.items():
            print "%d:  %s" % (v,k)

@policy_decorator
def monitor_topology(self):
    @self.network._topology.notify
    def f(topo):
        print "------ monitor topology output start -------"
        print topo
        print "------ monitor topology output end - -------"

all_monitor_modules =                           \
    monitor_packets()                           \
    | monitor_packets_explicit_bucket()         \
    | monitor_packets_less_decorated()          \
    | monitor_packets_undecorated()()           \
    | monitor_packets_limit_by_src_dst(limit=3) \
    | monitor_unique_packets()                  \
    | monitor_topology()                        \
    | monitor_grouped_packet_count()            \
    | learning_switch()

summary_modules =                     \
    monitor_topology()                \
    | monitor_grouped_packet_count()  \
    | learning_switch()

main = summary_modules

