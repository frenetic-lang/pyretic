
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
from examples.hub import hub

def monitor_packets(network):
    for pkt in query(network, all_packets):
        print "I see packet:"
        print pkt
        print "---------------"

def monitor_packet_count(network):
    for count in query_count(network, all_packets,2.5):
        print "I've seen %d packets!" % count
        
def monitor_grouped_packet_count(network):
    group_by = ['srcmac','dstmac','switch','srcip']
    for count in query_count(network, all_packets,4,group_by):
        print "count grouped by %s" % group_by
        for (k,v) in count.items():
            print "%d:  %s" % (v,k)

def example(network):
    run(network.install_policy(hub(network)), Network.fork(network))
    run(monitor_packets, Network.fork(network))
    run(monitor_packet_count, Network.fork(network))
    run(monitor_grouped_packet_count, Network.fork(network))

main = example
