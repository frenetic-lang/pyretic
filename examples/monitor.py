
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

def monitor_packets(network):
    for pkt in query(network, all_packets):
        print "I see packet:"
        print pkt
        print "---------------"

def monitor_packets_explicit_bucket(network):
    b = Bucket()
    monitoring_network = Network.fork(network)  # WE MUST EXPLICITY FORK NETWORK
    monitoring_network.install_policy(fwd(b))   # OR THIS LINE WOULD OVERWRITE OTHER COMPONENTS!
    for pkt in b:
        print "(explicit) I see packet: ", pkt

def monitor_packet_count(network):
    for count in query_count(network, all_packets,2.5):
        print "I've seen %d packets!" % count
        
def monitor_grouped_packet_count(network):
    group_by = ['srcmac','dstmac','switch','srcip','vlan_tos']
    for count in query_count(network, all_packets,4,group_by):
        print "count grouped by %s" % group_by
        for (k,v) in count.items():
            print "%d:  %s" % (v,k)

def monitor_policy(network):
    """Must use same network object on which policy to be monitored runs"""
    for policy in network.policy_changes:
        print "-------- POLICY CHANGE --------"
        print policy

def monitor_topology(network):
    for topo in network.topology_changes:
        print "------ monitor topology output start -------"
        print topo
        print "------ monitor topology output end - -------"

def example(network):
    run(learning_switch, network)
    run(monitor_policy, network)                       
    run(monitor_packets, network)
    run(monitor_packets_explicit_bucket, network)  
    run(monitor_packet_count, network)
    run(monitor_grouped_packet_count, network)
    run(monitor_topology, network)

main = example
