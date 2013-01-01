
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

##############################################################################################################################
# TO TEST EXAMPLE                                                                                                            #
# -------------------------------------------------------------------                                                        #
# start mininet:  sudo mn -c; sudo mn --switch ovsk --controller remote --mac --topo tree,3,3                                #
# run controller: pox.py --no-cli pyretic/examples/monitor_topology.py                                                       #
# watch topology: a new topology will be printed each time a switch, port, or link registers                                 #
# test:           change topology by running 'link sX sY down', or restart mininet w/ new topology args                      #
##############################################################################################################################


from frenetic.lib import *

def pretty_print(topo,title):
    edge_str = {}
    egress_str = {}
    switch_str_maxlen = len('switch')
    edge_str_maxlen = len('switch edges')
    egress_str_maxlen = len('egress ports')
    for switch in topo.nodes():
        edge_str[switch] = ', '.join([ "%s[%s] --- %s[%s]" % (s1,ports[s1],s2,ports[s2]) for (s1,s2,ports) in topo.edges(data=True) if s1 == switch or s2 == switch])
        egress_str[switch] = ', '.join([ "%s[%s]---" % (switch,p) for p in egress_ports(topo,switch)])

    if len(topo.nodes()) > 0:
        edge_str_maxlen =  max( [len(ed) for ed in edge_str.values()] + [edge_str_maxlen] )
        egress_str_maxlen =  max( [len(eg) for eg in egress_str.values()] + [egress_str_maxlen] )

    table_width = switch_str_maxlen + 5 + edge_str_maxlen + 5 + egress_str_maxlen + 3
    print "%s" % title.rjust(table_width/2+1,'-').ljust(table_width,'-')
    print "%s  |  %s  |  %s  |" % ('switch','switch edges'.rjust(edge_str_maxlen/2+1).ljust(edge_str_maxlen),'egress ports'.rjust(egress_str_maxlen/2+1).ljust(egress_str_maxlen),)        
    print ''.rjust(table_width,'-')
    for switch in topo.nodes():
        edge_str[switch] = edge_str[switch].ljust(edge_str_maxlen)
        egress_str[switch] = egress_str[switch].ljust(egress_str_maxlen)
        print "%s  |  %s  |  %s  |" % (str(switch).ljust(switch_str_maxlen),edge_str[switch],egress_str[switch])
    print ''.rjust(table_width,'-')

def monitor(network):
    for topology in network.topology_changes:
        pretty_print(topology, "topology_change!")
        
main = monitor
