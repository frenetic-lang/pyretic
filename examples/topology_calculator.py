
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
# start mininet:  /pyretic/mininet.sh --switch ovsk --topo clique,5,5                                                        #
# run controller: pox.py --no-cli pyretic/examples/monitor_topology.py                                                       #
# watch topology: a new topology and disjoint MST set will be printed each time a switch, port, or link registers            #
# test:           change topology by running 'link sX sY down', or restart mininet w/ new topology args                      #
##############################################################################################################################


from frenetic.lib import *
from examples.monitor import monitor_topology

@policy_decorator
def calculate_spanning_tree_set(self):
    @self.network._topology.notify
    def f(topo):
        msts = Topology.disjoint_minimum_spanning_tree_set(topo)
        print "Topo"
        print topo
        print "Disjoint Minimum Spanning Tree Set:"
        print "{"
        for mst in msts:
            print "%s" % mst
        print "}"

main = calculate_spanning_tree_set()
