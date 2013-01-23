
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

############################################################################################################################
# TO TEST EXAMPLE                                                                                                          #
# -------------------------------------------------------------------                                                      #
# start mininet:  ./pyretic/mininet.sh --switch ovsk --topo=clique,4,4                                                     #
# run controller: pox.py --no-cli pyretic/examples/virtualize.py --program=pyretic/examples/learning_switch.py --virttopo=pyretic/virttopos/bfs.py
############################################################################################################################


from frenetic.lib import *
import sys

def topo_to_vmap(topo):
    vmap = {}
    port_ind = 1
    for loc in topo.egress_locations():
        vmap[1, port_ind] = [(loc.switch, loc.port)]
        port_ind += 1
    return vmap
  
def setup_virtual_network(network):
    sys.setrecursionlimit(1500)
    vn = VNetwork.fork(network)
    @run
    def vmap_gen():
        for topo in network.topology_changes:
            vmap = topo_to_vmap(topo)
            vtopo = Topology()
            add_nodes_from_vmap(vmap, vtopo)
            vn.physical_policy = network.flood
            vn.from_vmap(vmap)
            vn.topology = vtopo
            print "------------ underlying network ---------------"
            print topo
            print "------------ abstracted network ---------------"
            print vtopo
    return vn
