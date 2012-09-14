
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

# Intended to be used with ./mininet.sh --topo linear,8

from frenetic.lib import *

vmap = {
    (1, 1): [(1, 1)],
    (1, 2): [(2, 3)],
    
    (2, 1): [(3, 1)],
    (2, 2): [(3, 2)],
    (2, 3): [(4, 3)],
    
    (3, 1): [(5, 1)],
    (3, 2): [(5, 2)],
    (3, 3): [(6, 3)],
    
    (4, 1): [(7, 1)],
    (4, 2): [(7, 2)],
    (4, 3): [(8, 3)],
}


physical_policy = simple_route(("switch", "voutport"),
                               ((1, 1), fwd(1)),
                               ((1, 2), fwd(2)),
                               ((2, 1), fwd(2)),
                               ((2, 2), fwd(3)),
    
                               ((3, 1), fwd(1)),
                               ((3, 2), fwd(2)),
                               ((3, 3), fwd(3)),
                               ((4, 1), fwd(2)),
                               ((4, 2), fwd(2)),
                               ((4, 3), fwd(3)),

                               ((5, 1), fwd(1)),
                               ((5, 2), fwd(2)),
                               ((5, 3), fwd(3)),
                               ((6, 1), fwd(2)),
                               ((6, 2), fwd(2)),
                               ((6, 3), fwd(3)),

                               ((7, 1), fwd(1)),
                               ((7, 2), fwd(2)),
                               ((7, 3), fwd(3)),
                               ((8, 1), fwd(2)),
                               ((8, 2), fwd(2)),
                               ((8, 3), fwd(3)))

def setup_virtual_network(network):
    return fork_virtual_network(network, make_vnetwork_gen([(vmap, physical_policy)]))
    
