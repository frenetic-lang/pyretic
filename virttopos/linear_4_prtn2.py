
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

# Intended to be used with ./mininet.sh --topo linear,4


#     +-----------------+         +-------------------+
#     |                 |         |                   |
#     |                 |         |                   |
# 1   |      v1         |         |       v2          |--------------
# ----+                 +---------+                   |    1
#     |                 |  3    3 |                   |
#     |                 |         |                   |
#     +---------+-------+         +------------+------+
#               |                              |
#            2  |                              | 2
#               |                              |

from frenetic.lib import *

vmap = VMap({                                                               
    (1, 1): (1, 1),
    (2, 1): (1, 2),
    (2, 3): (1, 3),

    (3, 1): (2, 2),
    (3, 2): (2, 3),
    (4, 1): (2, 1)
})

physical_policy = gen_static_physical_policy({
    (1, 1) : fwd(1),
    (1, 2) : fwd(2),
    (1, 3) : fwd(2),

    (2, 1) : fwd(2),
    (2, 2) : fwd(1),
    (2, 3) : fwd(3),

    (3, 1) : fwd(3),
    (3, 2) : fwd(1),
    (3, 3) : fwd(2),

    (4, 1) : fwd(1),
    (4, 2) : fwd(2),
    (4, 3) : fwd(2),
})

def setup_virtual_network(network):
    return vmap.fork(network, [(physical_policy,)])
