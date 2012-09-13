
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

# Intended to be used with ./mininet.sh --topo ytopo

from frenetic.lib import *

#                  +---------------+                              +-------------------+
#                  | +----------+  |                              | +--------------+  |
#            1     | |          |  |                              | |              |  |     1
#                --+ |1  s3     |v3|                              | |     s4      1|v3|        /-------
#          -----/  | |         2|  | 2                         2  | |2             |  |--------
#       --/        | +----------+ -\   2                   2   /--+-+--------------+  |
#                  +---------------+--+-------------------+----   +-------------------+
#                                     |  +-------------+  |
#                                     |  |2            3  |
#                                     |  |             |  |
#                                     |  |     s2      |v2|
#    two topos                        |  |             |  |
#    sharing all but s3, s4           |  +------1------+  |
#                                     +----------+--------+
#                                                |1
#                                                |2
#                                     +----------+-------+
#                                     |  +-------3----+  |
#                                     |  |            |  |
#                                     |  |     s1     |v1|
#                                     |  |            |  |
#                                     |  |  1     2   |  |
#                                     |  +------------+  |
#                                     +------------\-----+
#                                        ---/       \
#                              1     ---/            \-   1
#                                  -/                  \
#                                                       \

vmap1 = VMap({
    (1, 1): (1, 1, True),
    (1, 3): (1, 2),
    (2, 1): (2, 1),
    (2, 2): (2, 2),
    (3, 1): (3, 1, True),
    (3, 2): (3, 2),
})

vmap2 = VMap({
    (1, 2): (1, 1, True),
    (1, 3): (1, 2),
    (2, 1): (2, 1),
    (2, 3): (2, 2),
    (4, 1): (3, 1, True),
    (4, 2): (3, 2),
})

physical_policy1 = gen_static_physical_policy({
    (1, 1) : fwd(1),
    (1, 2) : fwd(3),
    
    (2, 1) : fwd(1),
    (2, 2) : fwd(2),
    
    (3, 1) : fwd(1),
    (3, 2) : fwd(2),
})

physical_policy2 = gen_static_physical_policy({
    (1, 1) : fwd(2),
    (1, 2) : fwd(3),
    
    (2, 1) : fwd(1),
    (2, 2) : fwd(3),
    
    (4, 1) : fwd(1),
    (4, 2) : fwd(2),
})


def setup_virtual_networks(network):
    n1 = vmap1.fork(network, [(physical_policy1,)], isolate=True)
    n2 = vmap2.fork(network, [(physical_policy2,)], isolate=True)
    
    return (n1, n2)
