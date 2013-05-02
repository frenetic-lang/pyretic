
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the          #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this          #
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
# run controller: pox.py --no-cli PATH_TO_THIS_EXAMPLE --program=PATH_TO_EXAMPLE_TO_BE_VIRTUALIZED --virttopo=PATH_TO_VDEF   #
# start mininet:  pyretic/mininet.sh --topo cycle,4,4                                                                        #
# run pingall:    once or twice, clear a node's arp entry for one of its neighbors - e.g., h1 arp -d h2 - and ping           # 
# test:           NO RESPONSE AVAILABLE message should only show up once for each end host IP address                        #
##############################################################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.virt import *

def virtualize_program(virttopo, program, **kwargs):
    virttopons = {}
    programns = {}
    execfile(virttopo, virttopons)
    execfile(program, programns)

    vn = virttopons["transform"]
    return virtualize(programns["main"](**kwargs), vn)

    
main = virtualize_program
