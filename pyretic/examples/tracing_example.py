
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
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
# run controller: pox.py --no-cli PATH_TO_THIS_EXAMPLE > tmp                                                                 #
# start mininet:  pyretic/mininet.sh --topo=gateway1_ns                                                                      #
# test:           h1 ping -c 1 hs1, then kill controller and examine tmp file                                                #
##############################################################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.examples.mac_learner import mac_learner
from pyretic.virttopos.gateway_vdef import gateway_vdef

@dynamic
def virtualized_policy(self):
    self.policy = virtualize(trace(flood()) , gateway_vdef(self), DEBUG=True)

def main():
    return virtualized_policy() >> if_(egress,clear_trace()) >> pkt_print('outgoing')


