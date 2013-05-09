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

############################################################################################################################
# TO TEST EXAMPLE                                                                                                          #
# -------------------------------------------------------------------                                                      #
# run controller: pox.py --no-cli PATH_TO_THIS_EXAMPLE                                                                     #
# start mininet:  ./pyretic/mininet.sh --topo clique,4,4                                                                   # 
# start xterms:   xterm h1 h2 h3                                                                                           #
# start tcpdump:  in each xterm,                                                                                           #
# > IFACE=`ifconfig | head -n 1 | awk '{print $1}'`; tcpdump -XX -vvv -t -n -i $IFACE not ether proto 0x88cc > $IFACE.dump #
# test:           run pingall, check that tcpdump outputted identical packets on each term                                 #
#                 NOTE: diff'ing for equality isn't foolproof as packets in tcpdumps may be reordered                      #
############################################################################################################################


from pyretic.lib.corelib import *
from pyretic.lib.std import *

hub = flood()

def main():
    return hub
