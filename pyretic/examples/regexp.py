################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
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

################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet: mininet.sh --topo=single,3,3 (or other single subnet network)       #
# test:    h1 python2 -m SimpleHTTPServer 3000                                 #
#          h2 curl 10.0.0.1:3000                                               #
#                                                                              #
#          It should output:                                                   #
#                                                                              #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner

def print_urls(pkt, match):
    print 'verb: %-5s | path: %-25s | version: %-3s' % match.groups()
        
### Main ###
def main():
    re = RegexpQuery("(?P<verb>GET|POST|DELETE|PUT|HEAD)\s*(?P<path>.*?)\s*HTTP/(?P<http>.*?)\n")
    re.register_callback(print_urls)

    return mac_learner() + re
