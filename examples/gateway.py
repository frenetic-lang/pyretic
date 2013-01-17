
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

# Intended to be used with ./mininet.sh --topo

from frenetic.lib import *

topology = nx.Graph()
topology.add_node(Switch(1), ports={Port(1), Port(2)})
topology.add_node(Switch(2), ports={Port(1), Port(2)})
topology.add_node(Switch(3), ports={Port(1), Port(2)})

def ingress_policy():
    return (match(at=None, switch=1, inport=1) & push(vswitch=1, vinport=1) |
            match(at="vswitch 1, vinport 2") & (push(vswitch=1, vinport=2) >> pop(["at"])) |
            match(at="vswitch 2, vinport 1") & (push(vswitch=2, vinport=1) >> pop(["at"])) |
            match(at="vswitch 2, vinport 2") & (push(vswitch=2, vinport=2) >> pop(["at"])) |
            match(at="vswitch 3, vinport 1") & (push(vswitch=3, vinport=1) >> pop(["at"])) |
            match(at=None, switch=1, inport=2) & push(vswitch=3, vinport=2))

def physical_policy(redo):
    return parallel(match(vswitch=1, voutport=1) & fwd(1),
                    match(vswitch=1, voutport=2) & (push(at="vswitch 2, vinport 1") >> redo),
                    match(vswitch=2, voutport=1) & (push(at="vswitch 1, vinport 2") >> redo),
                    match(vswitch=2, voutport=2) & (push(at="vswitch 3, vinport 1") >> redo),
                    match(vswitch=3, voutport=1) & (push(at="vswitch 2, vinport 2") >> redo),
                    match(vswitch=3, voutport=2) & fwd(2))

def egress_policy():
    return pop_vheaders

def run_figure1(network):
    vnetwork = VNetwork.fork(network)
    vnetwork.ingress_policy = ingress_policy
    vnetwork.physical_policy = physical_policy
    vnetwork.egress_policy = egress_policy
    vnetwork.topology = topology
    run(gateway, vnetwork)

main = run_figure1
