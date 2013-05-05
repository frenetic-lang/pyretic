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

from pyretic.core.network import ConcreteNetwork
import ipdb


class Runtime(object):
    def __init__(self, backend, main, show_traces, debug_packet_in, kwargs):
        self.network = ConcreteNetwork(self)
        self.policy = main(**kwargs)
        self.policy.set_network(self.network)
        self.debug_packet_in = debug_packet_in
        self.show_traces = show_traces
        self.backend = backend

    def _handle_PacketIn(self, recv_packet):
        if self.debug_packet_in == "1":
            ipdb.set_trace()
        
        with ipdb.launch_ipdb_on_exception():
            output = self.policy.eval(recv_packet)
            
        if self.debug_packet_in == "drop" and not output:
            ipdb.set_trace()
            output = self.policy.eval(recv_packet) # So we can step through it
        
        if self.show_traces:
            print "<<<<<<<<< RECV <<<<<<<<<<<<<<<<<<<<<<<<<<"
            print pyr_util.repr_plus([recv_packet], sep="\n\n")
            print
            print ">>>>>>>>> SEND >>>>>>>>>>>>>>>>>>>>>>>>>>"
            print pyr_util.repr_plus(output.elements(), sep="\n\n")
            print
        
        for pkt in output.elements():
            self.send_packet(pkt)


    def send_packet(self,packet):
        self.backend.send_packet(packet)


    def inject_discovery_packet(self,dpid, port):
        self.backend.inject_discovery_packet(dpid,port)
