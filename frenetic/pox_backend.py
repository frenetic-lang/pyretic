
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

from frenetic import generators
from frenetic import netcore as nc, network as net

from frenetic.util import frozendict

from pox.core import core
from pox.lib import revent

import pox.openflow.libopenflow_01 as of


class POXBackend(revent.EventMixin):
    def __init__(self, user_program):
        self.network = nc.Network()
        self.user_program = user_program
        self.listenTo(core)

    def _handle_GoingUpEvent(self, event):
        self.switch_connections = {}
        
        generators.run(self.user_program, self.network)

        self.listenTo(core.openflow)

    def _handle_PacketIn(self, event):
        pox_pkt = event.parsed
        packet = net.Packet(pox_pkt.pack(), switch=event.dpid, inport=event.ofp.in_port)
        n_pkts = self.network.get_policy().packets_to_send(packet)
        for pkt in n_pkts:
            assert "outport" in pkt.header
            if pkt.outport.is_real():
                self.send_packet(pkt)
            else:
                buck = pkt.outport.get_bucket()
                buck.signal(packet)
        
    def _handle_ConnectionUp(self, event):
        self.switch_connections[event.dpid] = event.connection
        self.network.switch_joins.signal(net.Switch(event.dpid))
        
    def _handle_ConnectionDown(self, event):
        # Post this to switch_down
        if event.dpid in self.switch_connections:
            del self.switch_connections[event.dpid]

        self.network.switch_parts.signal(net.Switch(event.dpid))
        
    def _handle_LinkEvent(self, event):
        # Post this somewhere
        pass

    def _handle_PortStatus(self, event):
        # Post this somewhere
        pass

    def _handle_BarrierIn(self, event):
        # We'll use this at some point?
        pass

    def send_packet(self, packet):
        switch = packet.header["switch"]
        inport = packet.header["inport"]
        outport = packet.header["outport"]
        
        msg = of.ofp_packet_out()
        msg.in_port = int(inport)
        msg.data = packet.payload

        outport = int(outport)
        if outport == net.Port.flood_port:
            outport = of.OFPP_FLOOD
        msg.actions.append(of.ofp_action_output(port = outport))

        self.switch_connections[int(switch)].send(msg)

_hack_program = None
        
def launch():
    backend = POXBackend(_hack_program)
    core.register("pyretic", backend)
        
def start(f):
    global _hack_program
    _hack_program = f
