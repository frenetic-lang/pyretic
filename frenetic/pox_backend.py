
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

from frenetic import generators as gs
from frenetic import network as net
from frenetic import virt
from frenetic import util

from pox.core import core
from pox.lib import revent

import pox.openflow.libopenflow_01 as of


class POXBackend(revent.EventMixin):
    # NOT **kwargs
    def __init__(self, user_program, show_traces, kwargs):
        self.network = virt.Network()
        self.switch_connections = {}
        self.show_traces = show_traces
        
        if core.hasComponent("openflow"):
            self.listenTo(core.openflow)
        else:
            # We'll wait for openflow to come up
            self.listenTo(core)
        
        gs.run(user_program, self.network, **kwargs)

    def _handle_ComponentRegistered (self, event):
        if event.name == "openflow":
            self.listenTo(core.openflow)
            return EventRemove # We don't need this listener anymore

    def _handle_PacketIn(self, event):
        packet = net.Packet(event.data).update_header_fields(switch=event.dpid,
                                                             inport=event.ofp.in_port)
        
        n_pkts = list(self.network.get_policy().packets_to_send(packet).elements())

        if self.show_traces:
            print "Recv"
            print util.repr_plus([packet], sep="\n\n")
            print
            print
            print "Send"
            print util.repr_plus(n_pkts, sep="\n\n")
            print
            print
            print "===================================="
        
        for pkt in n_pkts:
            assert "outport" in pkt.header, "gotta send it somewhere"
            if pkt.outport.is_real():
                self.send_packet(pkt)
            else:
                bucket = pkt.outport.get_bucket()
                # Perform the link's function here and rm outport
                pkt = pkt.update_header_fields(outport=None)
                bucket.signal(pkt)

    def _handle_ConnectionUp(self, event):
        if event.dpid not in self.switch_connections:
            self.switch_connections[event.dpid] = event.connection
            self.network.switch_joins.signal(net.Switch(event.dpid))
        
    def _handle_ConnectionDown(self, event):
        if event.dpid in self.switch_connections:
            del self.switch_connections[event.dpid]
            self.network.switch_parts.signal(net.Switch(event.dpid))
        
    def _handle_PortStatus(self, event):
        if event.added:
            self.network.port_ups((net.Switch(event.dpid), Port(event.port)))
        elif event.removed:
            self.network.port_downs((net.Switch(event.dpid), Port(event.port)))
        
    def send_packet(self, packet):
        switch = int(packet.switch)
        inport = int(packet.inport)
        outport = int(packet.outport)
        
        msg = of.ofp_packet_out()
        msg.in_port = inport
        msg.data = packet._get_payload()

        outport = outport
        if outport == net.Port.flood_port:
            outport = of.OFPP_FLOOD
        msg.actions.append(of.ofp_action_output(port = outport))

        self.switch_connections[switch].send(msg)

def launch(module_dict, show_traces=False, **kwargs):
    import pox
    backend = POXBackend(module_dict["main"], bool(show_traces), kwargs)
    pox.pyr = backend
        
