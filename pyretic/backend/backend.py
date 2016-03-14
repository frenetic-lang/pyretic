
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

import threading
from pyretic.backend.comm import *

class BackendServer(asyncore.dispatcher):
    """Receives connections and establishes handlers for each backend.
    """
    def __init__(self, backend, address):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(address)
        self.address = self.socket.getsockname()
        self.listen(1)
        self.backend = backend
        return

    def handle_accept(self):
        # Called when a backend connects to our socket
        backend_info = self.accept()
        self.backend.backend_channel = BackendChannel(self.backend,sock=backend_info[0])
        # We only want to deal with one backend at a time,
        # so close as soon as we set up the handler.
        # Normally you would not do this and the server
        # would run forever or until it received instructions
        # to stop.
        self.handle_close()
        return
    
    def handle_close(self):
        self.close()


class BackendChannel(asynchat.async_chat):
    """Handles echoing messages from a single backend.
    """
    def __init__(self, backend, sock):
        self.backend = backend
        self.received_data = []
        asynchat.async_chat.__init__(self, sock)
        # If there are delays in receiving messages from the other side, and
        # they are because of large message sizes, increase this buffer size.
        self.ac_in_buffer_size = 4096 * 50
        self.ac_out_buffer_size = 4096 * 50
        self.set_terminator(TERM_CHAR)
        return

    def collect_incoming_data(self, data):
        """Read an incoming message from the backend and put it into our outgoing queue."""
        with self.backend.channel_lock:
            self.received_data.append(data)

    def found_terminator(self):
        """The end of a command or message has been seen."""
        with self.backend.channel_lock:
            msg = deserialize(self.received_data)

        # USE DESERIALIZED MSG
        if msg is None or len(msg) == 0:
            print "ERROR: empty message"
        elif msg[0] == 'switch':
            if msg[1] == 'join':
                if msg[3] == 'BEGIN':
                    self.backend.runtime.handle_switch_join(msg[2])
            elif msg[1] == 'part':
                self.backend.runtime.handle_switch_part(msg[2])
            else:
                print "ERROR: Bad switch event"
        elif msg[0] == 'port':
            if msg[1] == 'join':
                self.backend.runtime.handle_port_join(msg[2],msg[3],msg[4],msg[5],msg[6])
            elif msg[1] == 'mod':
                self.backend.runtime.handle_port_mod(msg[2],msg[3],msg[4],msg[5],msg[6])
            elif msg[1] == 'part':
                self.backend.runtime.handle_port_part(msg[2],msg[3])
            else:
                print "ERROR: Bad port event"
        elif msg[0] == 'link':
            self.backend.runtime.handle_link_update(msg[1],msg[2],msg[3],msg[4])
        elif msg[0] == 'packet':
            packet = msg[1]
            cookie = msg[2]
            self.backend.runtime.handle_packet_in(packet, cookie)
        elif msg[0] == 'flow_stats_reply':
            self.backend.runtime.handle_flow_stats_reply(msg[1],msg[2])
        elif msg[0] == 'flow_removed':
            self.backend.runtime.handle_flow_removed(msg[1], msg[2])
        else:
            print 'ERROR: Unknown msg from backend %s' % msg
        return


class Backend(object):

    class asyncore_loop(threading.Thread):
        def run(self):
            asyncore.loop()

    def __init__(self):
        self.backend_channel = None
        self.runtime = None
        self.channel_lock = threading.Lock()

        address = ('localhost', BACKEND_PORT) # USE KNOWN PORT
        self.backend_server = BackendServer(self,address)
        
        self.al = self.asyncore_loop()
        self.al.daemon = True
        self.al.start()

    def send_reset_install_time(self):
        self.send_to_OF_client(['reset_install_time'])

    def send_packet(self,packet):
        self.send_to_OF_client(['packet',packet])

    def send_install(self,pred,priority,action_list,cookie,notify=False,table_id=0):
        self.send_to_OF_client(['install',pred,priority,action_list,cookie,notify,table_id])

    def send_modify(self,pred,priority,action_list,cookie,notify=False,table_id=0):
        self.send_to_OF_client(['modify',pred,priority,action_list,cookie,notify,table_id])

    def send_delete(self,pred,priority):
        self.send_to_OF_client(['delete',pred,priority])
        
    def send_clear(self,switch,table_id):
        self.send_to_OF_client(['clear',switch,table_id])

    def send_flow_stats_request(self,switch):
        self.send_to_OF_client(['flow_stats_request',switch])

    def send_barrier(self,switch):
        self.send_to_OF_client(['barrier',switch])

    def inject_discovery_packet(self,dpid, port):
        self.send_to_OF_client(['inject_discovery_packet',dpid,port])

    def send_to_OF_client(self,msg):
        serialized_msg = serialize(msg)
        with self.channel_lock:
            if not self.backend_channel is None:
                self.backend_channel.push(serialized_msg)
