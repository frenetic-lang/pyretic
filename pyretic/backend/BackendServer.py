import threading
from tools.comm import *
from pyretic.core.runtime import ConcretePacket
from tools.logger import simpleLogger

useThreading = True

class BackendChannel(asynchat.async_chat):
  """Handles echoing messages from a single client.
  """

  def __init__(self, server, sock):
    self.debug = True
    self.trace("BackendChannel.init: sock=%s" % sock)
    self.server = server    
    self.received_data = []    
    asynchat.async_chat.__init__(self, sock)
    self.set_terminator(TERM_CHAR)
      
    return

  def trace(self, logLine, timeStamped=False):
    if not self.debug:
      return
  
    simpleLogger.geTracePyretic()(logLine, timeStamped)

  def collect_incoming_data(self, data):
    """Read an incoming message from the client and put it into our outgoing queue."""
    self.trace("BackendChannel.collect_incoming_data: \ndata=%s\n" % data)
    with self.server.channel_lock:          
      self.received_data.append(data)        

  def found_terminator(self):
    """The end of a command or message has been seen."""
    self.trace("BackendChannel.found_terminator\n")
    self.processOFdata()                    
    
  def processSwitchData(self, msg):
    self.trace("processSwitchData: msg=%s" % msg)
    
    if msg[1] == 'join':
      if msg[3] == 'BEGIN':
        self.server.runtime.handle_switch_join(msg[2])

    elif msg[1] == 'part':
      self.server.runtime.handle_switch_part(msg[2])

    else:
      print "ERROR: Bad switch event"
  
  def processPortData(self, msg):
    self.trace("processPortData: msg=%s" % msg)

    if msg[1] == 'join':
      self.server.runtime.handle_port_join(msg[2],msg[3],msg[4],msg[5])

    elif msg[1] == 'mod':
      self.server.runtime.handle_port_mod(msg[2],msg[3],msg[4],msg[5])

    elif msg[1] == 'part':
      self.server.runtime.handle_port_part(msg[2],msg[3])

    else:
      print "ERROR: Bad port event"
  
  def processLinkData(self, msg):
    self.trace("processLinkData: msg=%s" % msg)
    self.server.runtime.handle_link_update(msg[1],msg[2],msg[3],msg[4])
  
  def processPacketData(self, msg):
    packet = ConcretePacket(msg[1])
    self.trace("processPacketData: packet=%s" % packet)
    self.server.runtime.handle_packet_in(packet)
  
  def processOFdata(self):
    with self.server.channel_lock:
      msg = deserialize(self.received_data)

    self.trace("BackendChannel.processOFdata: msg=%s\n" % msg, timeStamped=True)

    msg0 = msg[0]
    
    # USE DESERIALIZED MSG
    if msg0 == 'switch':
      self.processSwitchData(msg)
          
    elif msg0 == 'port':
      self.processPortData(msg)
          
    elif msg0 == 'link':
      self.processLinkData(msg)
      
    elif msg0 == 'packet':
      self.processPacketData(msg)
        
    else:
      print 'ERROR: Unknown msg from server %s' % msg
      
    return
  
class BackendServer(asyncore.dispatcher):
  """Receives connections and establishes handlers for each client.
  """
  class asyncore_loop(threading.Thread):
    def run(self):
      asyncore.loop()
  
  def __init__(self, port):
    self.debug = True
    self.trace("BackendServer port=%s\n" % (port), timeStamped=True)
    self.echoChannel = None                 
    self.runtime = None                     
    self.channel_lock = threading.Lock()    
    
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.bind(('', port))
    self.address = self.socket.getsockname()
    self.listen(1)

    if useThreading:
      self.al = self.asyncore_loop()
      self.al.daemon = True
      self.al.start()

    else:
      asyncore.loop()
    
    return

  def trace(self, logLine, timeStamped=False):
    if not self.debug:
      return
  
    simpleLogger.geTracePyretic()(logLine, timeStamped)

  def send_packet(self,packet):
    self.trace("Backend.send_packet: %s\n" % packet, timeStamped=True)
    self.send_to_OF_client(['packet',packet])

  def send_install(self,pred,action_list):
    self.trace("Backend.send_install: pred=%s action_list=%s\n" % (pred,action_list), timeStamped=True)
    self.send_to_OF_client(['install',pred,action_list])

  def send_clear_all(self):
    self.trace("Backend.send_clear_all\n", timeStamped=True)
    self.send_to_OF_client(['clear_all'])

  def inject_discovery_packet(self,dpid, port):
    self.trace("Backend.inject_discovery_packet: dpid=%s port=%s\n" % (dpid, port), timeStamped=True)
    self.send_to_OF_client(['inject_discovery_packet',dpid,port])

  def send_to_OF_client(self,msg):
    self.trace("Backend.send_to_OF_client: msg=%s\n" % msg, timeStamped=True)
    serialized_msg = serialize(msg)
    
    with self.channel_lock:
      self.echoChannel.push(serialized_msg)
  
  def handle_accept(self):
    # Called when a client connects to our socket
    client_info = self.accept()
    
    self.echoChannel = BackendChannel(self, sock=client_info[0])
    
    # We only want to deal with one client at a time,
    # so close as soon as we set up the handler.
    # Normally you would not do this and the server
    # would run forever or until it received instructions
    # to stop.
    self.handle_close()
    return

  def handle_close(self):
    self.close()


def buildOptions():
  desc = ( 'async chat echo server' )
  usage = ( '%prog [options]\n'
            '(type %prog -h for details)' )
  
  from optparse import OptionParser
  op = OptionParser( description=desc, usage=usage )
  
  op.add_option('--port', '-p', action = 'store', type   = 'int',
                 dest   = "port", default= BACKEND_PORT,
                 help   = 'set echo server port')
                 
  options, args = op.parse_args()

  return (options, args)
  
def main():
  (options, args) = buildOptions()
  print("port=%s" % options.port)
  server = BackendServer(options.port)
 
if __name__ == "__main__":
  main()
   