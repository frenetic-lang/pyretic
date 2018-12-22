from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController   
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel

################################################################################
# sudo mn --controller=remote,ip=127.0.0.1 --custom example_topos.py --topo linear --link=tc --mac --arp
################################################################################


class Linear( Topo ):
  def __init__(self,nswitches,hostfanout):

    # Initialize topology
    Topo.__init__( self )
    switches = []
    host_machines = []

    # Create switches
    for s in range(nswitches):
      switches.append(self.addSwitch( 's%s'%(s+1) ))

      # Host creation
      for h in range(hostfanout):
        host_machines.append(self.addHost( 'h%s'%(h+1+s*hostfanout) ))

    # Wiring switches and hosts
    for idx,s in enumerate(switches):

      if idx < len(switches)-1:
        self.addLink ( s, switches[idx+1])

      # Wiring hosts to switch
      for h in range(hostfanout):
        self.addLink( host_machines[h + idx*hostfanout], s )

class Server_LB( Topo ):
  def __init__(self):
    # Initialize topology
    Topo.__init__( self )

    # Add hosts and switches
    h1 = self.addHost( 'h1' )
    h2 = self.addHost( 'h2' )
    h3 = self.addHost( 'h3' )
    h4 = self.addHost( 'h4' )
    h5 = self.addHost( 'h5' )

    s1 = self.addSwitch( 's1' )
    s2 = self.addSwitch( 's2' )

    # Add links
    self.addLink( h1, s1 )
    self.addLink( h2, s1 )

    self.addLink( h3, s2, delay='50ms')
    self.addLink( h4, s2, delay='100ms' )
    self.addLink( h5, s2, delay='150ms' )
    
    self.addLink( s1, s2 )


class Traffic_LB( Topo ):
  def __init__(self):
    # Initialize topology
    Topo.__init__( self )

    # Add hosts and switches
    h1 = self.addHost( 'h1' )
    h2 = self.addHost( 'h2' )

    s1 = self.addSwitch( 's1' )
    s2 = self.addSwitch( 's2' )
    s3 = self.addSwitch( 's3' )
    s4 = self.addSwitch( 's4' )
    s5 = self.addSwitch( 's5' )

    # Add links
    self.addLink( h1, s1 )
    self.addLink( h2, s5 )
    self.addLink( s1, s2 )
    self.addLink( s1, s3 )
    self.addLink( s1, s4 )
    self.addLink( s2, s5 )
    self.addLink( s3, s5 )
    self.addLink( s4, s5 )


class Ratelimit( Topo ):
  def __init__(self):
    # Initialize topology
    Topo.__init__( self )

    # Add hosts and switches
    h1 = self.addHost( 'h1' )
    h2 = self.addHost( 'h2' )

    s1 = self.addSwitch( 's1' )
    s2 = self.addSwitch( 's2' )
    s3 = self.addSwitch( 's3' )
    s4 = self.addSwitch( 's4' )
    s5 = self.addSwitch( 's5' )

    # Add links
    self.addLink( h1, s1 )
    self.addLink( h2, s5 )
    self.addLink( s1, s2 )
    self.addLink( s1, s3, delay='50ms')
    self.addLink( s1, s4, delay='200ms')
    self.addLink( s2, s5 )
    self.addLink( s3, s5 )
    self.addLink( s4, s5 )

##### Topologies #####
topos = { 
          'linear': ( lambda: Linear(3,2) ),          \
          'server_lb' : ( lambda: Server_LB() ),   \
          'ratelimit' : ( lambda: Ratelimit() ),   \
          'traffic_lb' : ( lambda: Traffic_LB() ),   \
        }
