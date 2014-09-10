from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController   
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.util import irange,dumpNodeConnections
from mininet.log import setLogLevel
import time
import math
from optparse import OptionParser


## Make linear topology
class EventTopo(Topo):
  def __init__(self, N, **opts):
    # Initialize topology and default options
    Topo.__init__(self, **opts)

    # Create switches and hosts
    hosts = [ self.addHost( 'h%s' % h )
              for h in irange( 1, N ) ]
    switches = [ self.addSwitch( 's%s' % s )
              for s in irange( 1, N ) ]
  
    # Wire up switches
    last = None                
    for switch in switches:
      if last:
        self.addLink( last, switch )
      last = switch
  
    # Wire up hosts
    for host, switch in zip( hosts, switches ):
      self.addLink( host, switch )

topos = { 'mytopo': ( lambda: EventTopo(5) ) }


### Start ping between hosts
def startpings( host, targetip, wait_time):
  "Tell host to repeatedly ping targets"

  # Simple ping loop
  cmd = ( 'while true; do '
          ' echo -n %s "->" %s ' % (host.IP(), targetip.IP()) + 
          ' `ping %s -i %s -W 0.9 -c 50 >> ./output/%s_%s`;' % (targetip.IP(), str(wait_time), host.IP(),targetip.IP()) + 
          ' break;'
          'done &' )

  print ( '*** Host %s (%s) will be pinging ips: %s' %
          ( host.name, host.IP(), targetip.IP() ) )

  host.cmd( cmd )


### RTT test  
def RTTTest(n, wait_time):
    
  print "a. Firing up Mininet"
  net = Mininet(topo=EventTopo(n), controller=lambda name: RemoteController( 'c0', '127.0.0.1' ), host=CPULimitedHost, link=TCLink)                                  
  net.start() 

  h1 = net.get('h1')
  time.sleep(5)

  # Start pings
  print "b. Starting Test"
  hosts = net.hosts

  for idx1,h1 in enumerate(hosts):
    for idx2,h2 in enumerate(hosts):
      if h1!=h2 and idx1<idx2:
        startpings(h1,h2, wait_time)
   
  time.sleep(30)

  # Stop pings
  for host in hosts:
    host.cmd( 'kill %while' )
    host.cmd( 'pkill ping' )

  print "c. Stopping Mininet"
  net.stop()


### Bandwidth test
def BWTest(n, wait_time):
    
  print "a. Firing up Mininet"
  net = Mininet(topo=EventTopo(n), controller=lambda name: RemoteController( 'c0', '127.0.0.1' ), host=CPULimitedHost, link=TCLink)                                  
  net.start() 

  h1 = net.get('h1')
  time.sleep(5)

  # Start test
  print "b. Starting Test"
  hosts = net.hosts

  # Run iperf servers
  for host in hosts:
    host.cmd( 'iperf -s &' )
   
  # Start iperf measurements 
  for idx1,h1 in enumerate(hosts):
    for idx2,h2 in enumerate(hosts):
      if h1!=h2 and idx1<idx2:
        startiperf(h1,h2)
   
  time.sleep(30)
 
  for host in hosts:
    host.cmd( 'pkill iperf' )

  print "c. Stopping Mininet"
  net.stop()


### start iperf cmd
def startiperf(h1,h2):
  # Simple iperf
  cmd = ( 'iperf -c %s > ./output/iperf_%s_%s &') %(h2.IP(), h1.IP(), h2.IP())

  print ( '*** Host %s (%s) will do iperf to: %s' %
          ( h1.name, h1.IP(), h2.IP() ) )

  h1.cmd( cmd )


def main():
  desc = ( 'Generate Mininet Testbed' )
  usage = ( '%prog [options]\n'
            '(type %prog -h for details)' )
  op = OptionParser( description=desc, usage=usage )

  ### Options
  op.add_option( '--rate', '-r', action="store", \
                 dest="rate", help = "Set rate. <n>S for (n/second), <n>M for (n/minute). Don't include the brackets when specifying n" )

  op.add_option( '--switchNum', '-s', action="store", \
                 dest="switchnum", help = "Specify the number of switches for this linear topology." )

  op.add_option( '--mode', '-m', action="store", \
                 dest="mode", help = "rtt or bw" )


  wait_time = 0.0
  options, args = op.parse_args()

  if options.rate is not None:
    if options.rate.endswith('S'):
      num_str = options.rate.rstrip('S')
      wait_time = 1.0/float(num_str)
    elif options.rate.endswith('M'):
      num_str = options.rate.rstrip('M')
      wait_time = 60.0/float(num_str)
    else:
      print 'Wrong rate format. Abort.'
      op.print_usage()
      return
  else:
    print '\nNo rate given. Abort.\n'
    op.print_usage()
    return

  if options.switchnum is not None and options.mode is not None and options.rate is not None:
    setLogLevel('info')
    if options.mode == 'rtt':
      RTTTest(int(options.switchnum), wait_time)
    elif options.mode == 'bw':
      BWTest(int(options.switchnum),  wait_time)
    else: 
      print "wrong mode. exit"
      op.print_usage()
      return

  else:
    print '\nNo switch number given. Abort.\n'
    op.print_usage()

if __name__ == '__main__':
  main()

