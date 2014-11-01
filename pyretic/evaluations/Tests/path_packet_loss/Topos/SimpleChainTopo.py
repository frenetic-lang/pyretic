from pyretic.lib.corelib import *
from pyretic.lib.std import *
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI


class SimpleChainTopo(Topo):
    def __init__(self,n):
        Topo.__init__(self)

        # Switches
        for i in range(1, n+1):
            self.addSwitch('s' + str(i))
        
        # Switch Links
        for i in range(1, n):
            self.addLink('s' + str(i), 's' + str(i + 1))

        # Hosts

        self.addHost('h1')
        self.addLink('h1', 's1')

        self.addHost('h2')
        self.addLink('h2', 's' + str(n))
           
    @staticmethod
    def get_static_forwarding(n):

        ip_h1 = '10.0.0.1'
        ip_h2 = '10.0.0.2'

        policy = (
                    ( match(dstip = ip_h1) >> (  (match(switch = 1) >> fwd(2))
                                                +(~match(switch = 1) >> fwd(1))    
                                                ) )
                   +( match(dstip = ip_h2) >> ( (match(switch = 1) >> fwd(1))
                                                +(~match(switch = 1) >> fwd(2))
                                                ) )
                    )
        return policy




if __name__ == "__main__":
    topo = SimpleChainTopo(5)
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=6634)
    net.start()
    CLI(net)
    net.stop()
