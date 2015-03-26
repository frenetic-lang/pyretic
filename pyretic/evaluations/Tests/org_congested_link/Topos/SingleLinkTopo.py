import sys
sys.path.append('/home/mininet/pyretic/')
from pyretic.core.language import *
from pyretic.lib.std import *
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI


class SingleLinkTopo(Topo):
    def __init__(self,n,m):
        Topo.__init__(self)

        # Switches
        for i in range(1, n+m+3):
            self.addSwitch('s' + str(i))
        
        # Switch Links
        for i in range(1, n + 1):
            self.addLink('s' + str(i), 's' + str(n + m + 1))

        for i in range(n + 1, n + m + 1):
             self.addLink('s' + str(i), 's' + str(n + m + 2))

        self.addLink('s' + str(n + m + 1) , 's' + str(n + m + 2))
        


        # Hosts
        for i in range(1, n + 1):
            self.addHost('h' + str(i))
            self.addLink('h' + str(i), 's' + str(i))

        for i in range(1, m + 1):
            host_name = 'h' + str(i + n)
            self.addHost(host_name)
            self.addLink(host_name, 's' + str(i + n))

    @staticmethod
    def get_static_forwarding(n, m):

        ip_prefix = '10.0.0.'
        left_con_num = n + m + 1
        right_con_num = n + m + 2
        policy = drop
        for i in range(1, n + 1):
            partial_policy = (
                            (match(switch = i) >> fwd(2)) 
                            + (match(switch = left_con_num) >> fwd(i)) 
                            + (match(switch = right_con_num) >> fwd(m + 1))
                            + ( (~match(switch = i) & ~match(switch = left_con_num) & ~match(switch = right_con_num)) >> fwd(1) )
                            )
            policy += match(dstip = ip_prefix+str(i)) >> partial_policy
       
        for k in range(1, m + 1):
            i = k + n
            partial_policy = (
                            (match(switch = i) >> fwd(2)) 
                            + (match(switch = left_con_num) >> fwd(n + 1)) 
                            + (match(switch = right_con_num) >> fwd(k))
                            + ( (~match(switch = i) & ~match(switch = left_con_num) & ~match(switch = right_con_num)) >> fwd(1) )
                            )
            policy += match(dstip = ip_prefix+str(i)) >> partial_policy

        return policy




if __name__ == "__main__":
    import sys
    topo = SingleLinkTopo(int(sys.argv[1]), int(sys.argv[2]))
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=6634)
    net.start()
    CLI(net)
    net.stop()
