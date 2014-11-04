
from mininet.topo import Topo

class ChainTopo(Topo):
 
    def __init__(self, numSwitches, numClients, numServers=0, noIP=False):

        # Add default members to class.
        super(ChainTopo, self ).__init__()

        switch_inds = range(1,numSwitches+1)
        self.add_switches(switch_inds)
        self.connect_switches(switch_inds)

        client_ids = ['h'+str(i) for i in range(1,numClients+1)]
        server_ids = ['hs'+str(i) for i in range(1,numServers+1)]

        self.add_hosts(client_ids + server_ids,noIP)
        self.connect_hosts(switch_inds,client_ids,server_ids)

    def add_switches(self,switch_inds):
        for i in switch_inds:
            self.addSwitch('s'+str(i))

    def add_hosts(self,host_ids,noIP):
        for i in host_ids:
            if not noIP:
                self.addHost(i)
            else:
                self.addHost(i,ip=None)

    def connect_switches(self,switch_ids):

        # Topology trivial if less than 2 switch_ids
        if len(switch_ids) < 2:
            return

        # Connect switches in chain topology
        for s in switch_ids[:-1]:
            self.addLink('s'+str(s), 's'+str(s+1))

    def connect_hosts(self,switch_inds,client_ids,server_ids):
        # Connect nodes, divide them evenly across the switch_inds
        s = switch_inds[0]
        h = client_ids + server_ids
        hps = max(len(h) // len(switch_inds),1)
        while len(h) > 0:
            l = h[:hps]
            h = h[hps:]
            for j in l:
                self.addLink('s'+str(s),j)
            if [s] == switch_inds[-1:]:
                s = switch_inds[0]
            else:
                s += 1


class CycleTopo(ChainTopo):

    def connect_switches(self,switch_inds):

        # Topology trivial if less than 2 switches
        if len(switch_inds) < 2:
            return

        # Connect Switches in cycle topology
        for s in switch_inds:
            self.addLink('s'+str(s), 's'+str(1 + s % len(switch_inds)))


class CliqueTopo(ChainTopo):

    def connect_switches(self,switch_inds):
        # Topology trivial if less than 2 switches
        if len(switch_inds) < 2:
            return

        # Connect Switches in clique topology
        for s1 in switch_inds:
            for s2 in switch_inds:
                if s2 <= s1:
                    continue
                self.addLink('s'+str(s1), 's'+str(s2))


class BumpChainTopo(ChainTopo):

    def add_switches(self,switch_inds):
        super(BumpChainTopo, self ).add_switches(switch_inds)
        self.addSwitch('s101')
        self.addSwitch('s102')

    def connect_switches(self,switch_inds):
        super(BumpChainTopo, self ).connect_switches(switch_inds)
        self.addLink('s101','s'+str(switch_inds[0]))
        self.addLink('s102','s'+str(switch_inds[-1]))

    def connect_hosts(self,switch_inds,client_ids,server_ids):
        for client_id in client_ids:
            self.addLink('s101',client_id)
        for server_id in server_ids:
            self.addLink('s102',server_id)


class BumpCycleTopo(CycleTopo):

    def add_switches(self,switch_inds):
        super(BumpCycleTopo, self ).add_switches(switch_inds)
        self.addSwitch('s101')
        self.addSwitch('s102')

    def connect_switches(self,switch_inds):
        super(BumpCycleTopo, self ).connect_switches(switch_inds)
        self.addLink('s101','s'+str(switch_inds[0]))
        self.addLink('s102','s'+str(switch_inds[len(switch_inds) // 2]))

    def connect_hosts(self,switch_inds,client_ids,server_ids):
        for client_id in client_ids:
            self.addLink('s101',client_id)
        for server_id in server_ids:
            self.addLink('s102',server_id)


class BumpCliqueTopo(CliqueTopo):

    def add_switches(self,switch_inds):
        super(BumpCliqueTopo, self ).add_switches(switch_inds)
        self.addSwitch('s101')
        self.addSwitch('s102')

    def connect_switches(self,switch_inds):
        super(BumpCliqueTopo, self ).connect_switches(switch_inds)
        self.addLink('s101','s'+str(switch_inds[0]))
        self.addLink('s102','s'+str(switch_inds[len(switch_inds) // 2]))

    def connect_hosts(self,switch_inds,client_ids,server_ids):
        for client_id in client_ids:
            self.addLink('s101',client_id)
        for server_id in server_ids:
            self.addLink('s102',server_id)


class OneSwitchGatewayTopoNoSubnets(Topo):
    def __init__(self, numClients=3, numServers=3):        
        super(OneSwitchGatewayTopoNoSubnets, self).__init__()

        client_inds = range(1,numClients+1)
        server_inds = range(1,numServers+1)

        num_switches_left = 3
        num_switches_right = 3

        self.addSwitch('s1')
        for switch_id in xrange(2, 2 + num_switches_left + num_switches_right): 
            self.addSwitch('s'+str(switch_id))

        from mininet.util import ipParse,ipAdd
        
        for c in client_inds:
            self.addHost('h'+str(c))

        for s in server_inds: 
            self.addHost('hs'+str(s))
        
        # Ethernet side
        self.addLink('s1', 's2')  # s1[1] -- s2[1]
        self.addLink('s1', 's3')  # s1[2] -- s3[1]
        self.addLink('s2', 's4')  # s2[2] -- s4[1]
        self.addLink('s3', 's4')  # s3[2] -- s4[2]
        for c in client_inds:
            self.addLink('s'+str(c % num_switches_left + 2), 'h'+str(c))

        # IP side
        self.addLink('s1', 's5')  # s1[3] -- s5[1]
        self.addLink('s1', 's6')  # s1[4] -- s6[1]
        self.addLink('s5', 's7')  # s5[2] -- s7[1]
        self.addLink('s6', 's7')  # s6[2] -- s7[1]
        for s in server_inds:
            self.addLink('s'+str(s % num_switches_right + 2 + num_switches_left), 'hs'+str(s))


class ThreeSwitchGatewayTopoNoSubnets(Topo):
    def __init__(self, numClients=3, numServers=3):        
        super(ThreeSwitchGatewayTopoNoSubnets, self).__init__()

        client_inds = range(1,numClients+1)
        server_inds = range(1,numServers+1)

        num_switches_left = 3
        num_switches_right = 3

        self.addSwitch('s1000')
        self.addSwitch('s1001')
        self.addSwitch('s1002')
        for switch_id in xrange(2, 2 + num_switches_left + num_switches_right): 
            self.addSwitch('s'+str(switch_id))

        from mininet.util import ipParse,ipAdd
        
        for c in client_inds:
            self.addHost('h'+str(c))

        for s in server_inds: 
            self.addHost('hs'+str(s))

        # Ethernet side
        self.addLink('s1000', 's2')    # s1000[1] -- s2[1]
        self.addLink('s1000', 's3')    # s1000[2] -- s3[1]
        self.addLink('s2', 's4')       # s2[2] -- s4[1]
        self.addLink('s3', 's4')       # s3[2] -- s4[2]
        for c in client_inds:
            self.addLink('s'+str(c % num_switches_left + 2), 'h'+str(c))
        
        # IP side
        self.addLink('s1002', 's5')    # s1002[1] -- s5[1]
        self.addLink('s1002', 's6')    # s1002[2] -- s6[1]
        self.addLink('s5', 's7')       # s5[2] -- s7[1]
        self.addLink('s6', 's7')       # s6[2] -- s7[1]
        for s in server_inds:
            self.addLink('s'+str(s % num_switches_right + 2 + num_switches_left), 'hs'+str(s))

        # Link up physical gateway series
        self.addLink('s1001','s1000')  # s1001[1] -- s1000[3]
        self.addLink('s1001','s1002')  # s1001[2] -- s1002[3]


class OneSwitchGatewayTopo(Topo):
    def __init__(self, numClients=3, numServers=3):        
        super(OneSwitchGatewayTopo, self).__init__()

        prefix_size  = 24
        left_prefix  = '10.0.0.'
        right_prefix = '10.0.1.'

        client_inds = range(1,numClients+1)
        server_inds = range(1,numServers+1)

        num_switches_left = 3
        num_switches_right = 3

        self.addSwitch('s1')
        for switch_id in xrange(2, 2 + num_switches_left + num_switches_right): 
            self.addSwitch('s'+str(switch_id))

        from mininet.util import ipParse,ipAdd
        
        for c in client_inds:
            ipstr = left_prefix + str(c+1) + '/' + str(prefix_size)
            self.addHost('h'+str(c), ip=ipstr, gw=left_prefix+'1', gw_mac='AA:AA:AA:AA:AA:AA')

        for s in server_inds: 
            ipstr = right_prefix + str(s+1) + '/' + str(prefix_size)
            self.addHost('hs'+str(s), ip=ipstr, gw=right_prefix+'1', gw_mac='AA:AA:AA:AA:AA:AA')
        
        # Ethernet side
        self.addLink('s1', 's2')  # s1[1] -- s2[1]
        self.addLink('s1', 's3')  # s1[2] -- s3[1]
        self.addLink('s2', 's4')  # s2[2] -- s4[1]
        self.addLink('s3', 's4')  # s3[2] -- s4[2]
        for c in client_inds:
            self.addLink('s'+str(c % num_switches_left + 2), 'h'+str(c))

        # IP side
        self.addLink('s1', 's5')  # s1[3] -- s5[1]
        self.addLink('s1', 's6')  # s1[4] -- s6[1]
        self.addLink('s5', 's7')  # s5[2] -- s7[1]
        self.addLink('s6', 's7')  # s6[2] -- s7[1]
        for s in server_inds:
            self.addLink('s'+str(s % num_switches_right + 2 + num_switches_left), 'hs'+str(s))
            

class ThreeSwitchGatewayTopo(Topo):
    def __init__(self, numClients=3, numServers=3):        
        super(ThreeSwitchGatewayTopo, self).__init__()

        prefix_size  = 24
        left_prefix  = '10.0.0.'
        right_prefix = '10.0.1.'

        client_inds = range(1,numClients+1)
        server_inds = range(1,numServers+1)

        num_switches_left = 3
        num_switches_right = 3

        self.addSwitch('s1000')
        self.addSwitch('s1001')
        self.addSwitch('s1002')
        for switch_id in xrange(2, 2 + num_switches_left + num_switches_right): 
            self.addSwitch('s'+str(switch_id))

        from mininet.util import ipParse,ipAdd

        for c in client_inds:
            ipstr = left_prefix + str(c+1) + '/' + str(prefix_size)
            self.addHost('h'+str(c), ip=ipstr, gw=left_prefix+'1', gw_mac='AA:AA:AA:AA:AA:AA')

        for s in server_inds: 
            ipstr = right_prefix + str(s+1) + '/' + str(prefix_size)
            self.addHost('hs'+str(s), ip=ipstr, gw=right_prefix+'1', gw_mac='AA:AA:AA:AA:AA:AA')
        
        # Ethernet side
        self.addLink('s1000', 's2')    # s1000[1] -- s2[1]
        self.addLink('s1000', 's3')    # s1000[2] -- s3[1]
        self.addLink('s2', 's4')       # s2[2] -- s4[1]
        self.addLink('s3', 's4')       # s3[2] -- s4[2]
        for c in client_inds:
            self.addLink('s'+str(c % num_switches_left + 2), 'h'+str(c))
        
        # IP side
        self.addLink('s1002', 's5')    # s1002[1] -- s5[1]
        self.addLink('s1002', 's6')    # s1002[2] -- s6[1]
        self.addLink('s5', 's7')       # s5[2] -- s7[1]
        self.addLink('s6', 's7')       # s6[2] -- s7[1]
        for s in server_inds:
            self.addLink('s'+str(s % num_switches_right + 2 + num_switches_left), 'hs'+str(s))

        # Link up physical gateway series
        self.addLink('s1001','s1000')  # s1001[1] -- s1000[3]
        self.addLink('s1001','s1002')  # s1001[2] -- s1002[3]


class SimplePrefixTopo(Topo):
    def __init__(self):
        
        # Add default members to class.
        super(SimplePrefixTopo, self).__init__()

        # Set Node IDs for hosts and switches

        self.addHost('h1', ip='10.0.0.1')
        self.addHost('h2', ip='10.0.0.2')
        self.addHost('h3', ip='10.0.0.5')
        self.addSwitch('s1')

        # Add edges
        self.addLink('s1', 'h1')
        self.addLink('s1', 'h2')
        self.addLink('s1', 'h3')


topos = { 'triangle': ( lambda: CycleTopo(3,3) ), 
          'square': (lambda: CycleTopo(4,4)),
          'chain': ChainTopo,
          'clique': CliqueTopo,
          'cycle': CycleTopo,
          'bump_chain': BumpChainTopo,
          'bump_cycle': BumpCycleTopo,
          'bump_clique': BumpCliqueTopo,
          'gateway1': OneSwitchGatewayTopo,
          'gateway1_ns': OneSwitchGatewayTopoNoSubnets,
          'gateway3': ThreeSwitchGatewayTopo,
          'gateway3_ns': ThreeSwitchGatewayTopoNoSubnets,
          'simple_prefix': SimplePrefixTopo
}
 
