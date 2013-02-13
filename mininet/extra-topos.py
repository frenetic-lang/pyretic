
from mininet.topo import Topo

class ChainTopo(Topo):
 
    def __init__(self, numSwitches, numClients, numServers=0):

        # Add default members to class.
        super(ChainTopo, self ).__init__()

        switch_inds = range(1,numSwitches+1)
        self.add_switches(switch_inds)
        self.connect_switches(switch_inds)

        client_ids = ['h'+str(i) for i in range(1,numClients+1)]
        server_ids = ['hs'+str(i) for i in range(1,numServers+1)]

        self.add_hosts(client_ids + server_ids)
        self.connect_hosts(switch_inds,client_ids,server_ids)

    def add_switches(self,switch_inds):
        for i in switch_inds:
            self.addSwitch('s'+str(i))

    def add_hosts(self,host_ids):
        for i in host_ids:
            self.addHost(i)

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


### ONE-OFF TOPOS FOR EXAMPLES
class Figure3Topo(Topo):
    
    def __init__(self):
        
        # Add default members to class.
        super(Figure3Topo, self).__init__()

        # Set Node IDs for hosts and switches
        switch1 = 's1'
        switch2 = 's2' 

        data_server = 'data1'
        compute_server_1 = 'compute1'
        compute_server_2 = 'compute2'
        
        # Add nodes
        self.addSwitch(switch1)
        self.addSwitch(switch2)
                
        self.addHost(data_server)
        self.addHost(compute_server_1)
        self.addHost(compute_server_2)

        # Add edges
        self.addLink(switch1, data_server)
        self.addLink(switch1, compute_server_1)
        self.addLink(switch2, compute_server_2)

        self.addLink(switch1, switch2)
        

class YTopo(Topo):
    
    def __init__(self):
        
        # Add default members to class.
        super(YTopo, self).__init__()

        # Set Node IDs for hosts and switches
        host_ids = range(1,5)
        switch_ids = range(1,5)
        
        # Add nodes
        for switch_id in switch_ids: 
            self.addSwitch('s'+str(switch_id))

        for host_id in host_ids: 
            self.addHost('h'+str(host_id))
        
        # Add edges
        self.addLink('s1', 'h1')
        self.addLink('s1', 'h2')
        self.addLink('s3', 'h3')
        self.addLink('s4', 'h4')

        self.addLink('s1', 's2')
        self.addLink('s2', 's3')
        self.addLink('s2', 's4')


class GatewayTopo(Topo):
    def __init__(self, numClients=3, numServers=3):        
        super(GatewayTopo, self).__init__()

        prefix_size  = 24
        left_prefix  = '10.0.0.'
        right_prefix = '10.0.1.'

        client_inds = range(1,numClients+1)
        server_inds = range(1,numServers+1)

        for switch_id in xrange(1, 8): 
            self.addSwitch('s'+str(switch_id))

        from mininet.util import ipParse,ipAdd
        
        for c in client_inds:
            ipstr = left_prefix + str(c+1) + '/' + str(prefix_size)
            hoststr = 'h'+str(c)
            self.addHost(hoststr, ip=ipstr, gw=left_prefix+'1', gw_mac='AA:AA:AA:AA:AA:AA')

        for s in server_inds: 
            ipstr = right_prefix + str(s+1) + '/' + str(prefix_size)
            self.addHost('hs'+str(s), ip=ipstr, gw=right_prefix+'1', gw_mac='AA:AA:AA:AA:AA:AA')
        
        # Ethernet side
        for c in client_inds:
            self.addLink('s'+str(c % numClients + 2), 'h'+str(c))
        
        self.addLink('s2', 's3')
        self.addLink('s3', 's1')
        self.addLink('s1', 's4')
        self.addLink('s4', 's2')

        # IP side
        for s in server_inds:
            self.addLink('s'+str(s % numServers + numClients + 2), 'hs'+str(s))

        self.addLink('s1', 's5')
        self.addLink('s5', 's6')
        self.addLink('s6', 's7')
        self.addLink('s7', 's1')




class PGatewayTopo(Topo):
    def __init__(self, numClients=3, numServers=3):        
        super(PGatewayTopo, self).__init__()

        prefix_size  = 24
        left_prefix  = '10.0.0.'
        right_prefix = '10.0.1.'

        client_inds = range(1,numClients+1)
        server_inds = range(1,numServers+1)

        self.addSwitch('s1000')
        self.addSwitch('s1001')
        self.addSwitch('s1002')
        for switch_id in xrange(2, 8): 
            self.addSwitch('s'+str(switch_id))

        from mininet.util import ipParse,ipAdd

        for c in client_inds:
            ipstr = left_prefix + str(c+1) + '/' + str(prefix_size)
            hoststr = 'h'+str(c)
            self.addHost(hoststr, ip=ipstr, gw=left_prefix+'1', gw_mac='AA:AA:AA:AA:AA:AA')

        for s in server_inds: 
            ipstr = right_prefix + str(s+1) + '/' + str(prefix_size)
            self.addHost('hs'+str(s), ip=ipstr, gw=right_prefix+'1', gw_mac='AA:AA:AA:AA:AA:AA')

        self.addLink('s1000','s1001')
        self.addLink('s1001','s1002')
        
        # Ethernet side
        for c in client_inds:
            self.addLink('s'+str(c % numClients + 2), 'h'+str(c))
        
        self.addLink('s2', 's3')
        self.addLink('s3', 's1000')
        self.addLink('s1000', 's4')
        self.addLink('s4', 's2')

        # IP side
        for s in server_inds:
            self.addLink('s'+str(s % numServers + numClients + 2), 'hs'+str(s))

        self.addLink('s1002', 's5')
        self.addLink('s5', 's6')
        self.addLink('s6', 's7')
        self.addLink('s7', 's1002')

            


topos = { 'triangle': ( lambda: CycleTopo(3,3) ), 
          'square': (lambda: CycleTopo(4,4)),
          'chain': ChainTopo,
          'clique': CliqueTopo,
          'cycle': CycleTopo,
          'bump_chain': BumpChainTopo,
          'bump_cycle': BumpCycleTopo,
          'bump_clique': BumpCliqueTopo,
          'figure3' : Figure3Topo,
          'ytopo': YTopo,
          'gateway': GatewayTopo,
          'pgateway': PGatewayTopo,
}
 
