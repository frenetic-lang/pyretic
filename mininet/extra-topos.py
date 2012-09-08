

from mininet.topo import Topo, Node

class Figure3Topo(Topo):
    
    def __init__(self):
        
        # Add default members to class.
        super(Figure3Topo, self).__init__()

        # Set Node IDs for hosts and switches
        switch1 = 1
        switch2 = 2 

        data_server = 10
        compute_server_1 = 11
        compute_server_2 = 12
        
        # Add nodes
        self.add_node(switch1, Node(is_switch=True))
        self.add_node(switch2, Node(is_switch=True))
                
        self.add_node(data_server, Node(is_switch=False))
        self.add_node(compute_server_1, Node(is_switch=False))
        self.add_node(compute_server_2, Node(is_switch=False))

        # Add edges
        self.add_edge(switch1, data_server)
        self.add_edge(switch1, computer_server_1)
        self.add_edge(switch2, computer_server_2)

        self.add_edge(switch1, switch2)
        
        # Consider all switches and hosts 'on'
        self.enable_all()



class YTopo(Topo):
    
    def __init__(self):
        
        # Add default members to class.
        super(YTopo, self).__init__()

        # Set Node IDs for hosts and switches
        switch1 = 1
        switch2 = 2 
        switch3 = 3
        switch4 = 4

        host1 = 10
        host2 = 11
        host3 = 12
        host4 = 13
        
        # Add nodes
        self.add_node(switch1, Node(is_switch=True))
        self.add_node(switch2, Node(is_switch=True))
        self.add_node(switch3, Node(is_switch=True))
        self.add_node(switch4, Node(is_switch=True))
        
        self.add_node(host1, Node(is_switch=False))
        self.add_node(host2, Node(is_switch=False))
        self.add_node(host3, Node(is_switch=False))
        self.add_node(host4, Node(is_switch=False))

        # Add edges
        self.add_edge(switch1, host1)
        self.add_edge(switch1, host2)
        self.add_edge(switch3, host3)
        self.add_edge(switch4, host4)

        self.add_edge(switch1, switch2)
        self.add_edge(switch2, switch3)
        self.add_edge(switch2, switch4)
        
        
        # Consider all switches and hosts 'on'
        self.enable_all()

class SquareTopo(Topo):
    
    def __init__(self):
        
        # Add default members to class.
        super(SquareTopo, self).__init__()

        # Set Node IDs for hosts and switches
        switch1 = 1
        switch2 = 2 
        switch3 = 3
        switch4 = 4

        host1 = 10
        host2 = 11
        host3 = 12
        host4 = 13
        
        # Add nodes
        self.add_node(switch1, Node(is_switch=True))
        self.add_node(switch2, Node(is_switch=True))
        self.add_node(switch3, Node(is_switch=True))
        self.add_node(switch4, Node(is_switch=True))
        
        self.add_node(host1, Node(is_switch=False))
        self.add_node(host2, Node(is_switch=False))
        self.add_node(host3, Node(is_switch=False))
        self.add_node(host4, Node(is_switch=False))

        # Add edges
        self.add_edge(switch1, host1)
        self.add_edge(switch2, host2)
        self.add_edge(switch3, host3)
        self.add_edge(switch4, host4)

        self.add_edge(switch1, switch2)
        self.add_edge(switch1, switch4)
        self.add_edge(switch2, switch3)
        self.add_edge(switch3, switch4)
        
        # Consider all switches and hosts 'on'
        self.enable_all()

class TriangleTopo(Topo):
    
    def __init__(self):
        
        # Add default members to class.
        super(TriangleTopo, self).__init__()

        # Set Node IDs for hosts and switches
        switch1 = 1
        switch2 = 2 
        switch3 = 3

        host1 = 10
        host2 = 11
        host3 = 12
        
        # Add nodes
        self.add_node(switch1, Node(is_switch=True))
        self.add_node(switch2, Node(is_switch=True))
        self.add_node(switch3, Node(is_switch=True))
        
        self.add_node(host1, Node(is_switch=False))
        self.add_node(host2, Node(is_switch=False))
        self.add_node(host3, Node(is_switch=False))

        # Add edges
        self.add_edge(switch1, host1)
        self.add_edge(switch2, host2)
        self.add_edge(switch3, host3)

        self.add_edge(switch1, switch2)
        self.add_edge(switch2, switch3)
        self.add_edge(switch3, switch1)
        
        # Consider all switches and hosts 'on'
        self.enable_all()

class ChainTopo(Topo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(ChainTopo, self ).__init__()

        # Create hosts and switches
        # Hosts numbered 1..numHosts
        # Switches numbered 101..numSwitches
        hosts = range(1,numHosts+1)
        switches = range(101,numSwitches+101)

        # ADD NODES
        self.add_hosts(hosts)
        self.add_switches(switches)

        # ADD LINKS
        self.connect_switches(switches)
        self.connect_endhosts(switches,hosts)

        # Consider all switches and hosts 'on'
        self.enable_all()

    def add_switches(self,switches):
        for i in switches:
            self.add_node(i, Node(is_switch=True))

    def add_hosts(self,hosts):
        for i in hosts:
            self.add_node(i, Node(is_switch=False))

    def connect_switches(self,switches):
        # Topology trivial if less than 2 switches
        if len(switches) < 2:
            return

        # Connect Switches in chain topology
        for s in switches[:-1]:
            self.add_edge(s, s+1)

    def connect_endhosts(self,switches,hosts):
        # Connect nodes, divide them evenly across the switches
        s = switches[0]
        h = hosts[:]
        hps = max(len(hosts) // len(switches),1)
        while len(h) > 0:
            l = h[:hps]
            h = h[hps:]
            for j in l:
                self.add_edge(s,j)
            if [s] == switches[-1:]:
                s = switches[0]
            else:
                s += 1


class BumpChainTopo(ChainTopo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(BumpChainTopo, self ).__init__(numHosts,numSwitches)

    def add_switches(self,switches):
        super(BumpChainTopo, self ).add_switches(switches)
        self.add_node(201, Node(is_switch=True))
        self.add_node(202, Node(is_switch=True))

    def connect_switches(self,switches):
        super(BumpChainTopo, self ).connect_switches(switches)
        self.add_edge(201,switches[0])
        self.add_edge(202,switches[-1])

    def connect_endhosts(self,switches,hosts):
        servers, clients = splitServersClients(hosts)
#        h = hosts[:]
#        hps = len(hosts) // 2
#        servers = h[:hps]
#        clients = h[hps:]

        for endhost in servers:
            self.add_edge(201,endhost)

        for endhost in clients:
            self.add_edge(202,endhost)


class CycleTopo(ChainTopo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(CycleTopo, self ).__init__(numHosts,numSwitches)

    def connect_switches(self,switches):
        # Topology trivial if less than 2 switches
        if len(switches) < 2:
            return

        # Connect Switches in cycle topology
        for s in switches:
            self.add_edge(s, 101 + (s+1) % 101 % len(switches))


class BumpCycleTopo(CycleTopo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(BumpCycleTopo, self ).__init__(numHosts,numSwitches)

    def add_switches(self,switches):
        super(BumpCycleTopo, self ).add_switches(switches)
        self.add_node(201, Node(is_switch=True))
        self.add_node(202, Node(is_switch=True))

    def connect_switches(self,switches):
        super(BumpCycleTopo, self ).connect_switches(switches)
        self.add_edge(201,switches[0])
        self.add_edge(202,switches[len(switches)// 2])

    def connect_endhosts(self,switches,hosts):
        servers, clients = splitServersClients(hosts)
#        h = hosts[:]
#        hps = len(hosts) // 2
#        servers = h[:hps]
#        clients = h[hps:]

        for endhost in servers:
            self.add_edge(201,endhost)

        for endhost in clients:
            self.add_edge(202,endhost)


class CliqueTopo(ChainTopo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(CliqueTopo, self ).__init__(numHosts,numSwitches)

    def connect_switches(self,switches):
        # Topology trivial if less than 2 switches
        if len(switches) < 2:
            return

        # Connect Switches in clique topology
        for s1 in switches:
            for s2 in switches:
                if s2 <= s1:
                    continue
                self.add_edge(s1, s2)


class BumpCliqueTopo(CliqueTopo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(BumpCliqueTopo, self ).__init__(numHosts,numSwitches)

    def add_switches(self,switches):
        super(BumpCliqueTopo, self ).add_switches(switches)
        self.add_node(201, Node(is_switch=True))
        self.add_node(202, Node(is_switch=True))

    def connect_switches(self,switches):
        super(BumpCliqueTopo, self ).connect_switches(switches)
        self.add_edge(201,switches[0])
        self.add_edge(202,switches[len(switches)// 2])

    def connect_endhosts(self,switches,hosts):
        servers, clients = splitServersClients(hosts)
#        h = hosts[:]
#        hps = len(hosts) // 2
#        servers = h[:hps]
#        clients = h[hps:]

        for endhost in servers:
            self.add_edge(201,endhost)

        for endhost in clients:
            self.add_edge(202,endhost)


topos = { 'triangle': TriangleTopo,
          'figure3' : Figure3Topo,
          'square': SquareTopo,
          'ytopo': YTopo,
          'clique': CliqueTopo,
          'ChainTopo': ( lambda: ChainTopo(2,2) ),
          '3switch': ( lambda: CycleTopo(3,3) ) } 
