

from mininet.topo import Topo

class ChainTopo(Topo):
 
    def __init__(self, numHost_Ids, numSwitch_Ids):

        # Add default members to class.
        super(ChainTopo, self ).__init__()

        # Create host_ids and switch_ids
        # Host_Ids numbered 1..numHost_Ids
        # Switch_Ids numbered 1..numSwitch_Ids
        host_ids = range(1,numHost_Ids+1)
        switch_ids = range(1,numSwitch_Ids+1)

        # ADD NODES
        self.add_hosts(host_ids)
        self.add_switches(switch_ids)

        # ADD LINKS
        self.connect_switches(switch_ids)
        self.connect_hosts(switch_ids,host_ids)

    def add_switches(self,switch_ids):
        for i in switch_ids:
            self.addSwitch('s'+str(i))

    def add_hosts(self,host_ids):
        for i in host_ids:
            self.addHost('h'+str(i))

    def connect_switches(self,switch_ids):

        # Topology trivial if less than 2 switch_ids
        if len(switch_ids) < 2:
            return

        # Connect Switch_Ids in chain topology
        for s in switch_ids[:-1]:
            self.addLink('s'+str(s), 's'+str(s+1))

    def connect_hosts(self,switch_ids,host_ids):
        # Connect nodes, divide them evenly across the switch_ids
        s = switch_ids[0]
        h = host_ids[:]
        hps = max(len(host_ids) // len(switch_ids),1)
        while len(h) > 0:
            l = h[:hps]
            h = h[hps:]
            for j in l:
                self.addLink('s'+str(s),'h'+str(j))
            if [s] == switch_ids[-1:]:
                s = switch_ids[0]
            else:
                s += 1

class CycleTopo(ChainTopo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(CycleTopo, self ).__init__(numHosts,numSwitches)

    def connect_switches(self,switch_ids):

        # Topology trivial if less than 2 switches
        if len(switch_ids) < 2:
            return

        # Connect Switches in cycle topology
        for s in switch_ids:
            self.addLink('s'+str(s), 's'+str(1 + s % len(switch_ids)))


class CliqueTopo(ChainTopo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(CliqueTopo, self ).__init__(numHosts,numSwitches)

    def connect_switches(self,switches):
        # Topology trivial if less than 2 switches
        if len(switches) < 2:
            return

        # Connect Switches in clique topology
        for s1 in self.switches():
            for s2 in self.switches():
                if s2 <= s1:
                    continue
                self.addLink(s1, s2)




class BumpChainTopo(ChainTopo):

    def __init__(self, numClients, numServers, numSwitches):

        # Add default members to class.
        super(BumpChainTopo, self ).__init__(0,numSwitches)

    def add_switches(self,switches):
        super(BumpChainTopo, self ).add_switches(switches)
        self.addSwitch('server_switch')
        self.addSwitch('client_switch')

    def add_clients(self,host_ids):
        for i in host_ids:
            self.addHost('h'+str(i))

    def connect_switches(self,switches):

        super(BumpChainTopo, self ).connect_switches(switches)
        self.addLink('server_switch','s'+str(switches[0]))
        self.addLink('client_switch','s'+str(switches[-1]))

    def connect_hosts(self,switches,hosts):
        servers, clients = splitServersClients(hosts)

        for host in servers:
            self.addLink('server_switch','h'+str(host))

        for host in clients:
            self.addLink('client_switch','h'+str(host))



class BumpCycleTopo(CycleTopo):

    def __init__(self, numHosts, numSwitches):

        # Add default members to class.
        super(BumpCycleTopo, self ).__init__(numHosts,numSwitches)

    def add_switches(self,switches):
        super(BumpCycleTopo, self ).add_switches(switches)
        self.add_node(101, Node(is_switch=True))
        self.add_node(102, Node(is_switch=True))

    def connect_switches(self,switches):
        super(BumpCycleTopo, self ).connect_switches(switches)
        self.addLink(101,switches[0])
        self.addLink(102,switches[len(switches)// 2])

    def connect_hosts(self,switches,hosts):
        servers, clients = splitServersClients(hosts)

        for host in servers:
            self.addLink(101,host)

        for host in clients:
            self.addLink(102,host)


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
        self.addLink(201,switches[0])
        self.addLink(202,switches[len(switches)// 2])

    def connect_hosts(self,switches,hosts):
        servers, clients = splitServersClients(hosts)

        for host in servers:
            self.addLink(201,host)

        for host in clients:
            self.addLink(202,host)


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
        


topos = { 'triangle': ( lambda: CycleTopo(3,3) ), 
          'square': (lambda: CycleTopo(4,4)),
          'chain': ChainTopo,
          'clique': CliqueTopo,
          'cycle': CycleTopo,
          'bump_chain': BumpChainTopo,
          'figure3' : Figure3Topo,
          'ytopo': YTopo
}
 
