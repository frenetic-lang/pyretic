

from mininet.topo import Topo, Node

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

topos = { 'triangle': lambda: TriangleTopo() } 
