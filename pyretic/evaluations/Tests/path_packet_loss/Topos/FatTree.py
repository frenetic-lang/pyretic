import fnss
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI

def get_fattree_topo(k):
    fnss_topo = fnss.fat_tree_topology(k)
    return fnss.to_mininet(fnss_topo)

if __name__ == "__main__":
    topo = get_fattree_topo(6)
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=6634)
    net.start()
    CLI(net)
    net.stop()
