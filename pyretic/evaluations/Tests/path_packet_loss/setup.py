from Topos import *


def setup_topo(*params):
    return SimpleChainTopo.SimpleChainTopo(*params)

def setup_workload(net, n):
    hosts = net.topo.hosts()
    hosts = [net.getNodeByName(h) for h in hosts]
    return (hosts[0], hosts[1], ['1M'])

