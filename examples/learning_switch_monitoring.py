
from frenetic.lib import *

from examples import learning_switch
from examples import monitor_packets
from examples import monitor_topology

def learning_switch_monitoring(network):
    run(network.install_policy_func(
            learning_switch.learning_switch), 
        Network.fork(network))
    run(monitor_packets.monitor, Network.fork(network))
    run(monitor_topology.monitor, Network.fork(network))

main = learning_switch_monitoring

    
