
from frenetic.lib import *

from examples import learning_switch
from examples.monitor_packets import monitor_packets
from examples.monitor_packets import monitor_packet_count
from examples.monitor_topology import monitor as monitor_topology

def learning_switch_monitoring(network):
    run(network.install_policy_func(
            learning_switch.learning_switch), 
        Network.fork(network))
    run(monitor_packets, Network.fork(network))
    run(monitor_packet_count, Network.fork(network))
    run(monitor_topology, Network.fork(network))

main = learning_switch_monitoring

    
