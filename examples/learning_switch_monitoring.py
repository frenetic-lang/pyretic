
from frenetic.lib import *

from examples import learning_switch
from examples import monitor_packets
from examples import monitor_switches

def learning_switch_monitoring(network):
    run(learning_switch.learning_switch, fork_sub_network(network))
    run(monitor_packets.monitor, fork_sub_network(network))
    run(monitor_switches.monitor, fork_sub_network(network))

start(learning_switch_monitoring)

    
