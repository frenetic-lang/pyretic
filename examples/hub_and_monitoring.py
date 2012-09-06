from frenetic.lib import *

from examples import hub
from examples import monitor_packets
from examples import monitor_switches

def hub_and_monitoring(network):
    run(hub.hub, fork_sub_network(network))
    run(monitor_packets.monitor, fork_sub_network(network))
    run(monitor_switches.monitor, fork_sub_network(network))

start(hub_and_monitoring)

    
