
from frenetic.lib import *

from virttopos.two_isolated_networks import *

from examples import hub
from examples import monitor_packets
from examples import monitor_switches

def hub_and_monitoring(network):
    n1, n2 = setup_virtual_networks(network)
    run(hub.hub, n1)
    run(monitor_packets.monitor, fork_sub_network(n2))
    run(monitor_switches.monitor, fork_sub_network(n2))

main = hub_and_monitoring

    
    
