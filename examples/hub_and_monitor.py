
from frenetic.lib import *

from examples import hub
from examples import monitor


def hub_and_monitor(network):
    run(hub.hub, fork_sub_network(network))
    run(monitor.monitor, fork_sub_network(network))

start(hub_and_monitor)

    
