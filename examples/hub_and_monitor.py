
from frenetic.lib import *

from examples import hub
from examples import monitor_packets

def hub_and_monitor(network):
    run(network.install_policy_func(hub.hub), Network.fork(network))
    run(monitor_packets.monitor, Network.fork(network))
    
main = hub_and_monitor

    
