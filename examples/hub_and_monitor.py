
from frenetic.lib import *

from examples.hub import hub
from examples.monitor_packets import monitor_packets

def hub_and_monitor(network):
    run(hub, Network.fork(network))
    run(monitor_packets, Network.fork(network))
    
main = hub_and_monitor

    
