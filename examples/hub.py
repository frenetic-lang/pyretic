
from frenetic.lib import *

def hub(network):
    network.install_policy(flood)
        
start(hub)
