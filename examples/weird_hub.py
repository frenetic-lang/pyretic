
from frenetic.lib import *

def weird_hub(network):
    network.install_policy(modify(srcmac="00000001" * 6) >> flood)

    for switch in network.switch_joins:
        print "Add switch: %s" % switch
        
start(weird_hub)
