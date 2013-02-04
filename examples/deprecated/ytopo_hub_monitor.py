
from frenetic.lib import *

from virttopos.ytopo import *

from examples.hub_and_monitoring import hub_and_monitoring as hubmon


def hub_and_monitoring(network):
    n1, n2 = setup_virtual_networks(network)
    run(hubmon, n1)
    run(hubmon, n2)

main = hub_and_monitoring

    
    
