
from frenetic.lib import *

from virttopos.ytopo import *

from examples import hub as ehub


def hub(network):
    n1, n2 = setup_virtual_networks(network)
    run(ehub.hub, n1)
    run(ehub.hub, n2)

main = hub

    
    
