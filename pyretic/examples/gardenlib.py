
from pyretic.kinetic.util.rewriting import *

def redirectToGardenWall():
    client_ips = [IP('10.0.0.1'), IP('10.0.0.2'),IP('10.0.0.4'),IP('10.0.0.5'),IP('10.0.0.6'),IP('10.0.0.7'),IP('10.0.0.8')]
    rewrite_policy = rewriteDstIPAndMAC(client_ips, '10.0.0.3')
    return rewrite_policy
