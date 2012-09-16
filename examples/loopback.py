
from frenetic.lib import *


C = FixedInt(10)
CM = MatchExact(C)

def loopback(network):
    network.install_policy(match(my_count=None) & push(my_count=C(1), outport=0) |
                           match(my_count=CM(1)) & push(my_count=C(2), outport=0) |
                           match(my_count=CM(2)) & push(my_count=C(3), outport=0) |
                           match(my_count=CM(3)) & push(outport=1))
    
main = loopback
