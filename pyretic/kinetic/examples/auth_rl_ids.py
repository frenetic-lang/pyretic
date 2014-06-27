from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.translate import *

from pyretic.kinetic.apps.ids import *
from pyretic.kinetic.apps.auth import *
from pyretic.kinetic.apps.rate_limiter import *

#####################################################################################################
# App launch
#  - pyretic.py pyretic.kinetic.apps.auth_rl_ids
#
# Mininet Generation
#  - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --custom example_topos.py --topo=ratelimit
#
# Events to allow traffic "h1 ping h2"
#  - python json_sender.py -n auth -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001}
#  - python json_sender.py -n auth -l True --flow="{srcip=10.0.0.2}" -a 127.0.0.1 -p 50001}
#
# Events to block traffic "h1 ping h2"
#  - python json_sender.py -n infected -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001}
#
#
#
#####################################################################################################


def main():

    pol1 = auth()
    pol2 = rate_limiter()
    pol3 = ids()
    
    return pol1 >> pol2 >> pol3
