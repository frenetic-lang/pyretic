from pyretic.kinetic.apps.auth import auth
from pyretic.kinetic.apps.auth_web import *
from pyretic.kinetic.apps.auth_8021x import *
from pyretic.kinetic.apps.ids import *
from pyretic.kinetic.apps.gardenwall import *
from pyretic.kinetic.apps.mac_learner import *
from pyretic.kinetic.apps.rate_limiter import *
from pyretic.kinetic.apps.monitor import *

#####################################################################################################
# App launch
#  - pyretic.py pyretic.kinetic.examples.test
#
# Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#  - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --custom mininet_topos/example_topos.py --topo=ratelimit
#
#####################################################################################################

def main():

    number_of_fsms = 100

    # Load modules with LPEC FSMs
    auth_w_obj = auth_web(number_of_fsms)
    auth_x_obj = auth_8021x(number_of_fsms)
    ids_obj = ids(number_of_fsms)
    rl_obj = rate_limiter(number_of_fsms)

    # Possible to access each LPEC FSMs through 'list_of_fsm_policies'.
    for  p in auth_w_obj.fsm_pol.list_of_fsm_policies:
#        print p.compile()
        pass

    # Final compilation. 
    return (auth_w_obj + auth_x_obj) >> ids_obj >> rl_obj
