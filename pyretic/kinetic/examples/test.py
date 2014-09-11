
import time
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

    number_of_fsms = 5
    list_of_composed_policies = []

    # Load modules with LPEC FSMs
    auth_w_obj = auth_web(number_of_fsms)
    auth_x_obj = auth_8021x(number_of_fsms)
    ids_obj = ids(number_of_fsms)
    rl_obj = rate_limiter(number_of_fsms)
    
    lpecs_for_auth_w = auth_w_obj.fsm_pol.dict_of_fsm_policies
    lpecs_for_auth_x = auth_w_obj.fsm_pol.dict_of_fsm_policies
    lpecs_for_ids_obj = ids_obj.fsm_pol.dict_of_fsm_policies
    lpecs_for_rl_obj = rl_obj.fsm_pol.dict_of_fsm_policies
    
    total_lpecs = list(set(lpecs_for_auth_w.keys()+lpecs_for_auth_x.keys()+lpecs_for_ids_obj.keys()+lpecs_for_rl_obj.keys()))
    
    for lpec in total_lpecs:
        pol_auth_w = identity
        pol_auth_x = drop
        pol_ids_obj = identity
        pol_rl_obj = identity
        
        if lpec in lpecs_for_auth_w:
            pol_auth_w = lpecs_for_auth_w[lpec]
        if lpec in lpecs_for_auth_x:
            pol_auth_x = lpecs_for_auth_x[lpec]
        if lpec in lpecs_for_ids_obj:
            pol_ids_obj = lpecs_for_ids_obj[lpec]
        if lpec in lpecs_for_rl_obj:
            pol_rl_obj = lpecs_for_rl_obj[lpec]
        
        tmp = (pol_auth_w + pol_auth_x) >> pol_ids_obj >> pol_rl_obj
        list_of_composed_policies.append(tmp)            

    composed_aggregate_policies = disjoint(list_of_composed_policies)
    start = time.time()
    composed_classifiers = composed_aggregate_policies.compile()
    print "Time to compile the composed policies ", time.time()-start
    print "# of flow rules after composition ", len(composed_classifiers)
    
    return composed_aggregate_policies
