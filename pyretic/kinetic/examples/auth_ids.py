from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *

from pyretic.kinetic.apps.ids_only import *
from pyretic.kinetic.apps.gardenwall_only import *
from pyretic.kinetic.apps.auth_only import *

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

    pol1 = auth_only()
    pol2 = ids_only()

    # For NuSMV
    smv_str = fsm_def_to_smv_model_compose(pol1.fsm_def, pol2.fsm_def,'>>')
    mc = ModelChecker(smv_str,'auth_ids')  

    ## Add specs 
    mc.add_spec("FAIRNESS\n  authenticated;")
    mc.add_spec("FAIRNESS\n  infected;")

    ### If infected, block traffic, regardless of authentication
    mc.add_spec("SPEC AG (infected -> AX policy=drop)")

    ### If authentication event is false, next policy state is 'drop'
    mc.add_spec("SPEC AG (!authenticated -> AX policy=drop)")

    ### If authentication is true and infected is false, then allow
    mc.add_spec("SPEC AG (authenticated & !infected -> AX policy=identity)")

    ### It is always possible for the policy state to go to 'allow'
    mc.add_spec("SPEC AG (EF policy=identity)")

    mc.save_as_smv_file()
    mc.verify()
    
    return (pol1 >> pol2) >> flood()
