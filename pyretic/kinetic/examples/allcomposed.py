from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *

from pyretic.kinetic.apps.ids_only import *
from pyretic.kinetic.apps.gardenwall_only import *
from pyretic.kinetic.apps.auth_only import *
from pyretic.kinetic.apps.mac_learner import *

#####################################################################################################
# App launch
#  - pyretic.py pyretic.kinetic.apps.allcomposed
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
    pol2 = gardenwall_only()
    pol3 = mac_learner()

    # For NuSMV
#    smv_str = fsm_def_to_smv_model_compose(pol1.fsm_def, pol2.fsm_def,'>>')
    cfsm_def, smv_str = fsm_def_compose(pol1.fsm_def, pol2.fsm_def,'>>')
    cfsm_def2, smv_str = fsm_def_compose(cfsm_def, pol3.fsm_def,'>>')
    mc = ModelChecker(smv_str,'allcomposed')  

    ## Add specs 
    mc.add_spec("FAIRNESS\n  authenticated;")
    mc.add_spec("FAIRNESS\n  infected;")
    mc.add_spec("FAIRNESS\n  exempt;")
    mc.add_spec("FAIRNESS\n  topo_change;")

    ### If infected, block traffic, regardless of authentication
    mc.add_spec("SPEC AG (infected & !exempt -> AX policy=drop)")

    ### If authentication event is false, next policy state is 'drop'
    mc.add_spec("SPEC AG (!authenticated -> AX policy=drop)")


    mc.save_as_smv_file()
    mc.verify()
    
    return (pol1 >> pol2 >> pol3)
