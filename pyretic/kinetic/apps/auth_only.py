
from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *


#####################################################################################################
# * App launch
#   - pyretic.py pyretic.kinetic.apps.auth
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --topo=single,3
#
# * Start ping from h1 to h2 
#   - mininet> h1 ping h2
#
# * Events to allow traffic "h1 ping h2" (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n auth -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#   - python json_sender.py -n auth -l True --flow="{srcip=10.0.0.2}" -a 127.0.0.1 -p 50001
#####################################################################################################


class auth_only(DynamicPolicy):
    def __init__(self):

       ### DEFINE THE LPEC FUNCTION

        def lpec(f):
            return match(srcip=f['srcip'])

        ## SET UP TRANSITION FUNCTIONS

        @transition
        def authenticated(self):
            self.case(occurred(self.event),self.event)

        @transition
        def policy(self):
            self.case(is_true(V('authenticated')),C(identity))
            self.default(C(drop))

        ### SET UP THE FSM DESCRIPTION

        self.fsm_def = FSMDef( 
            authenticated=FSMVar(type=BoolType(), 
                            init=False, 
                            trans=authenticated),
            policy=FSMVar(type=Type(Policy,{drop,identity}),
                          init=drop,
                          trans=policy))

        ### SET UP POLICY AND EVENT STREAMS

        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)

        super(auth_only,self).__init__(fsm_pol)


def main():
    pol = auth_only()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'auth_only')  


    ## Add specs 
    mc.add_spec("FAIRNESS\n  authenticated;")

    ### If authentication event is true, next policy state is 'allow'
    mc.add_spec("SPEC AG (authenticated -> AX policy=policy_2)")

    ### If authentication event is false, next policy state is 'drop'
    mc.add_spec("SPEC AG (!authenticated -> AX policy=policy_1)")

    ### It is always possible for the policy state to go to 'allow'
    mc.add_spec("SPEC AG (EF policy=policy_2)")

    ### Policy state is 'drop' until authentication is true. 
    mc.add_spec("SPEC A [ policy=policy_1 U authenticated ]")

    mc.save_as_smv_file()
    mc.verify()

    return pol
