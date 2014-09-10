
from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *


#####################################################################################################
# * App launch
#   - pyretic.py pyretic.kinetic.apps.ids
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --topo=single,3
#
# * Start ping from h1 to h2 
#   - mininet> h1 ping h2
#
# * Events to block traffic "h1 ping h2" (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n infected -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#
# * Events to again allow traffic "h1 ping h2" (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n infected -l False --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#####################################################################################################

### Define a class for the application, subclassed from DynamicPolicy
class ids_only(DynamicPolicy):
    def __init__(self):

        ### 1. DEFINE THE LPEC FUNCTION

        def lpec(f):
            # Packets with same source IP 
            #  will have a same "state" (thus, same policy applied).
            return match(srcip=f['srcip'])


        ### 2. SET UP TRANSITION FUNCTIONS

        @transition
        def infected(self):
            # Return the variable's own value. 
            # If True, return True. If False, return False.
            self.case(occurred(self.event),self.event)

        @transition
        def policy(self):
            # If "infected" is True, change policy to "drop"
            self.case(is_true(V('infected')),C(drop))

            # Default policy is "indentity", which is "allow".
            self.default(C(identity))


        ### 3. SET UP THE FSM DESCRIPTION

        self.fsm_def = FSMDef(
            infected=FSMVar(type=BoolType(), 
                            init=False, 
                            trans=infected),
            policy=FSMVar(type=Type(Policy,{drop,identity}),
                          init=identity,
                          trans=policy))


        ### 4. SET UP POLICY AND EVENT STREAMS

        ### This part pretty much remains same for any application
        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)
        ### This part pretty much remains same for any application

        # Specify application class name here. (e.g., "ids")
        super(ids_only,self).__init__(fsm_pol)


def main():

    # DynamicPolicy that is going to be returned
    pol = ids_only()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'ids_only')  

    ## Add specs
    mc.add_spec("FAIRNESS\n  infected;")

    ### If infected event is true, next policy state is 'drop'
    mc.add_spec("SPEC AG (infected -> AX policy=policy_1)")

    ### If infected event is false, next policy state is 'allow'
    mc.add_spec("SPEC AG (!infected -> AX policy=policy_2)")

    ### Policy state is 'allow' until infected is true.
    mc.add_spec("SPEC A [ policy=policy_2 U infected ]")

    ### It is always possible to go back to 'allow'
    mc.add_spec("SPEC AG EF policy=policy_2")

    # Save NuSMV file
    mc.save_as_smv_file()

    # Verify
    mc.verify()

    # Return DynamicPolicy. 
    # flood() will take for of forwarding for this simple example.
    return pol
