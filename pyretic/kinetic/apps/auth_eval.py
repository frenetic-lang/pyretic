
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


class auth(DynamicPolicy):
    def __init__(self,num_of_fsms=0):
    
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

        self.fsm_pol = FSMPolicy(lpec,self.fsm_def,num_of_fsms)
        json_event = JSONEvent()
        json_event.register_callback(self.fsm_pol.event_handler)

        super(auth,self).__init__(self.fsm_pol)


def main():
    num_of_fsms = sys.argv[2]
    pol = auth(num_of_fsms)

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'auth')  

    ## Add specs 
    mc.add_spec("FAIRNESS\n  authenticated;")

    org_smv_str = mc.get_smv_str()

    verify_time_list_map = {}   #  { nspec : [list of measurements] } 
    nspec = [1,20,40,60,80,100]
    nspec = [100]
    for i in nspec:
        mc.set_smv_str(org_smv_str)
        spec_list = mc.spec_builder(pol.fsm_def,i)

        for s in spec_list:
            mc.add_spec(s)

        mc.save_as_smv_file()

        verify_time_list = []
        for j in range(1000):
            verify_time_list.append(mc.verify()*1000)
            time.sleep(0.05)
        verify_time_list_map[i] = verify_time_list

    print verify_time_list_map.keys()

    print 'Save result. '
    pickle_fd = open('./verify_auth_map.p','wb')
    pickle.dump(verify_time_list_map,pickle_fd)
    pickle_fd.close() 

    # Ask deployment
    ask_deploy(pol.fsm_pol)

    return pol >> flood()
