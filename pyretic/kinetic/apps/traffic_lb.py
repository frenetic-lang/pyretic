from random import choice

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent 
from pyretic.kinetic.smv.model_checker import *
from pyretic.kinetic.apps.mac_learner import *

    
#####################################################################################################
# * App launch
#   - pyretic.py pyretic.kinetic.apps.traffic_lb
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --custom mininet_topos/example_topos.py --topo=traffic_lb
#
# * Start ping from h1 to h2 
#   - mininet> h1 ping h2
#
# * Events to make flow load balance 
#   - python json_sender.py -n lb -l True --flow="{srcip=10.0.0.1,dstip=10.0.0.2}" -a 127.0.0.1 -p 50001
#
# * Events to make flow just take default path
#   - python json_sender.py -n lb -l False --flow="{srcip=10.0.0.1,dstip=10.0.0.2}" -a 127.0.0.1 -p 50001
#
#####################################################################################################



class traffic_lb(DynamicPolicy):
    def __init__(self):


        ### DEFINE INTERNAL METHODS
        
        self.links = [1,2,3]

        def interswitch():
            return if_(match(inport=2),fwd(1),fwd(2))

        def routing():
            match_inter = union([match(switch=2),match(switch=3),match(switch=4)])
            match_inport = union([match(inport=2),match(inport=3),match(inport=4)])

            r = if_(match_inter,interswitch(), if_(match_inport, fwd(1), drop))
            
            return r

        def randomly_choose_link():
            return traffic_lb_policy(choice(self.links)+1)

        def traffic_lb_policy(i):
            match_from_edge = (union([match(switch=1),match(switch=5)]) & match(inport=1))
            return if_(match_from_edge, fwd(i), routing())


        ### DEFINE THE LPEC FUNCTION

        def lpec(f):
            h1 = f['srcip']
            h2 = f['dstip']
            return union([match(srcip=h1,dstip=h2),match(srcip=h2,dstip=h1)] )


        ### SET UP TRANSITION FUNCTIONS
        @transition
        def lb(self):
            self.case(occurred(self.event),self.event)

        @transition
        def policy(self):
            self.case(is_true(V('lb')),C(randomly_choose_link()))
            self.default(C(traffic_lb_policy(2)))


        ### SET UP THE FSM DESCRIPTION
    
        self.fsm_def = FSMDef( 
            lb=FSMVar(type=BoolType(),
                         init=False,
                         trans=lb),
            policy=FSMVar(type=Type(Policy,set([traffic_lb_policy(i+1) for i in self.links ])),
                           init=traffic_lb_policy(2),
                           trans=policy))

        # Instantiate FSMPolicy, start/register JSON handler.
        fsm_pol = FSMPolicy(lpec, self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)
        
        super(traffic_lb,self).__init__(fsm_pol)


def main():
    pol = traffic_lb()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'traffic_lb')  

    ## Add specs
    mc.save_as_smv_file()
    mc.verify()

    # Ask deployment
    ask_deploy()

    return pol
