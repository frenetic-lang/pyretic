
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.kinetic.util.resetting_q import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *


#####################################################################################################
# * App launch
#   - pyretic.py pyretic.kinetic.apps.mac_learner
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mininet.sh --topo=clique,3,3
#
# * Start ping from h1 to h2 
#   - mininet> h1 ping h2
#
# * Events are internal
#   - Mac Learner application will automatically react to 
#     topology change (e.g., link down and up) emulated from Mininet, and successfully
#     forward traffic until no route exists between two hosts.
#####################################################################################################


class mac_learner(DynamicPolicy):
    def __init__(self):
        max_port = 8
        port_range = range(max_port+1)
        def int_to_policy(i):
            return flood() if i==0 else fwd(i)
        pol_range = map(int_to_policy,port_range)

        ### DEFINE THE LPEC FUNCTION

        def lpec(f):
            return match(dstmac=f['dstmac'],
                         switch=f['switch'])

        ## SET UP TRANSITION FUNCTIONS

        @transition
        def topo_change(self):
            self.case(occurred(self.event),self.event)
            self.default(C(False))

        @transition
        def port(self):
            self.case(is_true(V('topo_change')),C(0))
            self.case(occurred(self.event) & (V('port')==C(0)),self.event)
#            self.default(C(0))

        @transition
        def policy(self):
            for i in port_range:
                self.case(V('port')==C(i),C(int_to_policy(i)))
            self.default(C(flood()))

        ### SET UP THE FSM DESCRIPTION

        self.fsm_def = FSMDef(
            topo_change=FSMVar(type=BoolType(),
                               init=False,
                               trans=topo_change),
            port=FSMVar(type=Type(int,set(port_range)),
                        init=0,
                        trans=port),
            policy=FSMVar(type=Type(Policy,set(pol_range)),
                          init=flood(),
                          trans=policy))

        ### DEFINE QUERY CALLBACKS

        def q_callback(pkt):
            flow = frozendict(dstmac=pkt['srcmac'],switch=pkt['switch'])
            return fsm_pol.event_handler(Event('port',pkt['inport'],flow))

        ### SET UP POLICY AND EVENT STREAMS

        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        rq = resetting_q(query.packets,limit=1,group_by=['srcmac','switch'])
        rq.register_callback(q_callback)

        super(mac_learner,self).__init__(fsm_pol + rq)


def main():
    pol = mac_learner()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'mac_learner')  

    mc.add_spec("FAIRNESS\n  topo_change;")

    for i in range(1):
        ## Add specs
        mc.add_spec("SPEC AG (topo_change -> AX port=0)")
        mc.add_spec("SPEC AG (port=0 -> AG EF port>0)")
        mc.add_spec("SPEC ! AG (port=1 -> EX port=2)")
        mc.add_spec("SPEC AG (port>0 -> A [ port>0 U topo_change ] )")
#        mc.add_spec("SPEC ! AG A [ port>0 U topo_change ]")
#        mc.add_spec("SPEC AG (port=1 -> A [ port=1 U topo_change ] )")
#        mc.add_spec("SPEC ! AG (port=2 -> A [ port=1 U topo_change ] )")
#        mc.add_spec("SPEC AG (port=1 -> EF port=2)")
#        mc.add_spec("SPEC AG (port=1 -> A [ !(port=2) U port=0 ])")
#        mc.add_spec("SPEC AG (port=1 -> A [ !(port=2) U topo_change ])")

    mc.save_as_smv_file()
    mc.verify()
 
    # Ask deployment
    ask_deploy()

    return pol
