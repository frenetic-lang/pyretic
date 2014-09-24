
from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *
from pyretic.kinetic.util.resetting_q import *

#####################################################################################################
# * App launch
#   - pyretic.py pyretic.kinetic.apps.sf
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mininet.sh --topo=single,5
#
# * Internal hosts are: h3 (10.0.0.3) and h4(10.0.0.4).
#
# * Start ping from h1 to h3. Should not go through
#   - mininet> h1 ping h2 
#
# * Start ping from h3 to h1. Should go through
#   - mininet> h3 ping h1 
#
# * From now on, ping from h1 to h3 also works, until timeout occurs.
#
# * Events are internal
#   - Mac Learner application will automatically react to 
#     topology change (e.g., link down and up) emulated from Mininet, and successfully
#     forward traffic until no route exists between two hosts.
#####################################################################################################



class sf(DynamicPolicy):
    def __init__(self,internal_hosts,ih_prd):

       ### DEFINE THE LPEC FUNCTION

        def lpec(f):
            hosts = list()
            internal_h, external_h = None,None

            hosts.append(f['srcip'])
            hosts.append(f['dstip'])

            for host in hosts:
                if host in internal_hosts:
                    internal_h = host
                else:
                    external_h = host
                
            if internal_h is None or external_h is None:
                return None

            return (match(srcip=internal_h,dstip=external_h) | match(srcip=external_h,dstip=internal_h) )

        ## SET UP TRANSITION FUNCTIONS

        @transition
        def outgoing(self):
            self.case(is_true(V('timeout')),C(False))
            self.case(occurred(self.event),self.event)

        @transition
        def timeout(self):
            self.case(occurred(self.event),self.event)
            self.default(C(False))

        @transition
        def policy(self):
            self.case(is_true(V('timeout')),C(ih_prd))
            self.case(is_true(V('outgoing')),C(identity))
            self.default(C(ih_prd))

        ### SET UP THE FSM DESCRIPTION
        self.fsm_def = FSMDef(
            outgoing=FSMVar(type=BoolType(), 
                            init=False, 
                            trans=outgoing),
            timeout=FSMVar(type=BoolType(), 
                            init=False, 
                            trans=timeout),
            policy=FSMVar(type=Type(Policy,[identity,ih_prd]),
                          init=ih_prd,
                          trans=policy))

        ### DEFINE QUERY CALLBACKS

        def q_callback(pkt):
            flow = frozendict(srcip=pkt['srcip'],dstip=pkt['dstip'])
            return fsm_pol.event_handler(Event('outgoing',True,flow))

        ### SET UP POLICY AND EVENT STREAMS

        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        q = FwdBucket()
        q.register_callback(q_callback)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)
 
        super(sf,self).__init__(fsm_pol + (ih_prd >> q))


def main():
    internal_hosts = [IPAddr('10.0.0.3'),IPAddr('10.0.0.4')]
    ih_prd = union([match(srcip=h) for h in internal_hosts])
    pol = sf(internal_hosts,ih_prd)

    print fsm_def_to_smv_model(pol.fsm_def)

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'sf')  

    ## Add specs
    mc.add_spec("FAIRNESS\n  outgoing;")
    mc.add_spec("FAIRNESS\n  timeout;")

    ### If outgoing event is true and times is not up, next policy state is 'identity'
    mc.add_spec("SPEC AG (outgoing &!timeout -> AX policy=policy_1)")

    ### If outgoing event is true but also times is up, next policy state is 'match filter'
    mc.add_spec("SPEC AG (outgoing & timeout -> AX policy=policy_2)")

    ### If outgoing event is false, next policy state is 'match filter'
    mc.add_spec("SPEC AG (!outgoing -> AX policy=policy_2)")

#    ### Policy state is 'match filter' until outgoing is true.
#    mc.add_spec("SPEC A [ policy=policy_2 U (outgoing & !timeout) ]")

    # Save NuSMV file
    mc.save_as_smv_file()

    # Verify
    mc.verify()

    # Ask deployment
    ask_deploy()

    return pol >> flood()
