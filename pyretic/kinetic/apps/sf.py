
from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *


class sf(DynamicPolicy):
    def __init__(self,internal_hosts,ih_prd):

       ### DEFINE THE LPEC FUNCTION

        def lpec(f):
            hosts = list()
            internal_h = None
            external_h = None

            hosts.append(f['srcip'])
            hosts.append(f['dstip'])

            for host in hosts:
                if host in internal_hosts:
                    internal_h = host
                else:
                    external_h = host
                
            if internal_h is None or external_h is None:
                return None

            return (match(srcip=internal_h,dstip=external_h) |
                    match(srcip=external_h,dstip=internal_h) )

        ## SET UP TRANSITION FUNCTIONS

        @transition
        def outgoing(self):
            self.case(is_true(V('timeout')),C(False))
            self.case(occurred(self.event),self.event)

        @transition
        def timeout(self):
            self.case(occurred(self.event),self.event)

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
            src = pkt['srcip']
            dst = pkt['dstip']
            flow = frozendict(srcip=src,dstip=dst)
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
