
from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *
from pyretic.kinetic.util.rewriting import *
#from pyretic.kinetic.apps.mac_learner import *
from pyretic.modules.mac_learner import *

#####################################################################################################
# * App launch
#   - pyretic.py pyretic.kinetic.apps.vm_prov
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --topo=single,3
#
# * Start ping from h1 to public IP
#   - mininet> h1 ping 10.0.0.100
#
# * Make h1's flow use backup server (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n backup -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#
# * Make h1's flow use primary server again (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n backup -l False --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#####################################################################################################

class vm_prov(DynamicPolicy):
    def __init__(self):

        # List of servers
        vm_prov.serverList = ['10.0.0.3','10.0.0.4','10.0.0.5','10.0.0.6','10.0.0.7','10.0.0.8']   

        # Choose randomly
        def fwdToThisServer(which_srv):
            client_ips = [IP('10.0.0.1'), IP('10.0.0.2')]
            if which_srv > -1 and which_srv < len(vm_prov.serverList):
                server_ip_str = self.serverList[which_srv]
            else:
                server_ip_str = '10.0.0.3' # default
            rewrite_policy = rewriteDstIPAndMAC_Public(client_ips, '10.0.0.100', server_ip_str)
            return rewrite_policy


        ### DEFINE THE LPEC FUNCTION

        def lpec(f):
           return match(srcip=f['srcip'],dstip=f['dstip'])

        ## SET UP TRANSITION FUNCTIONS

        @transition
        def load(self):
            self.case(occurred(self.event),self.event)

        @transition
        def policy(self):
            lightLoad = NonDetermPolicy([fwdToThisServer(i) for i in range(1)])
            mediumLoad = NonDetermPolicy([fwdToThisServer(i) for i in range(len(vm_prov.serverList)/2)])
            heavyLoad = NonDetermPolicy([fwdToThisServer(i+1) for i in range(len(vm_prov.serverList)-1)])

            self.case((V('load')==C(1)) , C(lightLoad))
            self.case((V('load')==C(2)) , C(mediumLoad))
            self.case((V('load')==C(3)) , C(heavyLoad))

            # Else, to primary
            self.default(C(fwdToThisServer(0)))

        
        ### SET UP THE FSM DESCRIPTION

        self.fsm_def = FSMDef(
            load=FSMVar(type=Type(int,{1,2,3}),
                        init=1,
                        trans=load),
            policy=FSMVar(type=Type(Policy,set([fwdToThisServer(i) for i in range(len(vm_prov.serverList))])),
                          init=fwdToThisServer(0),
                          trans=policy))

        ### SET UP POLICY AND EVENT STREAMS

        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)

        super(vm_prov,self).__init__(fsm_pol)


def main():
    pol = vm_prov()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'vm_prov')

    # If load is light, just forward to 1st server.
    mc.add_spec("SPEC AG (load=1 -> AX policy=policy_1)")

    # If load is medium, forward to 1st or 2nd server.
    mc.add_spec("SPEC AG (load=2 -> AX (policy=policy_1 | policy=policy_2 | policy=policy_3) )")

    # If load is high, it is possible to forward to 5th(last) server 
    mc.add_spec("SPEC AG (load=3 -> EX (policy=policy_5))")

    # Save NuSMV file
    mc.save_as_smv_file()

    # Verify
    mc.verify()

    return pol >> mac_learner()
