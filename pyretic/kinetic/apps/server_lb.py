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
#   - pyretic.py pyretic.kinetic.apps.server_lb
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --custom mininet_topos/example_topos.py --topo=server_lb
#
# * Start ping from h1 to h2 
#   - mininet> h1 ping h2
#
# * Events  (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n lb -l True --flow="{srcip=10.0.0.1,dstip=10.0.0.2}" -a 127.0.0.1 -p 50001
#
#####################################################################################################



class serverlb(DynamicPolicy):
    def __init__(self):

        # Server list.
        self.servers = {'10.0.0.3': '00:00:00:00:00:03',
                   '10.0.0.4': '00:00:00:00:00:04', 
                   '10.0.0.5': '00:00:00:00:00:05'}

        # Randmoly choose a server from the list
        def randomly_choose_server(servermap):
            return server_i_policy(choice(servermap.keys()))

        # Forward to i-th server
        def server_i_policy(i):
            ip_list = self.servers.keys()
            ip_str = str(i)
            mac_str = self.servers[ip_str]
            public_ip = IP('10.0.0.100')
            client_ips = [IP('10.0.0.1'), IP('10.0.0.2')]
            receive_ip = [IP(ip_str)]*len(client_ips)
    
            rewrite_ip_policy = rewrite(zip(client_ips, receive_ip), public_ip)
            rewrite_mac_policy = if_(match(dstip=IP(ip_str),ethtype=2048),
                                     modify(dstmac=MAC(mac_str)),passthrough)
 
            return rewrite_ip_policy >> rewrite_mac_policy
    

        # Rewrite IP address.
        def rewrite(d,p):
            return intersection([subs(c,r,p) for c,r in d])
    

        # subroutine of rewrite()
        def subs(c,r,p):
            c_to_p = match(srcip=c,dstip=p)
            r_to_c = match(srcip=r,dstip=c)
            return ((c_to_p >> modify(dstip=r))+(r_to_c >> modify(srcip=p))+(~r_to_c >> ~c_to_p))
        
    

       ### DEFINE THE FLEC FUNCTION

        def lpec(f):
            return match(srcip=f['srcip'])
 
            
        ## SET UP TRANSITION FUNCTIONS
 
        @transition    
        def server(self):
            self.case(occurred(self.event),self.event)
 
        @transition    
        def policy(self):
            self.servers = {'10.0.0.3': '00:00:00:00:00:03',
                   '10.0.0.4': '00:00:00:00:00:04', 
                   '10.0.0.5': '00:00:00:00:00:05'}

            self.case(is_true(V('server')),C(randomly_choose_server(self.servers)))
            self.default(C(server_i_policy(self.servers.keys()[1])))


        ### SET UP THE FSM DESCRIPTION
    
        self.fsm_def = FSMDef(
            server=FSMVar(type=BoolType(), 
                           init=False, 
                           trans=server),
            policy=FSMVar(type=Type(Policy,set([server_i_policy(i) for i in self.servers])),
                           init=server_i_policy(choice(self.servers.keys())),
                           trans=policy))
   
        # Instantiate FSMPolicy, start/register JSON handler.
        fsm_pol = FSMPolicy(lpec, self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)
        
        super(serverlb,self).__init__(fsm_pol)


def main():
    pol = serverlb()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'server_lb')  

    ## Add specs
    mc.save_as_smv_file()
    mc.verify()

    # Ask deployment
    ask_deploy()


    return pol >> mac_learner()
