from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *
from pyretic.lib.query import *
import shlex, subprocess



BASE_CMD = 'python /home/mininet/pyretic/pyretic/kinetic/json_sender.py -n rate -l'

BYTES_FOR_RATE2 = 5000
BYTES_FOR_RATE3 = 10000

class monitor(DynamicPolicy):
    def __init__(self,port=50001):

        self.q = count_bytes(1,['srcip','dstip'])
        self.set_rate_2 = False 
        self.set_rate_3 = False

        def packet_count_printer(counts):
            print '==== Count Bytes===='
            print str(counts) + '\n'

            for m in counts:
                idx = str(m).find('srcip')
                idx2 = str(m).find('dstip')
                sip = str(m)[idx:idx2].lstrip("srcip', ").rstrip(") ('")
                dip = str(m)[idx2:].lstrip("dstip', ").rstrip(")")
 
                if counts[m] > BYTES_FOR_RATE2 and BYTES_FOR_RATE3 > counts[m] and self.set_rate_2 is False:
                    cmd = BASE_CMD + ' 2 --flow="{srcip=' + sip +',dstip='+dip+'}" -a 127.0.0.1 -p ' + str(port)
                    p1 = subprocess.Popen([cmd], shell=True)
                    p1.communicate()
                    self.set_rate_2 = True
                elif counts[m] > BYTES_FOR_RATE3 and self.set_rate_3 is False:
                    cmd = BASE_CMD + ' 3 --flow="{srcip=' + sip +',dstip='+dip+'}" -a 127.0.0.1 -p ' + str(port)
                    p1 = subprocess.Popen([cmd], shell=True)
                    p1.communicate()
                    self.set_rate_3 = True

        def monitoring():
            return self.q + passthrough

       ### DEFINE THE LPEC FUNCTION

        def lpec(f):
            return match(srcip=f['srcip'])

        ## SET UP TRANSITION FUNCTIONS

        @transition
        def mon(self):
            self.case(occurred(self.event),self.event)

        @transition
        def policy_trans(self):
            self.case(is_true(V('monitor')),C(monitoring()))
            self.default(C(identity))

        ### SET UP THE FSM DESCRIPTION

        self.fsm_def = FSMDef(
            monitor=FSMVar(type=BoolType(), 
                             init=False, 
                             trans=mon),
            policy=FSMVar(type=Type(Policy,set([identity,monitoring()])),
                           init=monitoring(),
                           trans=policy_trans))


        ### Set up monitoring
        self.q.register_callback(packet_count_printer)


        ### SET UP POLICY AND EVENT STREAMS

        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)

        super(monitor,self).__init__(fsm_pol)


def main():
    pol = monitor()

    return pol
