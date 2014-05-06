################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Nick Feamster (feamster@cc.gatech.edu)                               #
# author: Joshua Reich  (jreich@cs.princeton.edu)                              #
################################################################################

from pox.lib.addresses import EthAddr

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner

class local_load_balancer(LocalDynamicPolicy):

    def __init__(self, in_port, out_ports):
        self.in_port = in_port
        self.out_ports = out_ports
        self.next_port_index = 0
        self.query = match('inport' = in_port) >> local_packets(1, ['srcmac', 'dstmac'])
        self.query.register_callback(self.learn_new_outgoing)
        super(local_load_balancer,self).__init__(self.query)

    def learn_new_outgoing(self, pkt):
        self.policy += match(srcmac=pkt['srcmac'], dstmac=pkt['dstmac']) >> fwd(self.next_port_index)
        self.next_port_index += 1

def main ():
    # NOTE: we assume the topology is INTERNET --- 1 SWITCH 2 --- SERVER 1
    #                                                       3 --- SERVER 2
    return local_load_balancer(1, [2,3])
