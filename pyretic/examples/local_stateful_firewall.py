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

class local_firewall(LocalDynamicPolicy):

    def __init__(self, safezone_port):
        # Initialize the firewall
        print "initializing firewall"      
        self.safezone_port = safezone_port
        self.firewall = {}
        self.query = match('inport' = safezone_port) >> local_packets(1, ['srcmac', 'dstmac'])
        self.query.register_callback(self.learn_new_outgoing)
        super(local_firewall,self).__init__(self.query)

    def learn_new_outgoing(self, pkt):
        AddRule(pkt['srcmac'], pkt['dstmac'])
        self.update_policy()

    def AddRule (self, mac1, mac2):
        if (mac2,mac1) in self.firewall:
            return
        self.firewall[(mac1,mac2)]=True
        print "Adding firewall rule in %s: %s" % (mac1,mac2) 
        self.update_policy()
    
    def DeleteRule (self, mac1, mac2):
        try:
            del self.firewall[(mac1,mac2)]
            print "Deleting firewall rule in %s: %s" % (mac1,mac2) 
            self.update_policy()
        except:
            pass
        try:
            del self.firewall[(mac2,mac1)]
            print "Deleting firewall rule in %s: %s" % (mac1,mac2) 
            self.update_policy()
        except:
            pass

    def update_policy (self):
        firewall_policy = ~union([ (match(srcmac=mac1) & 
                                match(dstmac=mac2)) |
                               (match(dstmac=mac1) & 
                                match(srcmac=mac2)) 
                               for (mac1,mac2) 
                               in self.firewall.keys()])
        self.policy = self.query + firewall_policy
        print self.policy

def main ():
    # NOTE: we assume the topology is SAFE ZONE --- 1 SWITCH 2 --- INTERNET
    return local_firewall(1) >> flood()
