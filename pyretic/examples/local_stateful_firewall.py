################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Nick Feamster (feamster@cc.gatech.edu)                               #
# author: Joshua Reich  (jreich@cs.princeton.edu)                              #
################################################################################

from pox.lib.addresses import EthAddr

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

class local_firewall(LocalDynamicPolicy):

    def __init__(self, safezone_port):
        # Initialize the firewall
        print "initializing firewall"      
        self.safezone_port = safezone_port
        self.firewall = {}
        self.query = local_packets(1, ['srcmac', 'dstmac'])
        self.query.register_callback(self.learn_new_outgoing)
        self.query_policy = match(inport=self.safezone_port) >> self.query
        super(local_firewall,self).__init__(self.query_policy)

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
        self.policy = self.query_policy + firewall_policy
        print self.policy

def main ():
    # NOTE: we assume the topology is SAFE ZONE --- 1 SWITCH 2 --- INTERNET
    # local_firewall(1) >>
    return  ((match(inport=3) >> (fwd(1) + fwd(2))) + (match(inport=1) >> (fwd(2) + fwd(3))) + (match(inport=2) >> (fwd(1) + fwd(3))))
