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

class firewall(DynamicPolicy):

    def __init__(self):
        # Initialize the firewall
        print "initializing firewall"      
        self.firewall = {}
        super(firewall,self).__init__(true)
        import threading
        self.ui = threading.Thread(target=self.ui_loop)
        self.ui.daemon = True
        self.ui.start()

    def AddRule (self, mac1, mac2):
        if (mac2,mac1) in self.firewall:
            print "Firewall rule for %s: %s already exists" % (mac1,mac2) 
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
        self.policy = ~union([ (match(srcmac=mac1) & 
                                match(dstmac=mac2)) |
                               (match(dstmac=mac1) & 
                                match(srcmac=mac2)) 
                               for (mac1,mac2) 
                               in self.firewall.keys()])
        print self.policy

    def ui_loop (self):
        while(True):
            nb = raw_input('(b)lock, (a)llow, or (q)uit? ')
            if nb == 'b':
                try:
                    nb = raw_input('enter MAC address pair ')
                    (str1,str2) = nb.split(',')
                    (mac1,mac2) = (MAC(str1),MAC(str2))
                    self.AddRule(mac1,mac2)
                except:
                    print "Invalid Format"
            elif nb == 'a':
                try:
                    nb = raw_input('enter MAC address pair ')
                    (str1,str2) = nb.split(',')
                    (mac1,mac2) = (MAC(str1),MAC(str2))
                    self.DeleteRule(mac1,mac2)
                except:
                    print "Invalid Format"
            elif nb == 'q':
                print "Quitting"
                import os, signal
                os.kill(os.getpid(), signal.SIGINT)
                return
            else:
                print "Invalid option"    


def main ():
    return firewall() >> flood()
