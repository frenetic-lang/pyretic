################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich  (jreich@cs.princeton.edu)                              #
################################################################################

from multiprocessing import Lock

from pyretic.lib.corelib import *
from pyretic.lib.std import *

class topology_printer(DynamicPolicy):

    def __init__(self):
        self.last_topology = None
        self.lock = Lock()
        super(topology_printer,self).__init__()

    def set_network(self, network):
        with self.lock:
            print '------New Topology Information----------'
            print '---Switch ID list'
            print network.switches()
            print '---Switch ID paired with port ID list'
            print network.switches(with_ports=True)
            print '---Convert network topology object to string'
            print network.topology
            print '---Has changed: ',
            if self.last_topology:
                print self.last_topology != network.topology 
            else:
                print True
            self.last_topology = network.topology

def main ():
    return topology_printer()
