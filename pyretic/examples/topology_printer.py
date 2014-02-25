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
        self.topology = None
        self.lock = Lock()
        super(topology_printer,self).__init__()

    def set_network(self, network):
        with self.lock:
            if self.topology and (self.topology == network.topology):
                pass
            else:
                print self.topology
                print network.topology
                self.topology = network.topology
                print self.topology


def main ():
    return topology_printer()
