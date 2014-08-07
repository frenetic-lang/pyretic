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
            print network.switch_list()
            print '---List of every switch ID paired with port ID'
            print network.switch_with_port_ids_list()
            print '---List of every switch ID paired with port type'
            print [(sid,[(port.port_no,port.port_type) for port in ports]) 
                   for (sid,ports) in network.switch_with_ports_list()]
            print '---Edges'
            print '\n'.join(['s%s[%s]---s%s[%s]\ttype=%s' % (s1,data[s1],s2,data[s2],data['type']) for (s1,s2,data) in network.topology.edges(data=True)])
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
