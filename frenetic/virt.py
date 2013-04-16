################################################################################
# The Frenetic Project                                                         #
# frenetic@frenetic-lang.org                                                   #
################################################################################
# Licensed to the Frenetic Project by one or more contributors. See the        #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Frenetic Project licenses this        #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################

# This module is designed for import *.
from frenetic import generators as gs
from frenetic.network import *
from frenetic.netcore import *
from frenetic import util
from frenetic.util import singleton, Data

import itertools
from collections import Counter

################################################################################
# Virtualization policies 
################################################################################

class physical_to_virtual(SinglyDerivedPolicy):
    def __init__(self, vtag):
        self.vtag = vtag
        self.policy = (push(vtag=self.vtag) >> move(voutport="outport",
                                                    vswitch="switch",
                                                    vinport="inport"))
        
    def __repr__(self):
        return "physical_to_virtual %s" % self.vtag

        
@singleton
class virtual_to_physical(SinglyDerivedPolicy):
    def __init__(self):
        self.policy = (pop("switch", "inport", "outport", "vtag") >>
                       move(outport="voutport", switch="vswitch", inport="vinport"))
        
    def __repr__(self):
        return "virtual_to_physical"

        
@singleton
class pop_vheaders(SinglyDerivedPolicy):
    def __init__(self):
        self.policy = pop("vswitch", "vinport", "voutport", "vtag")
        
    def __repr__(self):
        return "pop_vheaders"

        
def add_nodes_from_vmap(vmap, vtopo):
    for switch, port_no in vmap:
        port = Port(port_no)
        try:
            vtopo.node[switch]['ports'][port_no] = port 
        except KeyError:
            vtopo.add_node(switch, ports={port_no: port})
    
def vmap_to_ingress_policy(vmap):
    ingress_policy = parallel(union(match(switch=sw, inport=p) for (sw, p) in switches)[
                                  push(vswitch=vsw, vinport=vp)]
                              for ((vsw, vp), switches) in vmap.iteritems())
    return ingress_policy

def vmap_to_egress_policy(vmap):
    matches_egress = []
    valid_match_egress = []
    for ((vsw, vp), switches) in vmap.iteritems():
        switch_pred = union(match(switch=sw, outport=p) for (sw, p) in switches)
        matches_egress.append(switch_pred)
        valid_match_egress.append(match(vswitch=vsw, voutport=vp) & switch_pred)
    return if_(union(matches_egress), union(valid_match_egress)[pop_vheaders], passthrough)


# New style combinators

class Virtualizer(object):
    pass

class virtualize(SinglyDerivedPolicy):
    def __init__(self, policy, virtdef):
        self.vpolicy = policy
        self.virtdef = virtdef
        self.vtag = id(self)
        self.policy = (
            if_(~match(vtag=self.vtag), 
                (self.virtdef.ingress_policy >> # set vswitch and vinport
                 # now make the virtualization transparent to the tenant's policy to get the outport
                 move(switch="vswitch", inport="vinport") >>
                 self.virtdef.transform_network(self.vpolicy) >>
                 physical_to_virtual(self.vtag)))
            # Pipe the packet with appropriate v* headers to the physical policy for processing
            >> self.virtdef.fabric_policy
            >> self.virtdef.egress_policy)
        
    def __repr__(self):
        return "virtualize_policy %s\n%s" % (self.vtag, self.virtdef)
