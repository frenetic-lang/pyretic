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
# Isolation
################################################################################

class isolate_policy(DerivedPolicy, Data("itag policy ingress_predicate egress_predicate")):
    def __repr__(self):
        return "isolate_policy %s\n%s" % (self.itag,
                                          util.repr_plus(["POLICY",
                                                          self.policy,
                                                          "INGRESS PREDICATE",
                                                          self.ingress_predicate,
                                                          "EGRESS PREDICATE",
                                                          self.egress_predicate]))
    
    def get_policy(self):
        pol = (if_(match(itag=None) & self.ingress_predicate,
                   push(itag=self.itag)) >>
               (match(itag=self.itag) &
                (self.policy >>
                 if_(is_bucket("outport") | self.egress_predicate, pop(["itag"])))))
        return pol
    
class INetwork(Network):
    def __init__(self):
        super(INetwork, self).__init__()
        
        self._ipolicy = gs.Behavior(drop)
        self._ingress_predicate = gs.Behavior(all_packets)
        self._egress_predicate = gs.Behavior(no_packets)
        
        for b in [self._policy, self._ingress_predicate, self._egress_predicate]:
            b.notify(self._handle_changes)
        
    ingress_predicate = gs.Behavior.property("_ingress_predicate")
    egress_predicate = gs.Behavior.property("_egress_predicate")
    
    def connect(self, network):
        """different than base"""
        @self._ipolicy.notify
        def change(policy):
            network.install_sub_policy(self, policy)

    def sync_with_topology(self):
        @self._topology.notify
        def handle(topology):
            self.egress_predicate = union(match(switch=l.switch,outport=l.port) 
                                          for l in topology.egress_locations())
            
    def _handle_changes(self, item):
        self._ipolicy.set(self._aggregate_ipolicy())

    def _aggregate_ipolicy(self):
        return isolate_policy(id(self),
                              self.policy,
                              self.ingress_predicate,
                              self.egress_predicate)

    @property
    def ipolicy(self):
        return self._ipolicy.get()
        
    @property
    def ipolicy_changes(self):
        return iter(self._ipolicy)

################################################################################
# Virtualization policies 
################################################################################

class physical_to_virtual(DerivedPolicy, Data("vtag")):
    def __repr__(self):
        return "physical_to_virtual %s" % self.vtag
        
    def get_policy(self):
        return (push(vtag=self.vtag) >> copy(voutport="outport",
                                             vswitch="switch",
                                             vinport="inport"))
        
@singleton
class virtual_to_physical(DerivedPolicy):
    def __repr__(self):
        return "virtual_to_physical"
        
    def get_policy(self):
         return (pop(["switch", "inport", "outport", "vtag"]) >>
                 copy(outport="voutport", switch="vswitch", inport="vinport"))
         

@singleton
class pop_vheaders(DerivedPolicy):
    def __repr__(self):
        return "pop_vheaders"
        
    def get_policy(self):
        return pop(["vswitch", "vinport", "voutport", "vtag"])

    
class virtualize_policy(DerivedPolicy, Data("vtag policy ingress_policy physical_policy_fn query_policy_fn")):
    def __repr__(self):
        return "virtualize_policy %s\n%s" % (self.vtag, util.repr_plus(["POLICY",
                                                                        self.policy,
                                                                        "INGRESS POLICY", 
                                                                        self.ingress_policy,
                                                                        "PHYSICAL POLICY", 
                                                                        self.physical_policy_fn(self),
                                                                        "QUERY POLICY",
                                                                        self.query_policy_fn(self)]))

    def get_policy(self):
        # if the vlan isnt set, then we need to find out the v* headers.
        pol = (if_(~match(vtag=self.vtag), 
                    (self.ingress_policy >> # set vswitch and vinport
                     # now make the virtualization transparent to the tenant's policy to get the outport
                     copy(switch="vswitch", inport="vinport") >>
                     self.policy >>
                     physical_to_virtual(self.vtag)))
                # Pipe the packet with appropriate v* headers to the physical policy for processing
                >> if_(is_bucket("voutport"),
                       self.query_policy_fn(self),
                       self.physical_policy_fn(self)))
        return pol
        
def add_nodes_from_vmap(vmap, vtopo):
    for switch, port_no in vmap:
        port = Port(port_no,'UP')
        try:
            vtopo.node[switch]['ports'][port_no] = port 
        except KeyError:
            vtopo.add_node(switch, ports={port_no: port})
    
def vmap_to_ingress_policy(vmap):
    ingress_policy = parallel(push(vswitch=vsw, vinport=vp) &
                            union(match(switch=sw, inport=p) for (sw, p) in switches)
                            for ((vsw, vp), switches) in vmap.iteritems())
    return ingress_policy

def vmap_to_egress_policy(vmap):
    matches_egress = []
    valid_match_egress = []
    for ((vsw, vp), switches) in vmap.iteritems():
        switch_pred = union(match(switch=sw, outport=p) for (sw, p) in switches)
        matches_egress.append(switch_pred)
        valid_match_egress.append(match(vswitch=vsw, voutport=vp) & switch_pred)
    return if_(union(matches_egress), union(valid_match_egress) & pop_vheaders, passthrough)
        
class VNetwork(Network):
    def __init__(self,backend):
        super(VNetwork, self).__init__(backend)
        
        self._vpolicy = gs.Behavior(drop)
        self._ingress_policy = gs.Behavior(drop)
        self._physical_policy = gs.Behavior(drop)
        self._egress_policy = gs.Behavior(no_packets)
        
        for b in [self._policy, self._ingress_policy,
                  self._physical_policy, self._egress_policy]:
            b.notify(self._handle_changes)

    @property
    def vpolicy(self):
        return self._vpolicy.get()
    
    ingress_policy = gs.Behavior.property("_ingress_policy")
    physical_policy = gs.Behavior.property("_physical_policy")
    egress_policy = gs.Behavior.property("_egress_policy")

    @classmethod
    def fork(cls, network):
        """different than base"""
        self = cls(network.backend)
        self.init_events()
        self.connect(network)
        return self

    def connect(self, network):
        """different than base"""
        @self._vpolicy.notify
        def change(policy):
            network.install_sub_policy(self, policy)

    def from_vmap(self, vmap):
        self.ingress_policy = vmap_to_ingress_policy(vmap)
        self.egress_policy = vmap_to_egress_policy(vmap)

    def _handle_changes(self, item):
        self._vpolicy.set(self._aggregate_vpolicy())

    def _aggregate_vpolicy(self):
        if isinstance(self.physical_policy, Policy):
            physical_policy = lambda rev: self.physical_policy
        else:
            assert callable(self.physical_policy), "must be a function or policy"
            physical_policy = self.physical_policy
            
        return virtualize_policy(id(self),
                                 self.policy,
                                 self.ingress_policy,
                                 lambda rev: physical_policy(rev) >> self.egress_policy,
                                 lambda rev: virtual_to_physical)
    @property
    def vpolicy_changes(self):
        return iter(self._vpolicy)
