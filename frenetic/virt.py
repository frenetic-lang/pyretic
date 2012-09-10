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
from frenetic.netcore import _

################################################################################
# Network
################################################################################

class Network(object):
    def __init__(self):
        self.switch_joins = gs.Event()
        self.switch_parts = gs.Event()
        
        self.policy_b = gs.Behavior(drop)
        self.policy_changes = self.policy_b # used only for iter method
        self.sub_policies = {}
        
        super(Network, self).__init__()

    def query(self, pred, fields=(), time=None):
        b = Bucket(fields, time)
        b.sub_network = fork_sub_network(self)
        b.sub_network.install_policy(pred & fwd(b))
        return b
        
    def install_policy(self, policy):
        self.sub_policies[self] = policy
        self.policy_b.set(self._aggregate_policy())
        
    def get_policy(self):
        return self.policy_b.get()

    def install_sub_policies(self, sub_gen):
        it = iter(sub_gen) # Don't leave creating the iterator up to timing.
        def adder():
            for policy in it:
                self.sub_policies[sub_gen] = policy
                self.policy_b.set(self._aggregate_policy())
        gs.run(adder)
    
    def _aggregate_policy(self):
        pol = drop
        for policy in self.sub_policies.itervalues():
            pol |= policy
        return pol
        
def add_sub_network(super_network, sub_network):
    super_network.install_sub_policies(sub_network.policy_changes)
        
def fork_sub_network(network):
    sub_net = Network()
    sub_net.switch_joins = network.switch_joins
    sub_net.switch_parts = network.switch_parts

    add_sub_network(network, sub_net)
    
    return sub_net


################################################################################
# Virtualization
################################################################################

def fork_virtual_network(network, vinfo, ingress_policy, physical_policy):
    sub_net = Network()
    vlan_db = generate_vlan_db(0, vinfo)

    network.install_sub_policies(
        virtualize_policy(vlan_db, ingress_policy, physical_policy, policy)
        for policy in sub_net.policy_changes)
    
    return sub_net

def generate_vlan_db(start_vlan, vinfo):
    vlan_to_vheaders = {}
    vheaders_to_vlan = {}
    
    for si, vswitch in enumerate(vinfo):
        for ipi, vinport in enumerate(vinfo[vswitch]):
            for opi, voutport in enumerate(vinfo[vswitch]):
                vlan_to_vheaders[start_vlan + si + ipi + opi] = (vswitch, vinport, voutport)
                vheaders_to_vlan[(vswitch, vinport, voutport)] = start_vlan + si + ipi + opi

    return (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan)

def vheaders_to_vlan_policy(vlan_db):
    (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan) = vlan_db
    
    return ((_.vswitch.is_missing() & modify(vlan=None) # if we are no longer virtualized, remove vlan.
            | enum((_.vswitch, vinfo.iterkeys()), # otherwise, encode.
                   lambda s:
                   enum((_.vinport, vinfo[s]),
                        (_.voutport, vinfo[s]),
                        lambda ip, op: modify(vlan=vheaders_to_vlan[(s, ip, op)]))))
            >> modify(vswitch=None,
                      vinport=None,
                      voutport=None))
    
def vlan_to_vheaders_policy(vlan_db):
    (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan) = vlan_db

    def vlan_dict_helper(vlan):
        (vswitch, vinport, voutport) = vlan_to_vheaders[vlan]
        return modify(vswitch=vswitch, vinport=vinport, voutport=voutport)
    
    return (enum((_.vlan, vlan_to_vheaders.iterkeys()), vlan_dict_helper) >>
            modify(vlan=None))
    
def pre_vheaders_to_headers_policy(vlan_db):
    (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan) = vlan_db
    
    return (enum((_.vswitch, vinfo.iterkeys()), 
                 lambda s:
                 enum((_.vinport, vinfo[s]),
                      lambda ip: modify(switch=s,
                                        inport=ip)))
            >> modify(vswitch=None,
                      vinport=None))

def headers_to_post_vheaders(vlan_db, x):
    (vinfo, start_vlan, vlan_to_vheaders, vheaders_to_vlan) = vlan_db
    
    return enum((x.switch, vinfo.iterkeys()),
                lambda s:
                enum((x.outport, vinfo[s]),
                     lambda op: modify(voutport=op)))
        
def virtualize_policy(vlan_db, ingress_policy, physical_policy, policy):
    """
    - `vinfo' is a mapping from switch to set of ports.
    - `start_vlan, ...` - see generate_vlan_db
    - `ingress_policy' is written in terms of the physical network, and tries to
       detect whether a packet is at the ingress of a virtual switch. If the packet
       is at the ingress of a virtual switch, then modify the vswitch and vinport of the
       packet to be the current virtual switch and the inport we are at, respectively .
    - `policy' is written in terms of the virtual network, and modifies the outport field.
       We will modify the voutport of the packet to be the outport returned.
    - `physical_policy' is written in terms of the physical network, and tries to
       forward packets along the fabric of the virtual switch until voutport is reached.
       When the packet leaves vswitch, the v* headers must be removed.

       (Implementation detail: removing vswitch is sufficient).

    Returns the virtualization of `policy' with respect to the other parameters.
    """

    return (if_(_.vlan.is_missing(), # if the vlan isnt set, then we need to find out the v* headers.
                    (ingress_policy >> # set vswitch and vinport
                    # now make the virtualization transparent to the tenant's policy to get the outport
                     let(pre_vheaders_to_headers_policy(vlan_db) >> policy,
                         lambda x: headers_to_post_vheaders(vlan_db, x))),
                  # However, if vlan IS set, re-set the v* headers.
                  vlan_to_vheaders_policy(vlan_db))
            # Pipe the packet with appropriate v* headers to the physical policy for processing
            >> physical_policy
            # and translate the v* headers to a vlan value, since the real network
            # doesn't understand our custom headers.
            >> vheaders_to_vlan_policy(vlan_db))
          
