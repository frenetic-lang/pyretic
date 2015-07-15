
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
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

################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet:  mininet.sh --topo cycle,4,4 (or other single subnet)               #
# test:     ping a neighbor - e.g., h1 ping -c5 h2                             #
#           then clear the arp entry for that neighbor - e.g., h1 arp -d h2    #
#           "NO RESPONSE AVAILABLE" message for h2 should only show up once    #
################################################################################

import collections

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

from pyretic.modules.mac_learner import mac_learner

VERBOSE_LEVEL = 1
ARP = match(ethtype=ARP_TYPE)
REQUEST=1
RESPONSE=2

def send_arp(msg_type,network,switch,outport,srcip,srcmac,dstip,dstmac):
    """Construct an arp packet from scratch and send"""
    rp = Packet()
    rp = rp.modify(protocol=msg_type)
    rp = rp.modify(ethtype=ARP_TYPE)
    rp = rp.modify(switch=switch)
    rp = rp.modify(port=outport)
    rp = rp.modify(srcip=srcip)
    rp = rp.modify(srcmac=srcmac)
    rp = rp.modify(dstip=dstip)
    rp = rp.modify(dstmac=dstmac)
    rp = rp.modify(raw='')

    if VERBOSE_LEVEL > 0:
        if msg_type == RESPONSE:
            print "--------- INJECTING RESPONSE ON %d[%d] FOR %s TO %s -----------" % (switch,outport,srcip,dstip)
        if msg_type == REQUEST:
            print "--------- INJECTING REQUEST ON %d[%d] FOR %s FROM %s -----------" % (switch,outport,dstip,srcip)
        if VERBOSE_LEVEL > 1:
            print rp

    network.inject_packet(rp)


def translate(mac_of={}):
    """Translate dstmac based on input IP/MAC mapping"""
    known_ip = parallel([ match(dstip=ip) >> modify(dstmac=mac) 
                          for (ip,mac) in mac_of.iteritems() ])
    unknown_ip = ~dstip_in(mac_of.keys())
    return known_ip + unknown_ip


class arp(DynamicPolicy):
    """Respond to arp request for any known hosts,
       learn macs of unknown hosts, rewrite macs based on dstip"""
    def __init__(self,mac_of={}):
        self.mac_of = mac_of
        self.location_of = {}
        self.outstanding_requests = collections.defaultdict(dict)
        self.query = packets()
        self.query.register_callback(self.handle_arp)
        self.network = None
        super(arp,self).__init__(self.query)

    def set_network(self, network):
        self.network = network

    def handle_arp(self,pkt):
        switch = pkt['switch']
        inport = pkt['port']
        srcip  = pkt['srcip']
        srcmac = pkt['srcmac']
        dstip  = pkt['dstip']
        dstmac = pkt['dstmac']
        opcode = pkt['protocol']

        # RECORD THE LOCATION AT WHICH THIS NODE IS ATTACHED TO THE NETWORK
        if not srcip in self.location_of:
            self.location_of[srcip] = Location(switch,inport)

        # IF THIS PACKET IS A REQUEST
        if opcode == 1:
            if dstip in self.mac_of:
                if VERBOSE_LEVEL > 0:
                    print "RECEIVED REQUEST FOR %s FROM %s, KNOWN HOST" % (dstip,srcip)
                    if VERBOSE_LEVEL > 1:
                        print pkt
                send_arp(RESPONSE,self.network,switch,inport,dstip,self.mac_of[dstip],srcip,srcmac)
            else:
                if VERBOSE_LEVEL > 0:
                    print "RECEIVED REQUEST FOR %s FROM %s, UNKNOWN HOST" % (dstip,srcip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                # LEARN MAC
                self.mac_of[srcip] = srcmac  

                # FORWARD REQUEST OUT OF ALL EGRESS PORTS
                self.outstanding_requests[srcip][dstip] = True
                if self.network is None:
                    return

                for loc in self.network.topology.egress_locations() - {Location(switch,inport)}:
                    switch  = loc.switch
                    outport = loc.port_no
                    srcip   = pkt['srcip']
                    srcmac  = pkt['srcmac']
                    dstip   = pkt['dstip']
                    dstmac  = pkt['dstmac']
                    send_arp(REQUEST,self.network,switch,outport,srcip,srcmac,dstip,dstmac)

        # THIS IS A RESPONSE THAT WE WILL ALSO LEARN FROM
        elif opcode == 2:
            try:
                del self.outstanding_requests[dstip][srcip]

                if VERBOSE_LEVEL > 0:
                    print "OUTSTANDING RESPONSE FOR %s TO %s" % (srcip,dstip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                # LEARN MAC
                self.mac_of[srcip] = srcmac
                loc = self.location_of[dstip]
                send_arp(RESPONSE,self.network,loc.switch,loc.port_no,srcip,self.mac_of[srcip],dstip,self.mac_of[dstip])
            except:

                if VERBOSE_LEVEL > 1:
                    print "IGNORABLE RESPONSE FOR %s TO %s" % (srcip,dstip)
                    print pkt
                pass    

def arp_and_flood():
    """Handle ARPs and do MAC learning"""
    return if_(ARP,arp(),flood())

def arp_and_mac_learn():
    """Handle ARPs and do MAC learning"""
    return if_(ARP,arp(),mac_learner())

def main():
    return arp_and_flood()



