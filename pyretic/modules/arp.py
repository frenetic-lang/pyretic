
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
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

##############################################################################################################################
# TO TEST MODULE                                                                                                             #
# -------------------------------------------------------------------                                                        #
# run controller: pox.py --no-cli PATH_TO_THIS_MODULE                                                                        #
# start mininet:  pyretic/mininet.sh --topo cycle,4,4                                                                        #
# run pingall:    once or twice, clear a node's arp entry for one of its neighbors - e.g., h1 arp -d h2 - and ping           # 
# test:           NO RESPONSE AVAILABLE message should only show up once for each end host IP address                        #
##############################################################################################################################

import collections

from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.modules.mac_learner import mac_learner

VERBOSE_LEVEL = 1
ARP = match(ethtype=ARP_TYPE)
REQUEST=1
RESPONSE=2

def send_arp(msg_type,network,switch,outport,srcip,srcmac,dstip,dstmac):
    """Construct an arp packet from scratch and send"""
    rp = Packet()
    rp = rp.push(protocol=msg_type)
    rp = rp.push(ethtype=ARP_TYPE)
    rp = rp.push(switch=switch)
    rp = rp.push(inport=-1)
    rp = rp.push(outport=outport)
    rp = rp.push(srcip=srcip)
    rp = rp.push(srcmac=srcmac)
    rp = rp.push(dstip=dstip)
    rp = rp.push(dstmac=dstmac)
    rp = rp.push(payload='')

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
    known_ip = parallel([ match(dstip=ip)[modify(dstmac=mac)] for (ip,mac) in mac_of.iteritems() ])
    unknown_ip = ~dstip_in(mac_of.keys())
    return known_ip | unknown_ip[passthrough]


@dynamic
def arp(self,mac_of={}):
    """Respond to arp request for any known hosts,
       learn macs of unknown hosts, rewrite macs based on dstip"""
    location_of = {}
    outstanding_requests = collections.defaultdict(dict)

    def handle_arp(pkt):
        switch = pkt['switch']
        inport = pkt['inport']
        srcip  = pkt['srcip']
        srcmac = pkt['srcmac']
        dstip  = pkt['dstip']
        dstmac = pkt['dstmac']
        opcode = pkt['protocol']

        # RECORD THE LOCATION AT WHICH THIS NODE IS ATTACHED TO THE NETWORK
        if not srcip in location_of:
            location_of[srcip] = Location(switch,inport)

        # IF THIS PACKET IS A REQUEST
        if opcode == 1:
            if dstip in mac_of:
                if VERBOSE_LEVEL > 0:
                    print "RECEIVED REQUEST FOR %s FROM %s, KNOWN HOST" % (dstip,srcip)
                    if VERBOSE_LEVEL > 1:
                        print pkt
                send_arp(RESPONSE,self.network,switch,inport,dstip,mac_of[dstip],srcip,srcmac)
            else:
                if VERBOSE_LEVEL > 0:
                    print "RECEIVED REQUEST FOR %s FROM %s, UNKNOWN HOST" % (dstip,srcip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                # LEARN MAC
                mac_of[srcip] = srcmac  

                # FORWARD REQUEST OUT OF ALL EGRESS PORTS
                outstanding_requests[srcip][dstip] = True
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
                del outstanding_requests[dstip][srcip]

                if VERBOSE_LEVEL > 0:
                    print "OUTSTANDING RESPONSE FOR %s TO %s" % (srcip,dstip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                # LEARN MAC
                mac_of[srcip] = srcmac
                loc = location_of[dstip]
                send_arp(RESPONSE,self.network,loc.switch,loc.port_no,srcip,mac_of[srcip],dstip,mac_of[dstip])
            except:

                if VERBOSE_LEVEL > 1:
                    print "IGNORABLE RESPONSE FOR %s TO %s" % (srcip,dstip)
                    print pkt
                pass

    self.query = packets()
    self.query.register_callback(handle_arp)
    self.policy = self.query


def arp_and_mac_learn():
    """Handle ARPs and do MAC learning"""
    return if_(ARP,arp(),mac_learner())


def main():
    return arp_and_mac_learn()



