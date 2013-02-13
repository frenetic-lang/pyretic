
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

##############################################################################################################################
# TO TEST EXAMPLE                                                                                                            #
# -------------------------------------------------------------------                                                        #
# start mininet:  pyretic/mininet.sh --topo cycle,4,4                                                                        #
# run controller: pox.py --no-cli pyretic/examples/arp.py                                                                    #
# run pingall:    once or twice, clear a node's arp entry for one of its neighbors - e.g., h1 arp -d h2 - and ping           # 
# test:           NO RESPONSE AVAILABLE message should only show up once for each end host IP address                        #
##############################################################################################################################

import collections

from frenetic.lib import *
from examples.learning_switch import learning_switch


ARP_TYPE = 2054
VERBOSE_LEVEL = 1
ARP = match([('type',ARP_TYPE)])

def send_arp_response(network,switch,outport,srcip,srcmac,dstip,dstmac):
    """Construct an arp packet from scratch and send"""

    rp = Packet()
    rp = rp.push(protocol=2)
    rp = rp.pushmany({'type' : 2054})
    rp = rp.push(switch=switch)
    rp = rp.push(outport=outport)
    rp = rp.push(inport=outport+1)
    rp = rp.push(srcip=srcip)
    rp = rp.push(srcmac=srcmac)
    rp = rp.push(dstip=dstip)
    rp = rp.push(dstmac=dstmac)
    rp = rp.push(payload='')

    if VERBOSE_LEVEL > 0:
        print "--------- INJECTING RESPONSE -----------"
        if VERBOSE_LEVEL > 1:
            print rp

    # XXX
    network.inject_packet(rp)


### USING STRING CASTING TO MAKE SURE PACKET FIELDS ACT LIKE PROPER DICT KEYS
### THIS IS A HACK AND SHOULD BE FIXED
@dynamic
def arp(self,mac_of={}):
    """Respond to arp request for any hosts in mac_of,
       learn macs of unknown hosts"""

    location_of = {}
    outstanding_requests = collections.defaultdict(dict)
    this = self

    @self.query(ARP)
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
            

        # GET THE NETWORK OBJECT
        network = None
        for n in this.networks:
            network = n
            break

        # IF THIS PACKET IS A REQUEST
        
        if opcode == 1:
            if dstip in mac_of:
                if VERBOSE_LEVEL > 0:
                    print "RECEIVED REQUEST FOR %s FROM %s, RESPONSE AVAILABLE" % (dstip,srcip)
                    if VERBOSE_LEVEL > 1:
                        print pkt
                send_arp_response(network,switch,inport,dstip,mac_of[dstip],srcip,srcmac)
            else:
                if VERBOSE_LEVEL > 0:
                    print "RECEIVED REQUEST FOR %s FROM %s, NO RESPONSE AVAILABLE" % (dstip,srcip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                # LEARN MAC
                mac_of[srcip] = srcmac  

                # FORWARD REQUEST OUT OF ALL EGRESS PORTS
                outstanding_requests[srcip][dstip] = True
                for loc in network.topology.egress_locations() - {Location(switch,inport)}:
                    # Can this just be send_response?
                    rq = Packet(pkt.header)
                    rq = rq.pop('switch')
                    rq = rq.push(switch=loc.switch)
                    rq = rq.push(outport=loc.port_no)
                    if rq['inport'] == loc.port_no:
                        rq = rq.push(inport=loc.port_no+1)

                    if VERBOSE_LEVEL > 0:
                        print "--------- INJECTING REQUEST -----------"
                        if VERBOSE_LEVEL > 1:
                            print rq
                            
                    network.inject_packet(rq)

        # THIS IS A RESPONSE THAT WE WILL ALSO LEARN FROM
        elif opcode == 2:
            try:
                del outstanding_requests[dstip][srcip]

                if VERBOSE_LEVEL > 0:
                    print "OUTSTANDING RESPONSE for %s to %s" % (srcip,dstip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                mac_of[srcip] = srcmac
                loc = location_of[dstip]
                send_arp_response(network,loc.switch,loc.port_no,srcip,mac_of[srcip],dstip,mac_of[dstip])
            except:

                if VERBOSE_LEVEL > 1:
                    print "IGNORABLE RESPONSE for %s to %s" % (srcip,dstip)
                    print pkt
                pass

def learn_arp():
    return if_(ARP,arp(),learning_switch())

def pre_specified_arp():
    mac_of = { IP('10.0.0.'+str(i)) : MAC('00:00:00:00:00:0'+str(i)) for i in range(1,9) }
    return if_(ARP,arp(mac_of),learning_switch())


def main():
    return learn_arp()
#    return pre_specified_arp()



