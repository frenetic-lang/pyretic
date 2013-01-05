
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
# start mininet:  sudo mn -c; sudo mn --switch ovsk --controller remote --mac --topo linear,4                                #
# run controller: pox.py --no-cli pyretic/examples/arp.py                                                                    #
# run pingall:    once or twice, clear a node's arp entry for one of its neighbors - e.g., h1 arp -d h2 - and ping           # 
# test:           NO RESPONSE AVAILABLE message should only show up once for each end host IP address                        #
##############################################################################################################################

import collections

from frenetic.lib import *
from examples import hub_restricted


ARP_TYPE = 2054
VERBOSE_LEVEL = 1


### THIS IS A BIT LAZY, WE COPY PACKET AND ONLY OVERRIDE NECESSARY FIELDS
def send_response(network,pkt,switch,outport,dstip=None,dstmac=None):

    response_packet = Packet(pkt.header)
    response_packet = response_packet.pop('switch')
    response_packet = response_packet.push(switch=switch)
    response_packet = response_packet.push(outport=outport)
    if not dstip is None:
        response_packet = response_packet.pop('dstip')
        response_packet = response_packet.push(dstip=dstip)
        response_packet = response_packet.pop('dstmac')
        response_packet = response_packet.push(dstmac=dstmac)

    if response_packet['inport'] == outport:
        fake_inports = [l.port for l in network.topology.interior_locations(switch)] 
        response_packet = response_packet.pop('inport')
        try:
            response_packet = response_packet.push(inport=fake_inports[0])
        except IndexError:
            print "All ports on switch %s are currently reported as egress ports!\nWill try incrementing the inport.\n(bug in some switches does not allow packets to be sent out the same outport as they reportedly came in...)"
            response_packet = response_packet.push(inport=outport+1)


    if VERBOSE_LEVEL > 0:
        print "--------- INJECTING RESPONSE -----------"
        if VERBOSE_LEVEL > 1:
            print response_packet

    network.inject_packet(response_packet)


### USING STRING CASTING TO MAKE SURE PACKET FIELDS ACT LIKE PROPER DICT KEYS
### THIS IS A HACK AND SHOULD BE FIXED
def arp(network):

    arp_packets = match([('type',ARP_TYPE)])

    request_packets = {}
    known_ips = {}
    response_packets = {}
    outstanding_requests = collections.defaultdict(dict)

    for pkt in query(network, arp_packets):

        switch = pkt['switch']
        inport = pkt['inport']
        srcmac = pkt['srcmac']
        srcip  = pkt['srcip']
        dstmac = str(pkt['dstmac'])
        dstip  = str(pkt['dstip'])

        known_ips[str(srcip)] = Location(switch,inport)

        if dstmac == 'ff:ff:ff:ff:ff:ff':
            request_packets[dstip] = pkt

            if dstip in response_packets:

                if VERBOSE_LEVEL > 0:
                    print "RECEIVED REQUEST FOR %s FROM %s, RESPONSE AVAILABLE" % (dstip,srcip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                response_pkt = response_packets[dstip]
                send_response(network,response_pkt,switch,inport,srcip,srcmac)
            else:

                if VERBOSE_LEVEL > 0:
                    print "RECEIVED REQUEST FOR %s FROM %s, NO RESPONSE AVAILABLE" % (dstip,srcip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                outstanding_requests[str(srcip)][dstip] = True
                for loc in network.topology.egress_locations() - {Location(switch,inport)}:
                    request_packet = Packet(pkt.header)
                    request_packet = request_packet.pop('switch')
                    request_packet = request_packet.push(switch=loc.switch)
                    request_packet = request_packet.push(outport=loc.port)
                    
                    if request_packet['inport'] == loc.port:
                        fake_inports = [l.port for l in network.topology.interior_locations(loc.switch)] 
                        request_packet = request_packet.pop('inport')
                        try:
                            request_packet = request_packet.push(inport=fake_inports[0])
                        except IndexError:
                            print "All ports on switch %s are currently reported as egress ports!\nWill try incrementing the inport.\n(bug in some switches does not allow packets to be sent out the same outport as they reportedly came in...)"
                            request_packet = request_packet.push(inport=loc.port+1)


                    if VERBOSE_LEVEL > 0:
                        print "--------- INJECTING REQUEST -----------"
                        if VERBOSE_LEVEL > 1:
                            print request_packet
                            
                    network.inject_packet(request_packet)
        else:
            try:
                del outstanding_requests[dstip][str(srcip)]

                if VERBOSE_LEVEL > 0:
                    print "OUTSTANDING RESPONSE for %s to %s" % (srcip,dstip)
                    if VERBOSE_LEVEL > 1:
                        print pkt

                response_packets[str(srcip)] = pkt
                loc = known_ips[dstip]
                send_response(network,pkt,loc.switch,loc.port)
            except:

                if VERBOSE_LEVEL > 1:
                    print "IGNORABLE RESPONSE for %s to %s" % (srcip,dstip)
                    print pkt
                pass


        

            
    

def example(network):
    run(hub_restricted.hub, Network.fork(network))
    run(arp, Network.fork(network))

main = example


