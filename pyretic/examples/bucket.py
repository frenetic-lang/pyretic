
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
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
# mininet: mininet.sh --topo=single,3                                          #
# pyretic: pyretic.py pyretic.examples.bucket -m p0                            #
# test:    `h_i ping h_j` produce increasing (packet/byte) counts every        #
#          10 seconds in buckets b_i.                                          #
#          In i/r0 modes, reported counts from switches are always 0.          #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner

import time
from datetime import datetime

# define some globals for use in various functions
ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')

fwding = ( (match(dstip=ip1) >> fwd(1)) +
           (match(dstip=ip2) >> fwd(2)) +
           (match(dstip=ip3) >> fwd(3)) )

class QueryTest(CountBucket):
    
    def __init__(self):
        super(QueryTest, self).__init__()
        self.register_callback(self.query_callback)
        import threading
        self.query_thread = threading.Thread(target=self.query_thread)
        self.query_thread.daemon = True
        self.query_thread.start()

    def query_thread(self):
        """Thread that issues stats queries every 10 seconds."""
        interval = 2.5
        while True:
            output = str(datetime.now()) + "| bucket " + str(id(self)) + ": print matches\n"
            for m in self.matches:
                output += str(m) + '\n'
            self.pull_stats()
            # print output
            print ">>>", str(datetime.now()), ('issued query %d, sleeping for %f' %
                                               (id(self), interval))
            time.sleep(interval)

    def query_callback(self, counts):
        print "***", str(datetime.now()), "| In user callback for bucket",
        print id(self)
        print "(packet, byte) counts:", counts
        print "-----------------------------------"

def test0():
    """Tests a single bucket that counts all packets.

    Check correctness of bucket counts with the following wireshark capture
    filters after starting capture on the _any_ interface. You may have to
    change the x11 port in the filter below (typically 6010, but may vary --
    verify from outputs of netstat or lsof on the terminal).

    (not (ip.addr==192.168.0.0/16 or tcp.port==6010 or (tcp.port==6633 and not
    of) or tcp.port==41414 or sll.pkttype==4) and (ip.addr == 10.0.0.0/16 or
    arp or of.pktin) )

    Here including packets with ip.addr in 10.0 subnet and ARPs is a proxy for
    all packets which hit openflow rules on the switch -- which are those that
    are counted by the query.

    If there are no openflow packet-ins, the number of packets displayed is, in
    fact, the right bucket count. Otherwise, you need to inspect the packet-ins
    to see which of those satisfy the filters in matching filters
    below. (Currently there is no way to specify wireshark capture filters on
    headers of packets sent to the controller as part of packet-in eventsfrom
    switches.)

    These filters should continue to work with dynamic topology and policy
    updates. However, counting must be done carefully when there are openflow
    packet-ins.
    """
    test_bucket = QueryTest()
    return test_bucket

def test1():
    """Tests a single match that is counted.

    Display filter for checking correctness:

    (not (ip.addr==192.168.0.0/16 or tcp.port==6010 or (tcp.port==6633 and not
    of) or tcp.port==41414 or sll.pkttype==4) ) and ( ( (ip.src == 10.0.0.1 ||
    (arp && (arp.src.proto_ipv4 == 10.0.0.1 ) ) ) ) || of.pktin )
    """
    test_bucket = QueryTest()
    return (match(srcip=ip1) >> test_bucket)

def test2():
    """Tests buckets containing multiple matches for traffic.

    Display filters for checking correctness:

    bucket 0:
    (not (ip.addr==192.168.0.0/16 or tcp.port==6010 or (tcp.port==6633 and not
    of) or tcp.port==41414 or sll.pkttype==4) ) and ( ( (ip.src == 10.0.0.1 ||
    ip.src == 10.0.0.3 || (arp && (arp.src.proto_ipv4 == 10.0.0.1 ||
    arp.src.proto_ipv4 == 10.0.0.3) ) ) ) || of.pktin )

    bucket 1:

    (not (ip.addr==192.168.0.0/16 or tcp.port==6010 or (tcp.port==6633 and not
    of) or tcp.port==41414 or sll.pkttype==4) ) and ( ( (ip.src == 10.0.0.2 ||
    (arp && (arp.src.proto_ipv4 == 10.0.0.2 ) ) ) ) || of.pktin )

    """
    b = [] # counting buckets
    for i in range(0,2):
        b.append(QueryTest())
        time.sleep(0.2)

    pol1 = match(srcip=ip1) >> b[0]
    pol2 = match(srcip=ip2) >> b[1]
    pol3 = match(srcip=ip3) >> b[0]

    return pol1 + pol2 + pol3

def test3():
    """Test if the same traffic feeding into multiple buckets gets accounted
    correctly.

    Display filters for checking correctness:

    Buckets 0 and 1:
    (not (ip.addr==192.168.0.0/16 or tcp.port==6010 or (tcp.port==6633 and not
    of) or tcp.port==41414 or sll.pkttype==4) ) and ( (ip.src == 10.0.0.1 and
    ip.dst == 10.0.0.2) || (arp && arp.src.proto_ipv4 == 10.0.0.1 &&
    arp.dst.proto_ipv4 == 10.0.0.2 ) || of.pktin )

    Bucket 2:
    (not (ip.addr==192.168.0.0/16 or tcp.port==6010 or (tcp.port==6633 and not
    of) or tcp.port==41414 or sll.pkttype==4) ) and ( (ip.src == 10.0.0.1 and
    ip.dst == 10.0.0.3) || (arp && arp.src.proto_ipv4 == 10.0.0.1 &&
    arp.dst.proto_ipv4 == 10.0.0.3 ) || of.pktin )
    """
    b = [] # counting buckets
    for i in range(0,3):
        b.append(QueryTest())
        time.sleep(0.2)

    query1 = match(srcip=ip1) >> match(dstip=ip2) >> b[0]
    query2 = match(srcip=ip1) >> match(dstip=ip2) >> b[1]
    query3 = match(srcip=ip1) >> match(dstip=ip3) >> b[2]

    return query1 + query2 + query3

def test4():
    """Test policy negation, but only for IP traffic.

    Display filter for checking correctness:

    (not (ip.addr==192.168.0.0/16 or tcp.port==6010 or (tcp.port==6633 and not
    of) or tcp.port==41414 or sll.pkttype==4) ) and ( ( (not ip.src == 10.0.0.1)
    and ( ip.dst == 10.0.0.1 || ip.dst == 10.0.0.2 || ip.dst == 10.0.0.3) ) ||
    (arp && (not arp.src.proto_ipv4 == 10.0.0.1) && (arp.dst.proto_ipv4 ==
    10.0.0.1 || arp.dst.proto_ipv4 == 10.0.0.2 || arp.dst.proto_ipv4 ==
    10.0.0.3) ) || of.pktin )
    """
    test_bucket = QueryTest()
    matched_traffic = ( (~match(srcip=ip1) & match(dstip=ip2)) +
                        (~match(srcip=ip1) & match(dstip=ip3)) +
                        (~match(srcip=ip1) & match(dstip=ip1)) )
    return (matched_traffic >> test_bucket)

def test5():
    """Test policy negation covering all other traffic.

    Display filter for checking correctness:

    (not (ip.addr==192.168.0.0/16 or (arp and (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or (of
    and not of.pktin) or ip.addr == 10.0.2.0/24 or (arp && ( arp.src.proto_ipv4
    == 10.0.2.0/24 or arp.dst.proto_ipv4 == 10.0.2.0/24 ) ) ) ) and (not ( (ip
    && ip.src == 10.0.0.1 ) or (arp && arp.src.proto_ipv4 == 10.0.0.1) or ipv6))
    """
    test_bucket = QueryTest()
    matched_traffic = ~match(srcip=ip1)
    return (matched_traffic >> test_bucket)

def test6():
    """Ensure no double counting of packets destined to controller."""
    return ( (match(dstip=ip1) >> QueryTest()) +
             (match(dstip=ip1) >> Controller) )

def main():
    return test0() + fwding
