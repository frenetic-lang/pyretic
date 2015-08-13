
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
#          Check under each test function for specific testing instructions.   #
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

def static_fwding_single_2():
    return ( (match(dstip=ip1) >> fwd(1)) +
             (match(dstip=ip2) >> fwd(2)) )

def static_fwding_single_3():
    return ( (match(dstip=ip1) >> fwd(1)) +
             (match(dstip=ip2) >> fwd(2)) +
             (match(dstip=ip3) >> fwd(3)) )

def static_fwding_cycle_3_3():
    return ( (match(dstip=ip1) >> match(switch=1) >> fwd(3)) +
             (match(dstip=ip1) >> match(switch=2) >> fwd(1)) +
             (match(dstip=ip1) >> match(switch=3) >> fwd(2)) +
             (match(dstip=ip2) >> match(switch=1) >> fwd(1)) +
             (match(dstip=ip2) >> match(switch=2) >> fwd(3)) +
             (match(dstip=ip2) >> match(switch=3) >> fwd(2)) +
             (match(dstip=ip3) >> match(switch=1) >> fwd(2)) +
             (match(dstip=ip3) >> match(switch=2) >> fwd(1)) +
             (match(dstip=ip3) >> match(switch=3) >> fwd(3)) )

def static_fwding_chain_3_3():
    return (
        (match(dstip=ip1) >> ((match(switch=1) >> fwd(2)) +
                              (match(switch=2) >> fwd(1)) +
                              (match(switch=3) >> fwd(1)))) +
        (match(dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(3)) +
                              (match(switch=3) >> fwd(1)))) +
        (match(dstip=ip3) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(2))))
    )

class QueryTest(CountBucket):
    
    def __init__(self, test_num=None):
        super(QueryTest, self).__init__()
        self.register_callback(self.query_callback)
        self.test_num = test_num if test_num else id(self)
        import threading
        self.query_thread = threading.Thread(target=self.query_thread)
        self.query_thread.daemon = True
        self.query_thread.start()

    def query_thread(self):
        """Thread that issues stats queries every 10 seconds."""
        interval = 5.0
        while True:
            output = str(datetime.now()) + "| bucket " + str(id(self))
            output += ": print matches\n"
            output += self.get_matches()
            # print output
            self.pull_stats()
            print ">>>", str(datetime.now()), ('issued query %s, sleeping for %f' %
                                               (str(self.test_num), interval))
            time.sleep(interval)

    def query_callback(self, counts):
        print "***", str(datetime.now()), "| In user callback for bucket",
        print self.test_num
        print "Bucket", self.test_num, "(packet, byte) counts:", counts
        print "-----------------------------------"

def test0():
    """Tests a single bucket that counts all packets.

    Check correctness of bucket counts with the following wireshark capture
    filters after starting capture on the _any_ interface. You may have to
    change the x11 port in the filter below (typically 6010, but may vary --
    verify from outputs of netstat or lsof on the terminal).

    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) )

    The expected number of packets/bytes printed from the buckets is same as the
    number of packets/bytes displayed by wireshark or tshark with these
    filters. They are designed to work under topology and policy updates.
    """
    test_bucket = QueryTest('0')
    return test_bucket

def test1():
    """Tests a single match that is counted.

    Display filter for checking correctness:

    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and ( ip.src ==
    10.0.0.1 || (arp && arp.src.proto_ipv4 == 10.0.0.1) )
    """
    test_bucket = QueryTest(1)
    return (match(srcip=ip1) >> test_bucket)

def test2():
    """Tests buckets containing multiple matches for traffic.

    Display filters for checking correctness:

    bucket 0:
    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and ( ip.src == 10.0.0.1 ||
    ip.src == 10.0.0.3 )

    bucket 1:
    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and ( ip.src ==
    10.0.0.2 )
    """
    b = [] # counting buckets
    for i in range(0,2):
        b.append(QueryTest('2.b%d' % i))
        time.sleep(0.2)

    pol1 = (match(ethtype=IP_TYPE) & match(srcip=ip1)) >> b[0]
    pol2 = (match(ethtype=IP_TYPE) & match(srcip=ip2)) >> b[1]
    pol3 = (match(ethtype=IP_TYPE) & match(srcip=ip3)) >> b[0]

    return pol1 + pol2 + pol3

def test3():
    """Tests buckets containing multiple matches for traffic.

    Display filters for checking correctness:

    bucket 0:
    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and ( ip.src == 10.0.0.1 ||
    ip.src == 10.0.0.3 || (arp && (arp.src.proto_ipv4 == 10.0.0.1 ||
    arp.src.proto_ipv4 == 10.0.0.3 ) ) )

    bucket 1:
    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and ( ip.src ==
    10.0.0.2 || (arp && arp.src.proto_ipv4 == 10.0.0.2) )
    """
    b = [] # counting buckets
    for i in range(0,2):
        b.append(QueryTest('3.b%d' % i))
        time.sleep(0.2)

    pol1 = match(srcip=ip1) >> b[0]
    pol2 = match(srcip=ip2) >> b[1]
    pol3 = match(srcip=ip3) >> b[0]

    return pol1 + pol2 + pol3

def test4():
    """Test if the same traffic feeding into multiple buckets gets accounted
    correctly.

    Display filters for checking correctness:

    Buckets 0 and 1:
    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and ( (ip.src == 10.0.0.1
    and ip.dst == 10.0.0.2) || (arp && arp.src.proto_ipv4 == 10.0.0.1 &&
    arp.dst.proto_ipv4 == 10.0.0.2 ) )

    Bucket 2:
    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and ( (ip.src == 10.0.0.1
    and ip.dst == 10.0.0.3) || (arp && arp.src.proto_ipv4 == 10.0.0.1 &&
    arp.dst.proto_ipv4 == 10.0.0.3 ) )
    """
    b = [] # counting buckets
    for i in range(0,3):
        b.append(QueryTest('4.b%d' % i))
        time.sleep(0.2)

    query1 = match(srcip=ip1) >> match(dstip=ip2) >> b[0]
    query2 = match(srcip=ip1) >> match(dstip=ip2) >> b[1]
    query3 = match(srcip=ip1) >> match(dstip=ip3) >> b[2]

    return query1 + query2 + query3

def test5():
    """Test policy negation, but only for IP traffic.

    Display filter for checking correctness:

    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and ( ( (not ip.src ==
    10.0.0.1) and ( ip.dst == 10.0.0.1 || ip.dst == 10.0.0.2 || ip.dst ==
    10.0.0.3) ) || (arp && (not arp.src.proto_ipv4 == 10.0.0.1) &&
    (arp.dst.proto_ipv4 == 10.0.0.1 || arp.dst.proto_ipv4 == 10.0.0.2 ||
    arp.dst.proto_ipv4 == 10.0.0.3) ) )
    """
    test_bucket = QueryTest(5)
    matched_traffic = ( (~match(srcip=ip1) & match(dstip=ip2)) +
                        (~match(srcip=ip1) & match(dstip=ip3)) +
                        (~match(srcip=ip1) & match(dstip=ip1)) )
    return (matched_traffic >> test_bucket)

def test6():
    """Test policy negation covering all other traffic.

    Display filter for checking correctness:

    (not (ip.addr==192.168.0.0/16 or (arp and (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or (of
    and not of.pktin) or ip.addr == 10.0.2.0/24 or (arp && ( arp.src.proto_ipv4
    == 10.0.2.0/24 or arp.dst.proto_ipv4 == 10.0.2.0/24 ) ) or ipv6 ) ) and (not
    ( (ip && ip.src == 10.0.0.1 ) or (arp && arp.src.proto_ipv4 == 10.0.0.1) or
    ipv6))
    """
    test_bucket = QueryTest(6)
    matched_traffic = ~match(srcip=ip1)
    return (matched_traffic >> test_bucket)

def test7():
    """Ensure no double counting of packets destined to controller.

    Display filter for checking correctness:

    (not (of or ip.addr==192.168.0.0/16 or (arp && (arp.src.proto_ipv4 ==
    192.168.0.0/16 or arp.dst.proto_ipv4 == 192.168.0.0/16) ) or tcp.port==6011
    or (tcp.port==6633 and not of) or tcp.port==41414 or sll.pkttype==4 or
    ip.addr == 10.0.2.0/24 or (arp && (arp.src.proto_ipv4 == 10.0.2.0/24 or
    arp.dst.proto_ipv4 == 10.0.2.0/24) ) or ipv6 ) ) and (ip.dst == 10.0.0.1 ||
    (arp && (arp.dst.proto_ipv4 == 10.0.0.1 ) ) )
    """
    return ( (match(dstip=ip1) >> QueryTest(7)) +
             (match(dstip=ip1) >> Controller) )

def parse_args(kwargs, defaults):
    params = dict(kwargs)
    (query_policy, fwding_policy) = defaults
    if 'query' in params:
        query_policy = globals()[str(params['query'])]
    if 'fwding' in params:
        fwding_policy = globals()[str(params['fwding'])]
    return (query_policy, fwding_policy)

def no_query():
    return drop

def main(**kwargs):
    defaults = (test0, mac_learner)
    (query, fwding) = parse_args(kwargs, defaults)
    return fwding() + query()
