
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
            output += 'issued query, going to sleep for %f' % interval
            print output
            time.sleep(interval)

    def query_callback(self, counts):
        print "*** In user callback for bucket", id(self)
        print "(packet, byte) counts:", counts

def test_main1():
    """Tests a single match that is counted."""
    test_bucket = QueryTest()
    return (match(srcip=ip1) >> test_bucket) + fwding

def test_main2():
    """Tests buckets containing multiple matches for traffic."""
    b = [] # counting buckets
    for i in range(0,2):
        b.append(QueryTest())
        time.sleep(0.2)

    pol1 = match(srcip=ip1) >> b[0]
    pol2 = match(srcip=ip2) >> b[1]
    pol3 = match(srcip=ip3) >> b[0]

    return pol1 + pol2 + pol3 + fwding

def test_main3():
    """Test if the same traffic feeding into multiple buckets gets accounted
    correctly.
    """
    b = [] # counting buckets
    for i in range(0,3):
        b.append(QueryTest())
        time.sleep(0.2)

    query1 = match(srcip=ip1) >> match(dstip=ip2) >> b[0]
    query2 = match(srcip=ip1) >> match(dstip=ip2) >> b[1]
    query3 = match(srcip=ip1) >> match(dstip=ip3) >> b[2]

    return fwding + query1 + query2 + query3

def test_main4():
    """Test policy negation, but only for IP traffic."""
    test_bucket = QueryTest()
    matched_traffic = ( (~match(srcip=ip1) & match(dstip=ip2)) +
                        (~match(srcip=ip1) & match(dstip=ip3)) +
                        (~match(srcip=ip1) & match(dstip=ip1)) )
    return (matched_traffic >> test_bucket) + fwding

def test_main5():
    """Test policy negation covering all other traffic."""
    test_bucket = QueryTest()
    matched_traffic = ~match(srcip=ip1)
    return (matched_traffic >> test_bucket) + fwding

def main():
    return test_main1()
