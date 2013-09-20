
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
        time.sleep(10)
        t = 10
        while True:
            print "---------"
            print "Printing matches for bucket", str(id(self)), "at time:", t
            for m in self.matches:
                print m
            print "---------"
            self.pull_stats()
            print "Issued query, sleeping for 10 seconds"
            time.sleep(10)
            t += 10

    def query_callback(self, counts):
        print "*** In user callback for bucket", id(self)
        print "(packet, byte) counts:", counts

def asymmetric_main():
    """Just another candidate policy; the default policy is in main() below."""
    b = [] # counting buckets
    for i in range(0,2):
        b.append(QueryTest())
        time.sleep(0.2)

    pol1 = match(srcip=IPAddr('10.0.0.1')) >> b[0]
    pol2 = match(srcip=IPAddr('10.0.0.2')) >> b[1]
    pol3 = (match(srcip=IPAddr('10.0.0.2')) >>
            modify(srcip=IPAddr('10.0.0.1')) >> fwd(2))
    pol4 = match(srcip=IPAddr('10.0.0.3')) >> b[0]
    pol5 = (match(srcip=IPAddr('10.0.0.1')) >> 
            modify(srcip=IPAddr('10.0.0.2')) >> fwd(1))

    return pol1 + pol2 + pol3 + pol4 + pol5

def main():
    ip1 = IPAddr('10.0.0.1')
    ip2 = IPAddr('10.0.0.2')
    ip3 = IPAddr('10.0.0.3')

    fwding = ( (match(dstip=ip1) >> fwd(1)) +
               (match(dstip=ip2) >> fwd(2)) +
               (match(dstip=ip3) >> fwd(3)) )

    b = [] # counting buckets
    for i in range(0,4):
        b.append(QueryTest())
        time.sleep(0.2)

    query1 = match(srcip=ip1) >> b[0]
    query2 = match(srcip=ip2) >> b[1]
    query3 = match(srcip=ip3) >> b[2]
    query4 = match(srcip=ip1) >> match(dstip=ip2) >> b[3]

    return fwding + query1 + query2 + query3 + query4

