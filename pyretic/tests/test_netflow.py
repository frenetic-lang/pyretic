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

from pyretic.lib.netflow import *
from pyretic.core.language import *
import logging, time, subprocess, shlex, os, threading

# Pcap test files for testing.
TESTPCAP = "pyretic/scratch/testpcap.pcap"
VLANTEST = "pyretic/scratch/vlantest.pcap"

def compilation_tests():
    x = NetflowBucket(start_fcapd=False)
    y = match(srcip='10.0.0.1')
    z = modify(dstip='192.168.0.2')

    print x
    print x.compile()
    print '****'
    a = y >> x
    print a
    print a.compile()
    print '****'
    b = y >> z >> x
    print b
    print b.compile()
    print '****'
    c = z + x
    print c
    print c.compile()
    print '****'
    d = y >> (z + x)
    print d
    print d.compile()
    print '****'
    e = x >> z
    print e
    print e.compile()

### Netflow bucket testing
### Helper functions for netflow bucket tests.
def nf_callback_fn(arg=''):
    def f(res):
        print '******************'
        print "Callback identifier:", arg
        print "This is a netflow bucket callback function. I got results:"
        print res
        print '******************'
    return f

def traffic_thread(loop=True):
    """ Generate a custom workload separately for nfcapd. """
    def run_workload():
        cmd = "softflowd -n localhost:%d -r %s" % (NFCAPD_PORT, VLANTEST)
        try:
            p = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
        except OSError:
            print "Errors in replaying traffic workload to netflow collector!"
            print "Got output:", p
        except subprocess.CalledProcessError:
            print "There were errors in running softflowd!"
            print "Got output:", p
    ''' Run a do-while-loop of run_workload. '''
    while True:
        run_workload()
        if not loop:
            break
        else:
            time.sleep(7)

def netflow_bucket_test1():
    """Run netflow bucket with a custom workload and see callback results. Note that
    this is an "offline" test, meaning there is no network involved. The
    functions just test the actions of the library given a running instance of
    the netflow collector daemon.
    """
    nb = NetflowBucket(cap_type="netflow")
    nb.register_callback(nf_callback_fn('#1'))
    # Check whether multiple nfcapd instances are started, and whether that
    # causes errors by starting different NetflowBuckets. Neither should
    # happen.
    nb.start_nfcapd()
    nb.start_nfcapd()

    nb2 = NetflowBucket(cap_type="netflow")
    nb2.register_callback(nf_callback_fn('#2'))
    nb2.set_preproc_pol(identity, 0)
    nb2.add_match({'srcip': IPPrefix('10.0.0/24')}, 60000, 1, 0)

    # test "active buckets" by only setting one of the objects above active
    NetflowBucket.set_active_buckets([nb2], 0)

    t = threading.Thread(target=traffic_thread, args=(True,))
    t.daemon = True
    t.start()

    try:
        time.sleep(300)
    except KeyboardInterrupt:
        print "Killing netflow test."

    nb.kill_nfcapd()
    print "Netflow bucket test complete"

if __name__ == "__main__":
    logging.basicConfig()
    compilation_tests()
    netflow_bucket_test1()
