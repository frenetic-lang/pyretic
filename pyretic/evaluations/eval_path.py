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
# mininet: Changes each time. Run evaluation script alongside corresponding    #
# mininet testing script                                                       #
# pyretic: pyretic.py pyretic.evaluations.eval_path -m p0 --test=<test_name>   #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.path import *
from pyretic.lib.query import counts
import threading

def query_callback(id_str, print_counts=True):
    def actual_callback(pkt):
        if print_counts:
            print '**************'
            print datetime.now()
            print 'Test', id_str, ' -- got a callback from installed path query!'
            print pkt
            print '**************'
    return actual_callback

def cycle_forwarding_policy(n):
    """The correct forwarding policy for a cycle topology. n is the number of
    nodes in the cycle."""
    ip_prefix = '10.0.0.'
    h1_ip = IP(ip_prefix + str(1))
    f = ((match(dstip=h1_ip) >> match(switch=1) >> fwd(3)) +
         (match(dstip=h1_ip) >> (~match(switch=1)) >> fwd(2)))
    for h in range(2,n+1):
        h_ip = IP(ip_prefix + str(h))
        f += (match(dstip=h_ip) >> ((match(switch=h) >> fwd(3)) +
                                    (match(switch=1) >> fwd(1)) +
                                    (((~match(switch=1))&(~match(switch=h))) >>
                                     fwd(2))))
    return f

def query_func(bucket, interval, id_str, duration):
    """Canonical callback function for a countbucket."""
    time_elapsed = 0
    while time_elapsed < duration:
        output = str(datetime.now())
        output += " Pulling stats for bucket " + id_str
        # output += bucket.get_matches()
        print output
        bucket.pull_stats()
        time.sleep(interval)
        time_elapsed += interval

## Test: Loop Forwarding
def path_test_loop(**kwargs):
    """Path query that checks for loops in forwarding.
    
    :param n: number of switches in the topology
    :type n: integer
    """
    plist = path_empty
    assert 'n' in kwargs
    n = int(kwargs['n'])
    # actually this needs to change and include id* on both sides
    for s in range(1,n+1):
        p = (atom(match(switch=s)) ^ +(atom(~match(switch=s))) ^
             atom(match(switch=s)))
        p.register_callback(query_callback('loops'))
        plist += p
    return plist
    # return []

def loop_fwding(**kwargs):
    """Forwarding policy that creates a loop when packets are sent from h1 to
    hn, and forwards in a single direction around the cycle topology otherwise.
    
    :param n: number of switches and hosts in the (loop) topology
    :type n: integer
    """
    assert 'n' in kwargs
    n = int(kwargs['n'])
    f = cycle_forwarding_policy(n)
    ip_prefix = '10.0.0.'
    h1_ip = IP(ip_prefix + str(1))
    h3_ip = IP(ip_prefix + str(3))
    f += (match(srcip=h3_ip, dstip=h1_ip, switch=1) >> fwd(2)) # h1 <--> h4 loop
    return f

## Test: Traffic Matrix
def path_test_tm(**kwargs):
    """ Query that measures the traffic matrix. Command line arguments:
    :param n: number of switches
    :param poll: polling time for each traffic matrix count
    :param duration: time after which to stop polling (useful to limit output
    when running tests)
    """
    default_timeout_value = 10 # default polling interval for counters
    default_poll_duration = 180 # default elapsed time after which polling stops

    def query_thread_setup(p, timeout, id_str, duration, print_counts=True):
        cb = CountBucket()
        p.set_bucket(cb)
        p.register_callback(query_callback(id_str, print_counts))
        query_thread = threading.Thread(target=query_func, args=(cb,
                                                                 timeout,
                                                                 id_str,
                                                                 duration))
        query_thread.daemon = True
        query_thread.start()

    def create_id_string(s1, s2):
        return str(s1) + '--->' + str(s2)

    def get_timeout(args):
        if 'poll' in args:
            return int(args['poll'])
        else:
            return default_timeout_value

    def get_duration(args):
        if 'test_duration' in args:
            return int(args['test_duration'])
        else:
            return default_poll_duration

    plist = path_empty
    n = int(kwargs['n'])
    timeout = get_timeout(kwargs)
    duration = get_duration(kwargs)
    for s1 in range(1,n+1):
        for s2 in range(s1+1,n+1):
            p = (atom(ingress_network() & match(switch=s1)) ^
                 end_path(match(switch=s2)))
            id = create_id_string(s1, s2)
            query_thread_setup(p, timeout, id, duration, s2==(s1+1))
            plist += p
            p = (atom(ingress_network() & match(switch=s2)) ^
                 end_path(match(switch=s1)))
            id = create_id_string(s2, s1)
            query_thread_setup(p, timeout, id, duration, s2==(s1+1))
            plist += p
    return plist

def tm_fwding(**kwargs):
    assert 'n' in kwargs
    n = int(kwargs['n'])
    return cycle_forwarding_policy(n)

## Test: Waypoint forwarding
def waypoint_fwding(**kwargs):
    h1 = IP('10.0.0.1')
    h2 = IP('10.0.0.2')
    h3 = IP('10.0.0.3')
    h4 = IP('10.0.0.4')
    policy = ((match(dstip=h1) >> ((match(switch=1) >> fwd(3)) +
                                   (match(switch=2) >> fwd(1)) +
                                   (match(switch=3) >> fwd(1)) +
                                   (match(switch=4) >> fwd(2)))) +
              (match(dstip=h2) >> ((match(switch=1) >> fwd(1)) +
                                   (match(switch=2) >> fwd(2)) +
                                   (match(switch=3) >> fwd(3)) +
                                   (match(switch=4) >> fwd(1)))) +
              (match(dstip=h3) >> ((match(switch=1) >> fwd(4)) +
                                   (match(switch=2) >> fwd(1)) +
                                   (match(switch=3) >> fwd(2)) +
                                   (match(switch=4) >> fwd(2)))) +
              (match(dstip=h4) >> ((match(switch=1) >> fwd(2)) +
                                   (match(switch=2) >> fwd(2)) +
                                   (match(switch=3) >> fwd(4)) +
                                   (match(switch=4) >> fwd(1)))))
    return policy

def path_test_waypoint(**kwargs):
    """ A waypoint query that specifies all packets not going through switch 4,
    designated as a 'firewall' switch.
    """
    p = (atom(ingress_network()) ^ atom(~match(switch=4)) ^
         atom(~match(switch=4)) ^ out_atom(identity))
    p.register_callback(query_callback("waypoint"))
    return p

# List of tests, to be used with the --test= parameter.
test_mains = {'loops': loop_fwding,
              'tm': tm_fwding,
              'waypoint': waypoint_fwding }

test_path_mains = {'loops': path_test_loop,
                   'tm': path_test_tm,
                   'waypoint': path_test_waypoint }

def test_setup(test_dict, default_test, **kwargs):
    params = dict(**kwargs)
    if 'test' in params:
        testname = params['test']
        return test_dict[testname](**kwargs)
    else:
        return default_test

def path_main(**kwargs):
    return test_setup(test_path_mains, [], **kwargs)

def main(**kwargs):
    return test_setup(test_mains, mac_learner(), **kwargs)

