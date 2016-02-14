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
# mininet: mininet.sh --topo=chain,3,3                                         #
# pyretic: pyretic.py pyretic.examples.path_query -m p0                        #
# test:    h1 ping h3 should produce packets at the controller from s3.        #
################################################################################
from pyretic.lib.corelib import *
from pyretic.core.network import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.path import *
from pyretic.lib.query import counts
from pyretic.lib.netflow import NetflowBucket
from pyretic.core import util
import copy
import threading

import time
from datetime import datetime

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')
ip4 = IPAddr('10.0.0.4')

only_count_results = False

def static_fwding_chain_2_2():
    return (
        (match(dstip=ip1) >> ((match(switch=1) >> fwd(2)) +
                              (match(switch=2) >> fwd(1)))) +
        (match(dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2))))
        )

def static_fwding_chain_3_3_only_h1_h3():
    return (
        (match(dstip=ip1) >> ((match(switch=1) >> fwd(2)) +
                              (match(switch=2) >> fwd(1)) +
                              (match(switch=3) >> fwd(1)))) +
        (match(dstip=ip3) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(2))))
        )

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

def stanford_shortest_path():
    from pyretic.examples.stanford_shortest_path import main as stan_fwding
    return stan_fwding()

def edge_network_cycle_4_4():
    return (
        match(switch=1, port=3) |
        match(switch=2, port=3) |
        match(switch=3, port=3) |
        match(switch=4, port=3)
    )

def query_func(bucket, interval):
    while True:
        output = str(datetime.now())
        output += " Pulling stats for bucket " + repr(bucket)
        # output += bucket.get_matches()
        print output
        bucket.pull_stats()
        time.sleep(interval)

def query_callback(test_num):
    global only_count_results

    def actual_callback(pkt):
        ac = actual_callback

        def touch_vars():
            """ Initialize function-specific counters, if uninitialized. """
            try:
                val = ac.pkt_count
                val = ac.byte_count
                val = ac.predwise_pkt_count
                val = ac.predwise_byte_count
            except AttributeError:
                ac.pkt_count = 0
                ac.byte_count = 0
                ac.predwise_pkt_count = {}
                ac.predwise_byte_count = {}

        def get_count_key(pkt):
            predwise_count_key = ['ethtype', 'srcip', 'dstip', 'switch', 'port']
            return util.frozendict({k: pkt[k] for k in predwise_count_key})

        def update_predwise_counts(pkt):
            curr_key = get_count_key(pkt)
            curr_pkt_count = ac.predwise_pkt_count.get(curr_key, 0)
            ac.predwise_pkt_count[curr_key] = curr_pkt_count + 1
            curr_byte_count = ac.predwise_byte_count.get(curr_key, 0)
            ac.predwise_byte_count[curr_key] = (curr_byte_count +
                                                pkt['payload_len'])

        def get_key_str(pred):
            try:
                out = "int:%s,ethtype:%s,srcip:%s,dstip:%s" % (
                    "s%d-eth%d" % (pred['switch'], pred['port']),
                    "ip" if pred['ethtype']==2048 else "arp",
                    str(pred['srcip']), str(pred['dstip']))
            except KeyError:
                raise RuntimeError("Missing keys from count predicate!")
            return out

        def print_predwise_entries():
            pkt_counts  = ac.predwise_pkt_count
            byte_counts = ac.predwise_byte_count
            for pred in pkt_counts.keys():
                assert pred in byte_counts.keys()
                print "Bucket %s %s counts: [%d, %d]" % (
                    str(test_num),
                    get_key_str(pred),
                    pkt_counts[pred],
                    byte_counts[pred])

        def print_total_entries():
            print "Bucket %s total counts: [%d, %d]" % (
                str(test_num),
                ac.pkt_count,
                ac.byte_count)

        print '**************'
        print datetime.now()
        print 'Test', test_num, ' -- got a callback from installed path query!'
        if only_count_results:
            if isinstance(pkt, pyretic.core.packet.Packet):
                touch_vars()
                ac.pkt_count  += 1
                ac.byte_count += pkt['payload_len']
                update_predwise_counts(pkt)
                # print_predwise_entries()
                print_total_entries()
            else:
                print "Bucket %s (packet, byte) counts: %s" % (
                    str(test_num), pkt)
        else:
            print pkt
        print '**************'
    return actual_callback

def path_callback(test_num):
    def actual_callback(pkt, paths):
        print '**************'
        print datetime.now()
        print 'Test', test_num, ' -- got a callback from installed path query!'
        print pkt
        print 'Got', len(paths), 'path(s) from the callback.'
        path_index = 1
        for path in paths:
            print '-----'
            print 'Printing path', path_index
            path_index += 1
            for p in path:
                print p
            print '-----'
        print '**************'
    return actual_callback

def agg_callback(test_num):
    def actual_callback(agg, res):
        print '**************'
        print datetime.now()
        print 'Test', test_num, ' -- got a callback from installed path query!'
        print res
        print 'from aggregate', agg
        print '**************'
    return actual_callback

def path_test_empty():
    return path_empty()

def path_test_0():
    p = atom(match(switch=2))
    p.register_callback(query_callback(0))
    return p

def path_test_0_5():
    p = +atom(identity) ^ atom(match(switch=2)) ^ +atom(identity)
    p.register_callback(query_callback(0.5))
    return p

def path_test_1():
    a1 = atom(match(switch=1,srcip=ip1))
    a2 = atom(match(switch=3,dstip=ip3))
    p = a1 ** a2
    p.register_callback(query_callback(1))
    return p

def path_test_2():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=3))
    p = a1 ** a2
    p.register_callback(query_callback(2))
    return p

def path_test_3():
    return path_test_2() + path_test_1()

def path_test_3_1():
    """ Run simultaneous upstream and downstream path_test_3. """
    p1 = path_test_1()
    p1.measure_upstream()
    p2 = path_test_2()
    p2.measure_upstream()
    return p1 + p2 + path_test_3()

def path_test_4():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=3))
    p = a1 ^ a2
    cb = CountBucket()
    p.set_bucket(cb)
    p.register_callback(query_callback(4))
    query_thread = threading.Thread(target=query_func, args=(cb,2.5))
    query_thread.daemon = True
    query_thread.start()
    return p

def path_test_4_5():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=2))
    p = a1 ^ a2
    cb = CountBucket(bname='1 ~> 2')
    p.set_bucket(cb)
    p.register_callback(query_callback("4.5"))
    query_thread = threading.Thread(target=query_func, args=(cb,5.0))
    query_thread.daemon = True
    query_thread.start()
    return p

def path_test_4_7():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=2))
    p = a1 ^ a2
    nb = NetflowBucket()
    p.set_bucket(nb)
    p.register_callback(query_callback("4.7"))
    return p

def path_test_5():
    a1 = atom(match(switch=1))
    a2 = atom(match(switch=3))
    p = (a1 ^ a2)  | (a2 ^ a1)
    p.register_callback(query_callback(5))
    return p

def path_test_5_1():
    a1 = in_atom(match(switch=1))
    a2 = out_atom(match(switch=2))
    p = (a1 ^ a2) | (a2 ^ a1)
    p.register_callback(query_callback("5.1"))
    return p

def path_test_5_2():
    """ upstream path query test. """
    a1 = in_atom(match(switch=1))
    a2 = out_atom(match(switch=2))
    p = (a1 ^ a2) | (a2 ^ a1)
    p.register_callback(query_callback("5.2"))
    p.measure_upstream()
    return p

def path_test_5_3():
    """ One upstream and one downstream query. """
    return path_test_5_2() + path_test_3()

def path_test_6():
    p = +atom(identity)
    p.register_callback(query_callback(6))
    return p

def path_test_7():
    p = atom(match(switch=1)) ^ +atom(identity)
    p.register_callback(query_callback(7))
    return p

def path_test_8():
    p = atom(ingress_network())
    p.register_callback(query_callback(8))
    return p

def path_test_9():
    p = atom(match(srcip=ip1)) ** out_atom(egress_network())
    p.register_callback(query_callback(9))
    return p

def path_test_10():
    """ TODO(ngsrinivas): Defunct test as of now -- drop atoms are not stitched
    into the main policy.
    """
    p = atom(match(srcip=ip1)) ^ drop_atom(identity)
    p.register_callback(query_callback(10))
    return p

def path_test_11():
    p = out_atom(identity)
    p.register_callback(query_callback(11))
    return p

def path_test_12():
    p = atom(match(switch=1))
    pb = PathBucket()
    p.set_bucket(pb)
    p.register_callback(path_callback(12))
    return p

def path_test_13():
    p = (atom(match(switch=1)) ^ atom(match(switch=2)) ^ atom(match(switch=3)))
    p.register_callback(query_callback(13))
    return p

def path_test_14():
    p = (atom(match(switch=1)) ^ hook(match(switch=2), ['port']) ^
         atom(match(switch=3)))
    p.register_callback(query_callback(14))
    return p

def path_test_15():
    p = (atom(match(switch=1)) ^ hook(match(switch=2), ['port']) ^
         hook(match(switch=3), ['srcip','dstip']))
    p.register_callback(query_callback(15))
    return p

def path_test_16():
    return path_test_13() + path_test_14() + path_test_15()

def path_test_17():
    p = atom(match(srcip=ip1))
    p.register_callback(query_callback(17))
    return p

def path_test_18():
    p = atom(identity)
    p.register_callback(query_callback(18))
    return p

def static_fwding_cycle_4_4_spanning_tree_1():
    return (
        (match(dstip=ip1) >> ((match(switch=1) >> fwd(3)) +
                              (match(switch=2) >> fwd(1)) +
                              (match(switch=3) >> fwd(1)) +
                              (match(switch=4) >> fwd(1)))) +
        (match(dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(3)) +
                              (match(switch=3) >> fwd(1)) +
                              (match(switch=4) >> fwd(1)))) +
        (match(dstip=ip3) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(3)) +
                              (match(switch=4) >> fwd(1)))) +
        (match(dstip=ip4) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(2)) +
                              (match(switch=4) >> fwd(3))))
        )

def static_fwding_cycle_4_4_spanning_tree_2():
    return (
        (match(dstip=ip1) >> ((match(switch=1) >> fwd(3)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(2)) +
                              (match(switch=4) >> fwd(2)))) +
        (match(dstip=ip2) >> ((match(switch=1) >> fwd(2)) +
                              (match(switch=2) >> fwd(3)) +
                              (match(switch=3) >> fwd(1)) +
                              (match(switch=4) >> fwd(1)))) +
        (match(dstip=ip3) >> ((match(switch=1) >> fwd(2)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(3)) +
                              (match(switch=4) >> fwd(1)))) +
        (match(dstip=ip4) >> ((match(switch=1) >> fwd(2)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(2)) +
                              (match(switch=4) >> fwd(3))))
        )

def path_test_waypoint_violation():
    """ This examples relies on the cycle,4,4 topology. Use one of the spanning
    tree forwarding policies static_fwding_cycle_4_4_spanning_tree_{1|2} as the
    main forwarding policy. S4 is a designed firewall switch, which must lie on
    the trajectory of any packet entering and leaving the network. We try and
    install a query below that catches packets between S1 and S3 that violate
    this waypoint constraint.

    Expected behaviour:

    With static_fwding_cycle_4_4_spanning_tree_1, packets between h1 and h3 do
    not go through S4, hence triggering callbacks as they hit S3/S1.

    With static_fwding_cycle_4_4_spanning_tree_2, no callbacks are triggered for
    packets between h1 and h3.

    As such the query can be generalized to detect _all_ waypoint violations:

    in_atom(ingress()) ^ +in_atom(~match(switch=4)) ^ out_atom(egress())

    TODO(ngsrinivas): generalize query as above once out_atom is implemented in
    full generality. =)
    """
    a = atom(match(switch=1))
    b = atom(~match(switch=4))
    c = atom(match(switch=3))
    i = atom(identity)
    p = (a ^ +b ^ c) | (c ^ +b ^ a)
    p.register_callback(query_callback("waypoint violated"))
    return p

def path_test_waypoint_violation_general():
    fw = match(switch=4)
    ing = ingress_network()
    eg  = egress_network()
    p = ((in_atom(ing & ~fw) ^ +in_atom(~fw) ^ out_atom(eg & ~fw)) |
         (in_out_atom(ing, eg & ~fw)))
    p.register_callback(query_callback("generalized_waypoint_violation"))
    return p

def path_test_waypoint_violation_general_static():
    fw = match(switch=4)
    edge = edge_network_cycle_4_4()
    p = ((in_atom(edge & ~fw) ^ +in_atom(~fw) ^ out_atom(edge & ~fw)) |
         (in_out_atom(edge, edge & ~fw)))
    p.register_callback(query_callback("generalized_waypoint_violation_static"))
    return p

def path_test_waypoint_violation_general_upstream():
    p = path_test_waypoint_violation_general()
    p.measure_upstream()
    return p

def change_dynamic_path(path_pol, interval, f_old_new_path_pol):
    """ A function that periodically changes the path policy of a dynamic path
    policy object.

    path_pol: dynamic_path_policy object
    interval: time (sec) between changes
    f_old_new_path_pol: function path_pol -> path_pol
    """
    while True:
        output =  str(datetime.now())
        output += "  Changing path policy"
        print output
        new_path_pol = f_old_new_path_pol(path_pol)
        path_pol.path_policy = new_path_pol
        time.sleep(interval)

def path_test_dynamic_1():
    a1 = atom(match(switch=1,srcip=ip1))
    a2 = atom(match(switch=2,dstip=ip2))
    p1 = a1 ** a2
    p1.register_callback(query_callback("dyn_1"))
    p = dynamic_path_policy(p1)
    dyn_thread = threading.Thread(target=change_dynamic_path,
                                  args=(p, 5.0, lambda x: x.path_policy))
    dyn_thread.daemon = True
    dyn_thread.start()
    return p

def path_test_19():
    p = out_atom(match(switch=1, port=1))
    p.register_callback(query_callback(19))
    return p

def path_test_20():
    p = in_out_atom(match(switch=2, port=3), match(switch=2, port=1))
    p.register_callback(query_callback(20))
    return p

def path_test_21():
    p = +in_atom(identity) ^ out_atom(egress_network())
    p.register_callback(query_callback(21))
    return p

def path_test_22():
    p1 = in_atom(match(switch=1)) ^ out_atom(match(switch=2))
    p2 = out_atom(match(switch=1)) ^ in_atom(match(switch=2))
    p1.register_callback(query_callback("22.p1"))
    p2.register_callback(query_callback("22.p2"))
    return p1 + p2

def path_test_23():
    p1 = in_atom(match(switch=1,port=2)) ^ out_atom(match(switch=2,port=3))
    p2 = out_atom(match(switch=1,port=1)) ^ in_atom(match(switch=2,port=1))
    p1.register_callback(query_callback("23.p1"))
    p2.register_callback(query_callback("23.p2"))
    return p1 + p2

def path_test_24():
    p1 = out_atom(match(switch=1,port=1)) ^ in_atom(match(switch=2,port=1))
    p2 = out_atom(match(switch=2,port=1)) ^ in_atom(match(switch=1,port=1))
    p1.register_callback(query_callback("24.p1"))
    p2.register_callback(query_callback("24.p2"))
    return p1 + p2

def path_test_per_hop_pktcount(**kwargs):
    """ Get packet counts of traffic from h_1 and h_n along a chain topology of
    length n, at each hop.
    """
    def setup_query(partial_query, query_pred, i, count=False):
        new_query = partial_query ^ atom(query_pred)
        if count:
            cb = CountBucket()
            new_query.set_bucket(cb)
            query_thread = threading.Thread(target=query_func, args=(cb,10.0))
            query_thread.daemon = True
            query_thread.start()
        new_query.register_callback(query_callback("per_hop_" + str(i)))
        return new_query

    params = dict(**kwargs)
    n = int(params['n'])
    p = path_epsilon()
    ip1 = IPAddr('10.0.0.1')
    ipn = IPAddr('10.0.0.' + str(n))
    partial_query = setup_query(path_epsilon(),
                            match(switch=1, srcip=ip1, dstip=ipn),
                            1)
    p += partial_query
    for i in range(2, n+1):
        partial_query = setup_query(partial_query,
                                    match(switch=i),
                                    i)
        p += partial_query
    return p

def chain_forwarding(**kwargs):
    params = dict(**kwargs)
    n = int(params['n'])
    ips = [0] + map(lambda x: IPAddr('10.0.0.' + str(x)), range(1, n+1))
    host_pol = drop
    for h in range(1, n+1):
        switch_pol = drop
        for s in range(1, n+1):
            if s == h:
                if h == 1 or h == n:
                    switch_pol += (match(dstip=ips[h], switch=s) >> fwd(2))
                else:
                    switch_pol += (match(dstip=ips[h], switch=s) >> fwd(3))
            elif s == 1:
                switch_pol += (match(dstip=ips[h], switch=1) >> fwd(1))
            elif s < h:
                switch_pol += (match(dstip=ips[h], switch=s) >> fwd(2))
            elif s > h:
                switch_pol += (match(dstip=ips[h], switch=s) >> fwd(1))
            else:
                raise RuntimeError("unmatchable condition.")
        host_pol += switch_pol
    return host_pol

def path_test_25():
    p = atom(ingress_network() & match(switch=1))
    p.register_callback(query_callback(25))
    return p

def path_test_26():
    p1 = (in_atom(match(srcip=ip1, switch=1)) ^
          out_atom(match(switch=2, dstip=ip2)))
    p2 = (in_atom(match(switch=1)) ^ in_out_atom(identity, match(switch=2)))
    p1.register_callback(query_callback("26.p1"))
    p2.register_callback(query_callback("26.p2"))
    return p1 + p2

def path_test_tm():
    num_switches = 4
    pset = path_empty()
    ing = ingress_network
    eg  = egress_network
    for i in range(1, num_switches + 1):
        for j in range(1, num_switches + 1):
            if (i != j):
                p = (in_atom(ing() & match(switch=i)) ^
                     +in_atom(identity) ^
                     out_atom(eg() & match(switch=j)))
                cb = CountBucket(bname=("%d ~> %d" % (i,j)))
                cb.register_callback(query_callback("27.%d.%d" % (i, j)))
                p.set_bucket(cb)
                query_thread = threading.Thread(target=query_func, args=(cb,5.0))
                query_thread.daemon = True
                query_thread.start()
                pset += p
    return pset

def path_test_tm_groupby_static():
    fvlist = {'switch': range(1,5)}
    p = in_group(match(port=3), ['switch']) ** out_group(match(port=3), ['switch'])
    fb = FwdBucket()
    fb.register_callback(agg_callback("tm_groupby"))
    p.set_bucket(fb)
    res_paths = path_grouping.expand_groupby(p, fvlist)
    return res_paths

def path_test_tm_groupby():
    p = (in_group(ingress_network(), ['switch']) **
         out_group(egress_network(), ['switch']))
    fb = FwdBucket()
    fb.register_callback(agg_callback("tm_groupby"))
    p.set_bucket(fb)
    return p

def path_test_27():
    return path_test_tm_groupby() + path_test_1()

def path_test_28():
    p = (in_group(ingress_network(), ['srcip']) **
         out_group(egress_network(), ['dstip', 'switch']))
    fb = FwdBucket()
    fb.register_callback(agg_callback("28_ip_groupby"))
    p.set_bucket(fb)
    fvlist = {'srcip': ['10.0.0.3', '10.0.0.4'],
              'dstip': ['10.0.0.1', '10.0.0.2']}
    p.set_fvlist(fvlist)
    return p

def stanford_firewall():
    from pyretic.examples.stanford_shortest_path import path_main as stan_query
    fb = FwdBucket()
    fb.register_callback(query_callback("stanford_firewall"))
    p = stan_query()
    p.set_bucket(fb)
    return p

def stanford_tm():
    qlist = []
    def edge_port(s):
        return 16 if (s == 1 or s == 2) else 4
    num_queries = 0
    for src in range(1,17):
        for dst in range(1,17):
            if src != dst:
                p = (in_atom(match(switch=src, port=edge_port(src))) **
                     out_atom(match(switch=dst, port=edge_port(dst))))
                # p = (in_atom(ingress_network() & match(switch=src)) **
                #      out_atom(egress_network() & match(switch=dst)))
                fb = FwdBucket()
                fb.register_callback(query_callback("tm_%d_%d" % (src, dst)))
                p.set_bucket(fb)
                num_queries += 1
                qlist.append(p)
    print "installing %d queries (%d)" % (num_queries, len(qlist))
    return path_policy_union(qlist)

def stanford_tm_counts():
    qlist = []
    def edge_port(s):
        return 16 if (s == 1 or s == 2) else 4
    num_queries = 0
    for src in range(1,17):
        for dst in range(1,17):
            if src != dst:
                p = (in_atom(match(switch=src, port=edge_port(src))) **
                     out_atom(match(switch=dst, port=edge_port(dst))))
                # p = (in_atom(ingress_network() & match(switch=src)) **
                #      out_atom(egress_network() & match(switch=dst)))
                cb = CountBucket()
                p.set_bucket(cb)
                num_queries += 1
                qlist.append(p)
    print "installing %d queries (%d)" % (num_queries, len(qlist))
    return path_policy_union(qlist)

def stanford_tm_progressive(**kwargs):
    qlist = []
    def edge_port(s):
        return 16 if (s == 1 or s == 2) else 4
    params = dict(kwargs)
    srccount = 4
    if 'srccount' in params:
        srccount = int(params['srccount'])
    num_queries = 0
    for src in range(1,srccount):
        for dst in range(1,17):
            if src != dst:
                p = (in_atom(match(switch=src, port=edge_port(src))) **
                     out_atom(match(switch=dst, port=edge_port(dst))))
                # p = (in_atom(ingress_network() & match(switch=src)) **
                #      out_atom(egress_network() & match(switch=dst)))
                fb = FwdBucket()
                fb.register_callback(query_callback("tm_%d_%d" % (src, dst)))
                p.set_bucket(fb)
                num_queries += 1
                qlist.append(p)
    print "installing %d queries (%d)" % (num_queries, len(qlist))
    return path_policy_union(qlist)

def get_query(kwargs, default):
    params = dict(kwargs)
    if 'query' in params:
        path_query = globals()[str(params['query'])]
    else:
        path_query = default
    return path_query

def get_fwding(kwargs, default):
    params = dict(kwargs)
    if 'fwding' in params:
        fwding_policy = globals()[str(params['fwding'])]
    else:
        fwding_policy = default
    return fwding_policy

def check_only_count(kwargs):
    global only_count_results
    params = dict(kwargs)
    if (('only_count_results' in params) and
        (params['only_count_results'] == 'true')):
        only_count_results = True

# type: unit -> path list
def path_main(**kwargs):
    check_only_count(kwargs)
    default = path_test_waypoint_violation_general
    query_fun = get_query(kwargs, default)
    try:
        return query_fun(**kwargs)
    except TypeError:
        return query_fun()

def main(**kwargs):
#    default = mac_learner()
    default = static_fwding_chain_3_3
#    default = static_fwding_cycle_4_4_spanning_tree_1
    return get_fwding(kwargs, default)()
