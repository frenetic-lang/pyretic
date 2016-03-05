from pyretic.lib.path import *
from pyretic.core.language import *
from datetime import datetime

import threading

TEN_IP = '10.0.0.0/24'

def forwarding_policy():
    return if_(match(dstip = '10.0.0.1'),
               if_(match(switch = 1), fwd(3),
               if_(match(switch = 2), fwd(1),
               if_(match(switch = 3), fwd(1),
               if_(match(switch = 4), fwd(1),
               drop)))),
           if_(match(dstip = '10.0.0.2'),
               if_(match(switch = 1), fwd(4),
               if_(match(switch = 2), fwd(1),
               if_(match(switch = 3), fwd(2),
               if_(match(switch = 4), fwd(1),
               drop)))),
           if_(match(dstip = '10.0.0.3'),
               if_(match(switch = 1), fwd(1),
               if_(match(switch = 2), fwd(2),
               if_(match(switch = 3), fwd(3),
               if_(match(switch = 4), fwd(2),
               drop)))),
           if_(match(dstip = '10.0.0.4'),
               if_(match(switch = 1), fwd(2),
               if_(match(switch = 2), fwd(2),
               if_(match(switch = 3), fwd(4),
               if_(match(switch = 4), fwd(2),
               drop)))),
           drop))))


def count_callback(test_num):
    def actual_callback(counts):
        print "***", str(datetime.now()), "| In user callback for bucket",
        print test_num
        print "Bucket", test_num, "(packet, byte) counts:", counts
        print "-----------------------------------"
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

def fw_callback(test_num):
    def actual_callback(res):
        print '**************'
        print datetime.now()
        print 'Test', test_num, ' -- got a callback from installed path query!'
        print res
        print '**************'
    return actual_callback

def query_func(bucket, interval):
    while True:
        output = str(datetime.now())
        output += " Pulling stats for bucket " + repr(bucket)
        # output += bucket.get_matches()
        print output
        bucket.pull_stats()
        time.sleep(interval)

def query_callback(test_num):
    only_count_results = True

    def actual_callback(pkt):
        ac = actual_callback
        print type(ac)
        print type(pkt)
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


def query1():
    edge_network = match(switch = 1, port = 3) | match(switch = 1, port = 4) | \
                   match(switch = 3, port = 3) | match(switch = 3, port = 4) 
    tenant_pred = edge_network & match(srcip = TEN_IP, dstip = TEN_IP, ethtype=2048)
    q = in_atom(tenant_pred) ** out_atom(edge_network)
    cb = CountBucket()
    q.set_bucket(cb)
    # q.register_callback(query_callback(1))
    q.register_callback(count_callback(1))
    query_thread = threading.Thread(target=query_func, args=(cb,5))
    query_thread.daemon = True
    query_thread.start()
    '''
    fb = FwdBucket()
    q.set_bucket(fb)
    q.register_callback(fw_callback(1))
    '''
    return q

def query_test():
    fvlist = {'switch': range(1,5)}
    edge_network = match(switch = 1, port = 3) | match(switch = 1, port = 4) | \
                   match(switch = 3, port = 3) | match(switch = 3, port = 4) 
    tenant_pred = edge_network & match(srcip = TEN_IP, dstip = TEN_IP, ethtype=2048)
    q = in_group(tenant_pred, groupby=['switch']) ** out_group(edge_network, groupby=['switch'])
    fb = CountBucket()
    fb.register_callback(agg_callback("tm_groupby"))
    q.set_bucket(fb)
    res_paths = path_grouping.expand_groupby(q, fvlist)
    buckets = [p.piped_policy for p in res_paths.path_policies]
    print len(buckets)
    return res_paths


def path_main(**kwargs):
    return query1()

def main():
    return forwarding_policy()
