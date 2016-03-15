from pyretic.lib.path import *
from pyretic.core.language import *
from datetime import datetime
import time
from cmd import Cmd
import copy
import threading
import itertools
import networkx as nx

TEN_IP = '10.0.0.0/24'
EDGE = match(switch = 1, port = 3) | match(switch = 1, port = 4) | \
       match(switch = 1, port = 5) | match(switch = 1, port = 6) | \
       match(switch = 5, port = 3) | match(switch = 5, port = 4) | \
       match(switch = 5, port = 5) | match(switch = 5, port = 6) 

TEN_SUBNET = match(srcip = TEN_IP, dstip = TEN_IP, ethtype=2048)

def forwarding_policy_small():
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

def forwarding_policy():
    last_hop = if_(match(switch = 5),
               if_(match(dstip = "10.0.0.5"), fwd(3),
               if_(match(dstip = "10.0.0.6"), fwd(4),
               if_(match(dstip = "10.0.0.7"), fwd(5),
               if_(match(dstip = "10.0.0.8"), fwd(6), 
               drop)))), drop)

    pol = if_(match(dstip = '10.0.0.1'),
               if_(match(switch = 1), fwd(3),
               if_(match(switch = 2), fwd(1),
               if_(match(switch = 3), fwd(1),
               if_(match(switch = 4), fwd(1),
               if_(match(switch = 5), fwd(1),
               drop))))),
           if_(match(dstip = '10.0.0.2'),
               if_(match(switch = 1), fwd(4),
               if_(match(switch = 2), fwd(1),
               if_(match(switch = 4), fwd(3),
               if_(match(switch = 5), fwd(1),
               if_(match(switch = 6), fwd(1),
               drop))))),
           if_(match(dstip = '10.0.0.3'),
               if_(match(switch = 1), fwd(5),
               if_(match(switch = 7), fwd(1),
               if_(match(switch = 6), fwd(3),
               if_(match(switch = 9), fwd(3),
               if_(match(switch = 5), fwd(2),
               drop))))),
           if_(match(dstip = '10.0.0.4'),
               if_(match(switch = 1), fwd(6),
               if_(match(switch = 7), fwd(1),
               if_(match(switch = 8), fwd(1),
               if_(match(switch = 9), fwd(1),
               if_(match(switch = 5), fwd(2),
               drop))))),
           if_(match(srcip = '10.0.0.1'),
               if_(match(switch = 1), fwd(1),
               if_(match(switch = 2), fwd(2),
               if_(match(switch = 3), fwd(2),
               if_(match(switch = 4), fwd(2),
               last_hop)))),
           if_(match(srcip = '10.0.0.2'),
               if_(match(switch = 1), fwd(1),
               if_(match(switch = 2), fwd(3),
               if_(match(switch = 4), fwd(2),
               if_(match(switch = 6), fwd(2),
               last_hop)))),
           if_(match(srcip = '10.0.0.3'),
               if_(match(switch = 1), fwd(2),
               if_(match(switch = 7), fwd(3),
               if_(match(switch = 6), fwd(4),
               if_(match(switch = 9), fwd(2),
               last_hop)))),
           if_(match(srcip = '10.0.0.4'),
               if_(match(switch = 1), fwd(2),
               if_(match(switch = 7), fwd(2),
               if_(match(switch = 8), fwd(2),
               if_(match(switch = 9), fwd(2),
               last_hop)))),
           last_hop))))))))
    return pol

def count_callback(test_num):
    def actual_callback(counts):
        print "Traffic statistics for query %s" % test_num
        print "%d Packets" % counts[0]
    return actual_callback

first_hop_stat = {}
second_hop_stat = {}
third_hop_stat = {}
fourth_hop_stat = {}
stat_dict_list = [first_hop_stat, second_hop_stat, third_hop_stat, fourth_hop_stat]
stat_lock = threading.Lock()
threshold = 0
pull_cnt = 0


def print_gb_stats():
    print "First Hop"
    print_stat_dict(first_hop_stat)
    print "************"
    print "Second Hop"
    print_stat_dict(second_hop_stat)
    print "************"
    print "Third Hop"
    print_stat_dict(third_hop_stat)
    print "************"
    print "Fourth Hop"
    print_stat_dict(fourth_hop_stat)
    print "************"

def aggr_callback(test_num, id_list):
    def actual_callback(agg, res):
        global threshold
        global pull_cnt
        sw_list = tuple([agg[i][0]['switch'] for i in id_list])
        stat_dict = stat_dict_list[len(sw_list) - 1]
        with stat_lock:    
            stat_dict[sw_list] = res
            pull_cnt += 1
            if pull_cnt == threshold:
                print_gb_stats()
                pull_cnt = 0
    return actual_callback


def print_stat_dict(d):
    for k in d:
        if d[k][0] > 0:
            print ",".join([str(x) for x in k]), ": ", "%d Packets" % d[k][0]

def print_stats(interval):
    while True:
        with stat_lock:
            print "First Hop"
            print_stat_dict(first_hop_stat)
            print "************"
            print "Second Hop"
            print_stat_dict(second_hop_stat)
            print "************"
            print "Third Hop"
            print_stat_dict(third_hop_stat)
            print "************"

        time.sleep(interval)

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
        bucket.pull_stats()
        time.sleep(interval)

def pull_func(bucket_list, interval):
    while True:
        for buc in bucket_list:
            buc.pull_stats()
        time.sleep(interval)


def up_and_down(q):
    q1 = q
    q2 = copy.copy(q)
    cb1 = CountBucket()
    q1.set_bucket(cb1)
    q1.register_callback(count_callback("Upstream"))
    q1.measure_upstream()

    cb2 = CountBucket()
    q2.set_bucket(cb2)
    q2.register_callback(count_callback("Downstream"))
    return [q1 + q2, cb1, cb2]


demotopo="\
                S3\n\
	       /  \ \n\
          %3d /    \ %3d \n\
             /      \ \n\
            /        \ \n\
          S2          S4\n\
	 /  \        /  \ \n\
        /    \      /    \ %3d (from 1->2->3->4->5)\n\
   %3d /  %3d \    / %3d  \ %3d (from 1->2->6->4->5)\n\
      /        \  /        \ \n\
%3d S1          S6          S5\n\
      \        /  \        /\n\
       \  %3d /    \ %3d  / %3d (from 1->7->6->9->5)\n\
    %3d \    /      \    / %3d (from 1->7->8->9->5)\n\
         \  /        \  /\n\
          S7          S9\n\
            \        /\n\
             \      /\n\
          %3d \    / %3d\n\
               \  /\n\
                S8"

def print_demo_stats():
    keys = [(2,3), (2,3,4),
            (2,3,4,5),
            (2,), (2,6), (2,6,4), (2,6,4,5),
            (),
            (7,6), (7,6,9), (7,6,9,5),
            (7,), (7,8,9,5),
            (7,8), (7,8,9)]
    print demotopo % tuple([int(stitch_dict[k][0]) for k in keys])

stitch_dict = {}
stitch_dict_lock = threading.Lock()
def stitch_callback(sw_list):
    def actual_callback(res):
        with stitch_dict_lock:
            stitch_dict[sw_list] = res
            if len(stitch_dict.keys()) == threshold:
                # print_stitch_stats()
                print_demo_stats()
                stitch_dict.clear()
    return actual_callback

def print_stitch_stats():
    count = 0
    for (k, v) in stitch_dict.items():
        [pkts, bytes] = v
        if pkts > 0:
            count += 1
            print k, ':', v
    print "Got %d keys" % count



def stitch(pred, hopcount):
    """ Convenience function to expand grouping for multiple paths and their
    prefixes """
    global threshold
    src = 1
    dst = 5
    g = nx.Graph()
    g.add_nodes_from(range(1,10))
    links = [(1, 2), (2, 3), (3, 4), (4, 5),
             (1, 7), (7, 8), (8, 9), (9, 5),
             (2, 6), (4, 6), (7, 6), (9, 6)]
    for l in links:
        g.add_edge(*l)
    paths = nx.all_simple_paths(g, src, dst)
    prefix_set = set()
    resq = None
    for p in paths:
        for prefix_len in range(0, len(p)):
            prefix_path = tuple(p[1:prefix_len+1])
            if len(prefix_path)+1 > hopcount:
                continue
            if not prefix_path in prefix_set:
                q = in_out_atom(match(switch=src) & pred, ~EDGE)
                for sw in prefix_path:
                    q = q ^ in_atom(match(switch=sw))
                cb = CountBucket()
                q.set_bucket(cb)
                q.register_callback(stitch_callback(prefix_path))
                if resq:
                    resq += q
                else:
                    resq = q
            prefix_set.add(prefix_path)
    buckets =  [p.piped_policy for p in resq.path_policies]
    print "Initialized %d queries" % len(buckets)
    threshold = len(buckets)
    return [resq] + buckets

def per_switch_hop(pred, cnt):
    
    fvlist = {'switch': range(1,10)}
    
    resq = None

    for i in range(1, cnt + 1):
        q = in_group(pred, groupby=['switch'])
        id_list = [id(q)]
        for j in range(i - 1):
            gb = in_group(identity, groupby=['switch'])
            id_list.append(id(gb))
            q = q ^ gb
        cb = CountBucket()
        q.set_bucket(cb)
        q.register_callback(aggr_callback("Hop %d" % i, id_list))

        queries = path_grouping.expand_groupby(q, fvlist)
        if resq is None:
            resq = queries
        else:
            resq += queries

    
    buckets =  [p.piped_policy for p in resq.path_policies]
   
    global threshold
    threshold = len(buckets)
    return [resq] + buckets


class DemoCLI(Cmd):
    """ Command-line prompt for demo queries. """
    prompt = "query> "

    def __init__(self, dpp, default_cb):
        """Initialize the CLI's internal structures using a dynamic_path_policy
        object. The default callback for the queries is also an additional
        argument.
        """
        assert isinstance(dpp, dynamic_path_policy)
        self.dpp = dpp
        self.default_cb = default_cb
        self.query_cnt = 0
        zid = self.get_new_id()
        self.refq_map = {zid: dpp.path_policy}
        self.buck_map = {zid : []}
        self.active_queries = set([0])
        self.print_map = {zid: dpp.path_policy}
        Cmd.__init__(self)

    def get_new_id(self):
        res = self.query_cnt
        self.query_cnt += 1
        return res

    def get_qid(self, qidstr):
        try:
            qid = int(qidstr)
        except Exception as e:
            print "*** There is no query with this reference."
            return False
        if not qid in self.refq_map:
            print "*** There is no query with this reference."
            return False
        return qid

    def emptyline(self):
        pass

    def do_help(self, line):
        print "The available commands are:"
        print "\tinit\tInitialize a new query"
        print "\tupstream\tmeasure a query upstream"
        print "\tdownstream\tmeasure a query downstream"
        print "\tadd\tAdd a new query"
        print "\tpull\tPull statistics for an existing query"
        print "\trm\tRemove an existing query"
        print "\tshow_all\tShow all queries"
        print "\tshow_active\tShow active queries"

    def do_init(self, qstr):
        buckets = []
        try:
            """ Dangerous!!! But this is the quickest way to do this. """
            q = eval(qstr)
        except Exception as e:
            print "*** Not a well formed expression:", e
            return
        if isinstance(q, list):
            if len(q) > 0 and isinstance(q[0], path_policy):
                for cb in q[1:]:
                    if isinstance(cb, CountBucket):
                        buckets.append(cb)
                q = q[0]
            else:
                print "*** Not a well formed query."
                return

        elif not isinstance(q, path_policy):
            print "*** Not a well formed query."
            return
    
        
        qid = self.get_new_id()
        
        if len(buckets) == 0:
            cb = CountBucket()
            cb.register_callback(self.default_cb(qid))
            q.set_bucket(cb)
            buckets = [cb]

        self.refq_map.update({qid: q})
        self.print_map.update({qid: qstr})
        self.buck_map[qid] = buckets
        print "Initialized query: reference %d" % qid

    def do_upstream(self, qidstr):
        qid = self.get_qid(qidstr)
        if qid:
            q = self.refq_map[qid]
            q.measure_upstream()
            print "Changed measurement of query to upstream: reference %d" % qid

    def do_downstream(self, qidstr):
        qid = self.get_qid(qidstr)
        if qid:
            q = self.refq_map[qid]
            q.measure_downstream()
            print "Changed measurement of query to downstream: reference %d" % qid

    def do_add(self, qidstr):
        qid = self.get_qid(qidstr)
        if qid:
            q = self.refq_map[qid]
            self.active_queries.add(qid)
            self.dpp.path_policy += q
            print "Added query: reference %d" % qid

    def do_show_all(self, line):
        print "Showing queries:"
        for (qid, q) in self.print_map.items():
            print qid, ':', q
    
    def do_show_active(self, line):
        print "Showing active queries:"
        for qid in self.active_queries:
            if qid in self.print_map:
                print qid, ":", self.print_map[qid]

    def do_rm(self, qidstr):
        qid = self.get_qid(qidstr)
        if qid:
            del self.refq_map[qid]
            del self.buck_map[qid]
            del self.print_map[qid]
            self.active_queries.discard(qid)
            queries = self.refq_map.values()
            if len(queries) > 1:
                self.dpp.path_policy = path_policy_union(self.refq_map.values())
            elif len(queries) == 1:
                self.dpp.path_policy = queries[0]
            else:
                self.dpp.path_policy = path_empty()

    def do_pull(self, qidstr):
        qid = self.get_qid(qidstr)
        if qid:
            for cb in self.buck_map[qid]:
                cb.pull_stats()
            time.sleep(3)

    def do_EOF(self, line):
        print '\n'
        print "Exiting CLI"
        return True

    def do_exit(self, line):
        return self.do_EOF(line)

    def do_quit(self, line):
        return self.do_EOF(line)

def span_cli(p, default_cb):
    cli = DemoCLI(p, default_cb)
    time.sleep(2)
    print
    cli.cmdloop()

def query1():
    tenant_pred = EDGE & match(srcip = TEN_IP, dstip = TEN_IP, ethtype=2048)
    q1 = in_atom(tenant_pred) ** out_atom(EDGE)
    q1 |= in_out_atom(tenant_pred, EDGE)
    cb1 = CountBucket()
    q1.set_bucket(cb1)
    q1.register_callback(count_callback("1 - Upstream"))
    q1.measure_upstream()
    query_thread = threading.Thread(target=query_func, args=(cb1,5))
    query_thread.daemon = True
    query_thread.start()

    q2 = in_atom(tenant_pred) ** out_atom(EDGE)
    q2 |= in_out_atom(tenant_pred, EDGE)
    cb2 = CountBucket()
    q2.set_bucket(cb2)
    q2.register_callback(count_callback("1 - Downstream"))
    query_thread = threading.Thread(target=query_func, args=(cb2,5))
    query_thread.daemon = True
    query_thread.start()
    return q1 + q2

def query2():
    fvlist = {'switch': range(1,5)}
    tenant_pred = EDGE & match(srcip = TEN_IP, dstip = TEN_IP, ethtype=2048)
    
    # first hop
    q1 = in_group(tenant_pred, groupby=['switch'])
    cb1 = CountBucket()
    q1.set_bucket(cb1)
    q1.register_callback(aggr_callback("2 - first hop", [id(q1)]))
    res_q = path_grouping.expand_groupby(q1, fvlist)
    
    # second hop
    gb1 = in_group(tenant_pred, groupby=['switch'])
    gb2 = in_group(identity, groupby=['switch'])
    q2 = gb1 ^ gb2
    cb2 = CountBucket()
    q2.set_bucket(cb2)
    q2.register_callback(aggr_callback("2 - second hop", [id(gb1), id(gb2)]))
    res_q += path_grouping.expand_groupby(q2, fvlist)

    # third hop
    gb1 = in_group(tenant_pred, groupby=['switch'])
    gb2 = in_group(identity, groupby=['switch'])
    gb3 = in_group(identity, groupby=['switch'])
    q3 = gb1 ^ gb2 ^ gb3
    cb3 = CountBucket()
    q3.set_bucket(cb3)
    q3.register_callback(aggr_callback("2 - third hop", [id(gb1), id(gb2), id(gb3)]))
    res_q += path_grouping.expand_groupby(q3, fvlist)

    buckets =  [p.piped_policy for p in res_q.path_policies]
    # start pulling thread
    query_thread = threading.Thread(target=pull_func, args=(buckets,5))
    query_thread.daemon = True
    query_thread.start()

    print_thread = threading.Thread(target=print_stats, args=(10,))
    print_thread.daemon = True
    print_thread.start()

    return res_q

def query_test():
    fvlist = {'switch': range(1,5)}
    EDGE = match(switch = 1, port = 3) | match(switch = 1, port = 4) | \
                   match(switch = 3, port = 3) | match(switch = 3, port = 4) 
    tenant_pred = EDGE & match(srcip = TEN_IP, dstip = TEN_IP, ethtype=2048)
    q = in_group(tenant_pred, groupby=['switch']) ** out_group(EDGE, groupby=['switch'])
    fb = CountBucket()
    fb.register_callback(aggr_callback("tm_groupby"))
    q.set_bucket(fb)
    res_paths = path_grouping.expand_groupby(q, fvlist)
    buckets = [p.piped_policy for p in res_paths.path_policies]
    print len(buckets)
    return res_paths

def query3():
    """ Use a dynamic path policy and a CLI to have user-typed queries. """
    p = dynamic_path_policy(path_empty())
    cli_thread = threading.Thread(target=span_cli, args=(
        p, count_callback))
    cli_thread.start()
    return p

def path_main(**kwargs):
    # return query1()
    return query3()

def main():
    return forwarding_policy()
