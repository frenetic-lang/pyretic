from pyretic.lib.path import *
from pyretic.core.language import *
from datetime import datetime
import time
from cmd import Cmd

import threading
import itertools

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
        print "Traffic statistics for query %s" % test_num
        print "%d Packets" % counts[0]
        print "%d Bytes" % counts[1]
        print "-----------------------------------"
    return actual_callback

first_hop_stat = {}
second_hop_stat = {}
third_hop_stat = {}
stat_dict_list = [first_hop_stat, second_hop_stat, third_hop_stat]
stat_lock = threading.Lock()

def aggr_callback(test_num, id_list):
    def actual_callback(agg, res):
        sw_list = tuple([agg[i][0]['switch'] for i in id_list])
        stat_dict = stat_dict_list[len(sw_list) - 1]
        with stat_lock:    
            stat_dict[sw_list] = res
    return actual_callback


def print_stat_dict(d):
    for k in d:
        if d[k][0] > 0:
            print ",".join([str(x) for x in k]), ": ", "%d Packets, %d Bytes" % tuple(d[k])

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

EDGE = match(switch = 1, port = 3) | match(switch = 1, port = 4) | \
               match(switch = 3, port = 3) | match(switch = 3, port = 4) 

class DemoCLI(Cmd):
    """ Command-line prompt for demo queries. """
    prompt = "query>>> "

    def __init__(self, dpp, default_cb):
        """Initialize the CLI's internal structures using a dynamic_path_policy
        object. The default callback for the queries is also an additional
        argument.
        """
        assert isinstance(dpp, dynamic_path_policy)
        self.dpp = dpp
        self.default_cb = default_cb
        self.refq_map = {id(dpp.path_policy): dpp.path_policy}
        Cmd.__init__(self)

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
        print "\tadd\tAdd a new query"
        print "\trm\tRemove an existing query"
        print "\tpull\tPull statistics for an existing query"
        print "\tshow\tShow installed queries"

    def do_add(self, qstr):
        try:
            """ Dangerous!!! But this is the quickest way to do this. """
            q = eval(qstr)
        except Exception as e:
            print "*** Not a well formed expression:", e
            return
        if not isinstance(q, path_policy):
            print "*** Not a well formed query."
            return
        cb = CountBucket()
        cb.register_callback(self.default_cb(id(q)))
        q.set_bucket(cb)
        self.refq_map.update({id(q): q})
        self.dpp.path_policy += q
        print "Added query: reference %d" % id(q)

    def do_show(self, line):
        print "Showing installed queries:"
        for (qid, q) in self.refq_map.items():
            print qid, ':', q

    def do_rm(self, qidstr):
        qid = self.get_qid(qidstr)
        if qid:
            del self.refq_map[qid]
            self.dpp.path_policy = path_policy_union(self.refq_map.values())

    def do_pull(self, qidstr):
        qid = self.get_qid(qidstr)
        if qid:
            q = self.refq_map[qid]
            q.get_policy().pull_stats()

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
