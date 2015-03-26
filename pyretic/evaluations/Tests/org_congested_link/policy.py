from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.path import *
from pyretic.lib.query import counts
from Topos import *

import threading
import itertools

def query_callback(id_str, print_counts=True):
    def actual_callback(pkt):
        if print_counts:
            print '**************'
            print datetime.now()
            print 'Test', id_str, ' -- got a callback from installed path query!'
            print pkt
            print type(pkt)
            print '**************'
    return actual_callback


def all_packets_query():
    p = +atom(identity)
    p.register_callback(query_callback('all_packets_query'))
    return p


class LinkCongestionStats:
    
    def __init__(self, bucket_interval, report_interval):
        self.buckets = {}
        self.bucket_interval = bucket_interval
        self.report_interval = report_interval
        self.stat = {}
        self.stat_lock = threading.Lock()
    

    def report(self):
        while True:
            with self.stat_lock:
                s = sum(self.stat.values())
                if s == 0:
                    print 'no traffic yet'
                    continue
                m = 0
                max_pair = None
                rel_stats = {}

                for k,v in self.stat.items():
                    if max(v, m) == v:
                        max_pair = k
                        m = v

                rel_stats[k] = float(v) / s

            print rel_stats
            time.sleep(self.report_interval)
            
            
    def link_congestion_query(self, **kwargs):
        params = dict(**kwargs)
        m = int(params['m'])
        n = int(params['n'])
        
        try:    
            ingress = [ 's' + str(i) for i in range(int(params['in_start']),  int(params['in_end']) + 1)]
            if 'same' in params and params['same'] == 'True':
                egress = ingress
            else:
                egress = [ 's' + str(i) for i in range( int(params['out_start']), int(params['out_end']) + 1)]
        except KeyError:
            ingress = [ 's' + str(i) for i in range( 1, n + 1)]
            if 'same' in params and params['same'] == 'True':
                egress = ingress
            else:
                egress = ['s' + str(i) for i in range(n + 1, n + m + 1)]
         
        try:
            s1 = int(params['first'])
            s2 = int(params['second'])
        except KeyError:
            s1 = m + n + 1
            s2 = m + n + 2

        pairs = [ (int(pair[0][1:]), int(pair[1][1:]) ) for pair in itertools.product(ingress, egress)]
        p = None
        for pair in pairs:
            partial_query = in_atom(match(switch = pair[0])) ** out_atom(match(switch = s1)) ^ in_atom(match(switch = s2)) ** out_atom(match(switch = pair[1]))
            partial_query.register_callback(query_callback(pair)) 
            cb = CountBucket()
            #partial_query.set_bucket(cb)
            self.buckets[pair] = cb
            self.stat[pair] = 0
            #partial_query.register_callback(self.bucket_callback(pair))
            if p is None:
                p = partial_query
            else:
                p += partial_query

        query_thread = threading.Thread(target = self.pull_buckets)
        #query_thread.start()
    
        report_thread = threading.Thread(target = self.report)
        #report_thread.start()
        return p        

    def pull_buckets(self):
        while True:
            for key in self.buckets:
                cb = self.buckets[key]
                cb.pull_stats()
            time.sleep(self.bucket_interval)
    
    def bucket_callback(self, key):
        def callback_func(inp):
            #with self.stat_lock:
             #   self.stat[key] += inp[1]
            print inp
        return callback_func 
 
def path_main(**kwargs):
    lcs = LinkCongestionStats(5,5)
    return lcs.link_congestion_query(**kwargs)


def main(**kwargs):
    params = dict(**kwargs)
    m = int(params['m'])
    n = int(params['n'])
    return SingleLinkTopo.SingleLinkTopo.get_static_forwarding(n,m) 

