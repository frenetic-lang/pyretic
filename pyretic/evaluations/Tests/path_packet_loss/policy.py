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


class PathPacketLossStats:
    
    def __init__(self, bucket_interval, report_interval):
        self.buckets = {}
        self.bucket_interval = bucket_interval
        self.report_interval = report_interval
        self.stat = {}
        self.stat_lock = threading.Lock()
    

    def report(self):
        while True:
            with self.stat_lock:
                s = ""
                for key in self.stat:
                    s += 's%d ' % key
                    print "%s: %d" % (key, self.stat[key])   
                         
            time.sleep(self.report_interval)
            
            
    def query(self, **kwargs):
        params = dict(**kwargs)
        n = int(params['n'])
        
        ip_h1 = '10.0.0.1'
        ip_h2 = '10.0.0.2'
        partial_query = atom(match(switch = 1) & match(srcip=ip_h1) & match(dstip=ip_h2))
        #partial_query = atom(ingress_network() & match(srcip=ip_h1) & match(dstip=ip_h2))
        partial_query.register_callback(self.bucket_callback(1))
        p = partial_query
        for i in range(2, n + 1):
            partial_query = partial_query ^ atom(match(switch = i))
            #cb = CountBucket()
            #partial_query.set_bucket(cb)
            #self.buckets[i] = cb
            self.stat[i] = 0
            partial_query.register_callback(self.bucket_callback(i))
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
             #   self.stat[key] += inp[0]
            print key, inp
        return callback_func 
 
def path_main(**kwargs):
    ppl = PathPacketLossStats(5,5)
    return ppl.query(**kwargs)
    #return all_packets_query()
    #return link_congestion_query(['s1'], ['s2'], 3, 4)


def main(**kwargs):
    params = dict(**kwargs)
    n = int(params['n'])
    return SimpleChainTopo.SimpleChainTopo.get_static_forwarding(n) 

