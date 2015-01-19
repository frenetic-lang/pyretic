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
            
    def get_edge_num(self, k, pod_num, edge_num):
        core_cnt = (k/2) ** 2
        return core_cnt + k * (pod_num - 1) + (k / 2) + edge_num
    
    def get_aggr_list(self, k, pod_num):
        core_cnt = (k/2) ** 2
        start = core_cnt + k * (pod_num - 1) + 1
        return range(start, start + k/2)
        
    
    def get_core_list(self, k, aggr_num):
        core_cnt = (k/2) ** 2
        in_pod_aggr_num = (aggr_num - core_cnt - 1) % (k/2)
        start = k / 2 * (in_pod_aggr_num) + 1
        return range(start, start + k/2)

    def get_core_aggr(self, k, core_num, pod_num):
        core_cnt = (k/2) ** 2
        core_row = (core_num - 1)/ (k/ 2) + 1
        return core_cnt + k * (pod_num - 1) + core_row

    def query(self, **kwargs):
        params = dict(**kwargs)
        k = int(params['k'])
        
        core_cnt = (k / 2) ** 2

        src = self.get_edge_num(k, 1, 1)
        dst = self.get_edge_num(k, k, k/2)
       
        paths = []
        for aggr in self.get_aggr_list(k, 1):
            for core in self.get_core_list(k, aggr):
                paths.append([aggr, core, self.get_core_aggr(k, core, k), dst])
      
        ip_h1 = '10.0.0.1'
        ip_h2 = '10.0.0.2'
        
        
        base_query = atom(match(switch = 1) & match(srcip=ip_h1) & match(dstip=ip_h2))
        #partial_query = atom(ingress_network() & match(srcip=ip_h1) & match(dstip=ip_h2))
        base_query.register_callback(self.bucket_callback(1))
        p = base_query
       
        for path in paths:
            partial_query = base_query
            for hop in path:
                partial_query = partial_query ^ atom(match(switch = hop))
                #cb = CountBucket()
                #partial_query.set_bucket(cb)
                #self.buckets[i] = cb
                #self.stat[i] = 0
                partial_query.register_callback(self.bucket_callback(path))

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
    return identity
