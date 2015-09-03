from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.path import *
from pyretic.lib.query import counts
from pyretic.evaluations.Tests.common_modules.stanford_forwarding import *
from Topos import *

import threading
import itertools
import os
import json
import socket

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
        t = StanfordTopology.StanfordTopo()
        ports = t.port_map
        switches = ports.keys()
        egress_pairs = itertools.product(switches, switches)

        s1 = 1
        s2 = 2
 
        pol = None
        
        for pair in egress_pairs:
            partial_match_0 = drop
            for p in ports[pair[0]]:
                partial_match_0 |= match(inport = p)
            partial_match_0 = match(switch = pair[0]) & partial_match_0
            
            partial_match_1 = drop
            for p in ports[pair[1]]:
                partial_match_1 |= match(outport = p)
            partial_match_1 = match(switch = pair[1]) & partial_match_1

            partial_query = in_atom(partial_match_0) ** out_atom(match(switch = s1)) ^ in_atom(match(switch = s2)) ** out_atom(partial_match_1)
            partial_query.register_callback(query_callback(pair)) 
            cb = CountBucket()
            #partial_query.set_bucket(cb)
            self.buckets[pair] = cb
            self.stat[pair] = 0
            partial_query.register_callback(self.bucket_callback(pair))
            if pol is None:
                pol = partial_query
            else:
                pol += partial_query

        query_thread = threading.Thread(target = self.pull_buckets)
        #query_thread.start()
    
        report_thread = threading.Thread(target = self.report)
        #report_thread.start()
        return pol        

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
    return StanfordForwarding()


if __name__ == "__main__":
    print get_forwarding_classifier()
