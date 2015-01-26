from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.path import *
from pyretic.lib.query import counts
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


class SliceStats:
    
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
                print self.stat

            time.sleep(self.report_interval)
            
    def get_union_query(self, pairs):
        pol = None 
        for pair in pairs:
            slice1 = match(srcip = pair[0], dstip = pair[0])
            slice2 = match(srcip = pair[1], dstip = pair[1])
            partial_pol = +(in_atom(identity)) ^ in_out_atom(slice1, slice2)
            if pol is None:
                pol = partial_pol
            else:
                pol += partial_pol
            
        return pol

    def get_alternate_query(self, pairs):
        pol = None 
        
        for pair in pairs:
            slice1 = match(srcip = pair[0], dstip = pair[0])
            slice2 = match(srcip = pair[1], dstip = pair[1])
            partial_pol = in_out_atom(slice1, slice2) | in_out_atom(slice2, slice1)

            if pol is None:
                pol = partial_pol
            else:
                pol |= partial_pol
            
        return +(in_atom(identity)) ^ pol


    def get_slices(self, s):
        assert s < 256
        base = '10.0.%d.0/24'
        
        res = []
        for i in range(s):
            res.append(base % i)

        return res

    def slice_isolation_query(self, **kwargs):
        #s = int(kwargs['s'])
        s = 2
        slices = self.get_slices(s)
        pairs = itertools.combinations(slices, 2)
        return self.get_alternate_query(pairs) 
        
        

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
    ss = SliceStats(5, 10)
    path_policy = ss.slice_isolation_query(**kwargs)
    return path_policy

################### forwarding ################

def main(**kwargs):
    return identity

