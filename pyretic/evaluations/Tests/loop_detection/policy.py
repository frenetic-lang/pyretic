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


class LoopStats:
    
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
            
    
    def get_port_map(self):
        core_cnt = (self.k / 2) ** 2
        port_map = {}

        for i in range(0, self.k):
            start = core_cnt + 1 + (self.k * i) + (self.k / 2)
            for j in range(0, self.k / 2):
                port_map[start + j] = range(1, self.fout + 1)

        return port_map

    def loop_detection_query(self, **kwargs):
        self.k = int(kwargs['k'])
        self.fout = int(kwargs['fout'])

        ports = self.get_port_map()
        switches = ports.keys()
        pol = None

        for sw in switches:
            sw_ports = ports[sw]
            for p in sw_ports:
                
                #partial_query = in_atom(match(switch = sw, inport = p)) ** in_atom(match(switch = sw, inport = p))
                partial_query = +(in_atom(~(match(switch = sw, inport = p)))) ^ in_atom(match(switch = sw, inport = p)) ^ +(in_atom(~match(switch = sw, inport = p))) ^ in_atom(match(switch = sw, inport = p))
                #partial_query = in_atom(identity) ^ in_atom(match(switch = sw, inport = p)) ^ +(in_atom(identity)) ^ in_atom(match(switch = sw, inport = p))


                pair = (sw, p)
                partial_query.register_callback(query_callback(pair)) 
                cb = CountBucket()
                #partial_query.set_bucket(cb)
                self.buckets[pair] = cb
                self.stat[pair] = 0
                #partial_query.register_callback(self.bucket_callback(pair))
                if pol is None:
                    pol = partial_query
                else:
                    pol += partial_query

        query_thread = threading.Thread(target = self.pull_buckets)
        #query_thread.start()
    
        report_thread = threading.Thread(target = self.report)
        #report_thread.start()
        #return +(in_atom(identity)) ^ pol        
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
    ls = LoopStats(5, 10)
    path_policy = ls.loop_detection_query(**kwargs)
    #print path_policy
    return path_policy

################### forwarding ################

def main(**kwargs):
    return identity


