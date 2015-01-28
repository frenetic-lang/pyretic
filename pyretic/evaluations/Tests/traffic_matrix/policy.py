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


class TrafficMatrixStats:
    
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

    def traffic_matrix_query(self, **kwargs):
        self.k = int(kwargs['k'])
        self.fout = int(kwargs['fout'])
        ports = self.get_port_map()
        switches = ports.keys()
        egress_pairs = itertools.product(switches, switches)

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

            
            partial_query = in_atom(partial_match_0) ** out_atom(partial_match_1)
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

        port_pol = None
        for sw in switches:
            sw_ports = ports[sw]
            
            in_port_match = None
            out_port_match = None
            for p in sw_ports:
                
                if in_port_match is None:
                    in_port_match = match(inport = p)
                else:
                    in_port_match |= match(inport = p)

                if out_port_match is None:
                    out_port_match = match(outport = p)
                else:
                    out_port_match |= match(outport = p)

            partial_port_pol = in_out_atom(match(switch = sw) & in_port_match, match(switch = sw) & out_port_match)

            if port_pol is None:
                port_pol = partial_port_pol
            else:
                port_pol += partial_port_pol


        query_thread = threading.Thread(target = self.pull_buckets)
        #query_thread.start()
    
        report_thread = threading.Thread(target = self.report)
        #report_thread.start()
        return pol + port_pol        

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
    tms = TrafficMatrixStats(5, 10)
    path_policy = tms.traffic_matrix_query(**kwargs)
    print 'hi'
    #print path_policy
    return path_policy

################### forwarding ################

def main(**kwargs):
    return identity


