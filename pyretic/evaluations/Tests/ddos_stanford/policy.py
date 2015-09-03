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


class DDosStats:
    
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
            
            
    def ddos_query(self):
        t = StanfordTopology.StanfordTopo()
        ports = t.port_map
        switches = ports.keys()
	
        target = 3

        port_pol = None
        
        target_match = None
        for p in ports[target]:
            if target_match is None:
                target_match = match(outport = p)
            else:
                target_match |= match(outport = p)
        
        target_match = match(switch = target) & target_match

        for sw in switches:
            if sw == target:
                continue
            sw_ports = ports[sw]
            in_port_match = None
            for p in sw_ports:
                if in_port_match is None:
                    in_port_match = match(inport = p)
                else:
                    in_port_match |= match(inport = p)

            partial_port_pol = in_atom(match(switch = sw) & in_port_match) ** out_atom(target_match) 

            if port_pol is None:
                port_pol = partial_port_pol
            else:
                port_pol += partial_port_pol
     
        query_thread = threading.Thread(target = self.pull_buckets)
        #query_thread.start()
    
        report_thread = threading.Thread(target = self.report)
        #report_thread.start()
    
        return  port_pol       

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
    ds = DDosStats(5, 10)
    path_policy = ds.ddos_query()
    return path_policy

def main(**kwargs):
    return StanfordForwarding()


if __name__ == "__main__":
    print get_forwarding_classifier()
