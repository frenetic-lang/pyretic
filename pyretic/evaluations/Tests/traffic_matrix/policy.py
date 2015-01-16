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
    
    def __init__(self, k, bucket_interval, report_interval):
        self.k = k

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
                port_map[start + j] = [0]

        return port_map

    def traffic_matrix_query(self):
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
    k = int(kwargs['k'])
    tms = TrafficMatrixStats(k, 5, 10)
    path_policy = tms.traffic_matrix_query()
    #print path_policy
    return path_policy

################### forwarding ################

class StanfordForwarding(Policy):
    def __init__(self):
        self._classifier = None
    
    def eval(self, pkt):
        return self.compile().eval(pkt)
    
    def compile(self):
        if not self._classifier:
            self._classifier = self.get_forwarding_classifier()
        return self._classifier

    def get_forwarding_classifier(self):
        PORT_TYPE_MULTIPLIER = 10000
        SWITCH_ID_MULTIPLIER = 100000

        port_count = {5:8, 7:15, 3:11, 4:11, 2:21, 1:24, 14:9, 13:9, 16:7, 8:14, 9:9, 15:31, 11:8, 12:8, 10:9, 6:8}

        cls_rules = []
        dir_name = 'stanford_openflow_rules'
        for file_name in os.listdir(dir_name):
            if file_name[-3:] == '.of':
                f = open(os.path.join(dir_name, file_name))
                rules = json.load(f)['rules']
                f.close()
                
                switch_id = None
                
                for rule in rules:
                    dst_ip = socket.inet_ntoa(struct.pack('!L', rule['ip_dst_match']))
                    netmask = 32 - rule['ip_dst_wc']
                    dst_ip += '/%d' % netmask
                    new_dst = None
                    if rule['ip_dst_new']:
                        new_dst = socket.inet_ntoa(struct.pack('!L', rule['ip_dst_new']))
                    
                    dst_port = rule['out_ports']
                    
                    if switch_id is None:
                        switch_id = rule['in_ports'][0] / SWITCH_ID_MULTIPLIER
                    
                    
                    new_ports = [p % PORT_TYPE_MULTIPLIER for p in rule['in_ports']]
                    new_ports.sort()
                    if new_ports[0] != 1 and new_ports[-1] != port_count[switch_id]:
                        print 'baaaaaaad'
                    for (i,j) in zip(new_ports[:-1], new_ports[1:]):
                        if j != i + 1:
                            print 'eeeeh'
                    
                    

                    partial_match = match(switch = switch_id, dstip = dst_ip).compile().rules[0].match
                    partial_actions = None 
                    if dst_port:
                        for dst in dst_port:
                            dst = dst % PORT_TYPE_MULTIPLIER
                            if partial_actions is None:
                                partial_actions = fwd(dst)
                            else:
                                partial_actions += fwd(dst)
                          
                    else:
                        partial_actions = drop

                    partial_actions = partial_actions.compile().rules[0].actions
                    cls_rules.append(Rule(partial_match, partial_actions))
        print len(cls_rules)
        return Classifier(cls_rules)    
        
    def get_forwarding_policy(self):
        PORT_TYPE_MULTIPLIER = 10000
        SWITCH_ID_MULTIPLIER = 100000

        port_count = {5:8, 7:15, 3:11, 4:11, 2:21, 1:24, 14:9, 13:9, 16:7, 8:14, 9:9, 15:31, 11:8, 12:8, 10:9, 6:8}
        policy_dic = {}

        dir_name = 'stanford_openflow_rules'
        for file_name in os.listdir(dir_name):
            if file_name[-3:] == '.of':
                f = open(os.path.join(dir_name, file_name))
                rules = json.load(f)['rules']
                f.close()
                
                switch_id = None
                
                switch_policy = drop
                for rule in rules:
                    dst_ip = socket.inet_ntoa(struct.pack('!L', rule['ip_dst_match']))
                    netmask = 32 - rule['ip_dst_wc']
                    dst_ip += '/%d' % netmask
                    new_dst = None
                    if rule['ip_dst_new']:
                        new_dst = socket.inet_ntoa(struct.pack('!L', rule['ip_dst_new']))
                    
                    dst_port = rule['out_ports']
                    
                    if switch_id is None:
                        switch_id = rule['in_ports'][0] / SWITCH_ID_MULTIPLIER
                    
                    new_ports = [p % PORT_TYPE_MULTIPLIER for p in rule['in_ports']]
                    new_ports.sort()
                    if new_ports[0] != 1 and new_ports[-1] != port_count[switch_id]:
                        print 'baaaaaaad'
                    for (i,j) in zip(new_ports[:-1], new_ports[1:]):
                        if j != i + 1:
                            print 'eeeeh'
                    
                    

                    partial_policy = match(dstip = dst_ip)
                    if not new_dst is None:
                        partial_policy = partial_policy >> modify(dstip = new_dst)
                
                    if dst_port:
                        partial_dst = None
                        for dst in dst_port:
                            dst = dst % PORT_TYPE_MULTIPLIER
                            if partial_dst is None:
                                partial_dst = fwd(dst)
                            else:
                                partial_dst += fwd(dst)
                      
                        partial_policy = partial_policy >> partial_dst
                    else:
                        partial_policy = partial_policy >> drop

                    switch_policy += partial_policy
                policy_dic[switch_id] = switch_policy
        
        print policy_dic
        forwarding = QuerySwitch('switch', policy_dic, set([drop]))

def main(**kwargs):
    return StanfordForwarding()


