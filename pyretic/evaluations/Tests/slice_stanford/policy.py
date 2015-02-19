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
            #partial_pol = in_out_atom(slice1, slice2)
 
            if pol is None:
                pol = partial_pol
            else:
                pol |= partial_pol
        
        '''final_pol = pol
        for i in range(3):
            pol = in_atom(identity) ^ pol
            final_pol += pol
        return final_pol'''

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
        
        forwarding = QuerySwitch('switch', policy_dic, set([drop]))

def main(**kwargs):
    return StanfordForwarding()


if __name__ == "__main__":
    print get_forwarding_classifier()
