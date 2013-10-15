
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################

import pyretic.core.util as util
from pyretic.core.language import *
from pyretic.core.network import *
from multiprocessing import Process, Manager, RLock, Lock, Value, Queue, Condition
import logging, sys, time
from datetime import datetime

TABLE_MISS_PRIORITY = 0

try:
    import ipdb as debugger
    USE_IPDB=True
except:
    import pdb as debugger
    import traceback, sys
    USE_IPDB=False


class Runtime(object):
    def __init__(self, backend, main, kwargs, mode='interpreted', verbosity='normal', 
                 show_traces=False, debug_packet_in=False):
        self.verbosity = self.verbosity_numeric(verbosity)
        self.log = logging.getLogger('%s.Runtime' % __name__)
        self.network = ConcreteNetwork(self)
        self.prev_network = self.network.copy()
        self.policy = main(**kwargs)
        self.debug_packet_in = debug_packet_in
        self.show_traces = show_traces
        self.mode = mode
        self.backend = backend
        self.backend.runtime = self
        self.vlan_to_extended_values_db = {}
        self.extended_values_to_vlan_db = {}
        self.extended_values_lock = RLock()
        self.active_dynamic_policies = set()
        if mode != 'interpreted':
            dynamic_sub_pols = self.ast_fold(self.add_dynamic_sub_pols,
                                             set(),
                                             self.policy)
            for p in dynamic_sub_pols:
                p.attach(self.handle_policy_change)
        self.in_update_network = False
        self.update_network_lock = Lock()
        self.update_network_no = Value('i', 0)
        self.global_outstanding_queries_lock = Lock()
        self.global_outstanding_queries = {}
        self.manager = Manager()
        self.old_rules_lock = Lock()
        self.old_rules = self.manager.list()
        self.update_rules_lock = Lock()
        self.update_buckets_lock = Lock()

    def verbosity_numeric(self,verbosity_option):
        numeric_map = { 'low': 1,
                        'normal': 2,
                        'high': 3,
                        'please-make-it-stop': 4}
        return numeric_map.get(verbosity_option, 0)

    def ast_fold(self, fun, acc, policy):
        if isinstance(policy,DerivedPolicy):
            fun(acc,policy)
            self.ast_fold(fun,acc,policy.policy)

        elif isinstance(policy,CombinatorPolicy):
            fun(acc,policy)
            for sub_policy in policy.policies:
                self.ast_fold(fun,acc,sub_policy)

        else:
            fun(acc,policy)

        return acc

    def add_dynamic_sub_pols(self, acc, policy):
        if isinstance(policy,DynamicPolicy):
            acc.add(policy)

    def add_query_sub_pols(self, acc, policy):
        from pyretic.lib.query import packets
        if isinstance(policy,Query):
            acc.add(policy)
        ### TODO remove this hack once packets is refactored        
        elif isinstance(policy,packets):
            acc.add(policy)

    def update_network(self):
        if self.network.topology != self.prev_network.topology:
            with self.update_network_lock:
                self.update_network_no.value += 1
                this_update_network_no = self.update_network_no.value
                self.in_update_network = True
                self.prev_network = self.network.copy()
                self.policy.set_network(self.prev_network)
                if self.mode == 'reactive0':
                    self.clear_all(this_update_network_no,self.update_network_no)
                elif self.mode == 'proactive0' or self.mode == 'proactive1':
                    classifier = self.policy.compile()
                    self.log.debug(
                        '|%s|\n\t%s\n\t%s\n\t%s\n' % (str(datetime.now()),
                            "generate classifier",
                            "policy="+repr(self.policy),
                            "classifier="+repr(classifier)))
                    self.install_classifier(classifier,this_update_network_no,self.update_network_no)
                self.in_update_network = False

    def handle_policy_change(self, changed, old, new):
        old_dynamics = self.find_dynamic_sub_pols(old,set())
        new_dynamics = self.find_dynamic_sub_pols(new,set())
        for p in (old_dynamics - new_dynamics):
            p.detach()
        for p in (new_dynamics - old_dynamics):
            p.attach(self.handle_policy_change)
        if self.in_update_network:
            pass
        else:
            if self.mode == 'reactive0':
                self.clear_all() 
            elif self.mode == 'proactive0' or self.mode == 'proactive1':
                classifier = self.policy.compile()
                self.log.debug(
                    '|%s|\n\t%s\n\t%s\n\t%s\n' % (str(datetime.now()),
                        "generate classifier",
                        "policy="+repr(self.policy),
                        "classifier="+repr(classifier)))
                self.install_classifier(classifier)

    def handle_switch_join(self,switch_id):
        self.network.handle_switch_join(switch_id)

    def handle_switch_part(self,switch_id):
        self.network.handle_switch_part(switch_id)

    def handle_port_join(self,switch_id,port_id,conf_up,stat_up):
        self.network.handle_port_join(switch_id,port_id,conf_up,stat_up)

    def handle_port_mod(self, switch, port_no, config, status):
        self.network.handle_port_mod(switch, port_no, config, status)

    def handle_port_part(self, switch, port_no):
        self.network.handle_port_part(switch, port_no)

    def handle_link_update(self, s1, p_no1, s2, p_no2):
        self.network.handle_link_update(s1, p_no1, s2, p_no2)

    def match_on_all_fields(self, pkt):
        pred = pkt.copy()
        del pred['header_len']
        del pred['payload_len']
        del pred['raw']
        return pred

    def match_on_all_fields_rule_tuple(self, pkt_in, pkts_out):
        concrete_pkt_in = self.pyretic2concrete(pkt_in)
        concrete_pred = self.match_on_all_fields(concrete_pkt_in)
        action_list = []
        
        ### IF NO PKTS OUT THEN INSTALL DROP (EMPTY ACTION LIST)
        if len(pkts_out) == 0:
            return (concrete_pred,0,action_list)

        for pkt_out in pkts_out:
            concrete_pkt_out = self.pyretic2concrete(pkt_out)
            actions = {}
            header_fields = set(concrete_pkt_out.keys()) | set(concrete_pkt_in.keys())
            for field in header_fields:
                if field not in native_headers + ['outport']:
                    continue
                try:
                    in_val = concrete_pkt_in[field]
                except:
                    in_val = None
                try:
                    out_val = concrete_pkt_out[field]
                except:
                    out_val = None
                if not out_val == in_val: 
                    actions[field] = out_val
            action_list.append(actions)

        # DEAL W/ BUG IN OVS ACCEPTING ARP RULES THAT AREN'T ACTUALLY EXECUTED
        if pkt_in['ethtype'] == ARP_TYPE: 
            for action_set in action_list:
                if len(action_set) > 1:
                    return None

        return (concrete_pred,0,action_list)


    def reactive0(self,in_pkt,out_pkts,eval_trace):
        if self.mode == 'reactive0':
            rule = None
            ### DON'T INSTALL RULES THAT CONTAIN QUERIES
            from pyretic.lib.query import packets, count_packets, count_bytes
            if eval_trace.contains_class(packets.FilterWrappedFwdBucket):
                pass
            elif eval_trace.contains_class(count_packets):
                pass
            elif eval_trace.contains_class(count_bytes):
                pass
            else:
                rule_tuple = self.match_on_all_fields_rule_tuple(in_pkt,out_pkts)
                if rule_tuple:
                    self.install_rule(rule_tuple)
                    self.log.debug(
                        '|%s|\n\t%s\n\t%s\n\t%s\n' % (str(datetime.now()),
                            " | install rule",
                            rule_tuple[0],
                            'actions='+repr(rule_tuple[2])))

    def handle_packet_in(self, concrete_pkt):
        pyretic_pkt = self.concrete2pyretic(concrete_pkt)
        if self.debug_packet_in:
            debugger.set_trace()
        if USE_IPDB:
             with debugger.launch_ipdb_on_exception():
                 if (self.mode == 'interpreted' or 
                     self.mode == 'proactive0' or self.mode == 'proactive1'):
                     output = self.policy.eval(pyretic_pkt)
                 else:
                     (output,eval_trace) = self.policy.track_eval(pyretic_pkt,dry=False)
                     self.reactive0(pyretic_pkt,output,eval_trace)
        else:
            try:
                if (self.mode == 'interpreted' or 
                    self.mode == 'proactive0' or self.mode == 'proactive1'):
                    output = self.policy.eval(pyretic_pkt)
                else:
                    (output,eval_trace) = self.policy.track_eval(pyretic_pkt,dry=False)
                    self.reactive0(pyretic_pkt,output,eval_trace)
            except :
                type, value, tb = sys.exc_info()
                traceback.print_exc()
                debugger.post_mortem(tb)
        if self.show_traces:
            self.log.info("<<<<<<<<< RECV <<<<<<<<<<<<<<<<<<<<<<<<<<")
            self.log.info(str(util.repr_plus([pyretic_pkt], sep="\n\n")))
            self.log.info("")
            self.log.info(">>>>>>>>> SEND >>>>>>>>>>>>>>>>>>>>>>>>>>")
            self.log.info(str(util.repr_plus(output, sep="\n\n")))
            self.log.info("")
        map(self.send_packet,output)
  
    def pyretic2concrete(self,packet):
        concrete_packet = ConcretePacket()
        for header in ['switch','inport','outport']:
            try:
                concrete_packet[header] = packet[header]
                packet = packet.pop(header)
            except:
                pass
        for header in native_headers + content_headers:
            try:
                val = packet[header]
                concrete_packet[header] = val
            except:
                pass
        extended_values = extended_values_from(packet)
        if extended_values:
            vlan_id, vlan_pcp = self.encode_extended_values(extended_values)
            concrete_packet['vlan_id'] = vlan_id
            concrete_packet['vlan_pcp'] = vlan_pcp
        return concrete_packet

    def handle_flow_stats_reply(self, switch, flow_stats):
        def convert(f,val):
            if f == 'match':
                import ast
                val = ast.literal_eval(val)
                return { g : convert(g,v) for g,v in val.items() }
            if f == 'actions':
                import ast
                vals = ast.literal_eval(val)
                return [ { g : convert(g,v) for g,v in val.items() }
                         for val in vals ]
            if f in ['srcmac','dstmac']:
                return MAC(val)
            elif f in ['srcip','dstip']:
                return IP(val)
            else:
                return val
        flow_stats = [ { f : convert(f,v) 
                         for (f,v) in flow_stat.items() }
                       for flow_stat in flow_stats       ]
        flow_stats = sorted(flow_stats, key=lambda d: -d['priority'])
        def flow_stat_str(flow_stat):
            output = str(flow_stat['priority']) + ':\t' 
            output += str(flow_stat['match']) + '\n\t->'
            output += str(flow_stat['actions']) + '\n\t'
            output += 'packet_count=' + str(flow_stat['packet_count']) 
            output += '\tbyte_count=' + str(flow_stat['byte_count'])
            return output
        self.log.debug(
            '|%s|\n\t%s\n' % (str(datetime.now()),
                '\n'.join(['flow table for switch='+repr(switch)] + 
                    [flow_stat_str(f) for f in flow_stats])))
        with self.global_outstanding_queries_lock:
            if switch in self.global_outstanding_queries:
                for bucket in self.global_outstanding_queries[switch]:
                    bucket.handle_flow_stats_reply(switch, flow_stats)
                del self.global_outstanding_queries[switch]

    def concrete2pyretic(self,packet):
        def convert(h,val):
            if h in ['srcmac','dstmac']:
                return MAC(val)
            elif h in ['srcip','dstip']:
                return IP(val)
            else:
                return val
        try:
            vlan_id = packet['vlan_id']
            vlan_pcp = packet['vlan_pcp']
            extended_values = self.decode_extended_values(vlan_id, vlan_pcp)
        except KeyError:
            extended_values = util.frozendict()       
        pyretic_packet = Packet(extended_values)
        d = { h : convert(h,v) for (h,v) in packet.items() if not h in ['vlan_id','vlan_pcp'] }
        return pyretic_packet.modifymany(d)

    def send_packet(self,pyretic_packet):
        concrete_packet = self.pyretic2concrete(pyretic_packet)
        self.backend.send_packet(concrete_packet)

    def install_classifier(self, classifier, this_update_no=None, current_update_no=None):
        if classifier is None:
            return

        ### CLASSIFIER TRANSFORMS 

        def remove_drop(classifier):
            return Classifier(Rule(rule.match,
                                   filter(lambda a: a != drop,rule.actions))
                              for rule in classifier.rules)

        def remove_identity(classifier):
            # DISCUSS (cole): convert identity to inport rather
            # than drop?
            return Classifier(Rule(rule.match,
                                   filter(lambda a: a != identity,rule.actions))
                              for rule in classifier.rules)

        def send_drops_to_controller(classifier):
            def replace_empty_with_controller(actions):
                if len(actions) == 0:
                    return [Controller]
                else:
                    return actions
            return Classifier(Rule(rule.match,
                                   replace_empty_with_controller(rule.actions))
                              for rule in classifier.rules)
                
        def controllerify(classifier):
            def controllerify_rule(rule):
                if reduce(lambda acc, a: acc | (a == Controller),rule.actions,False):
                    # DISCUSS (cole): should other actions be taken at the switch
                    # before sending to the controller?  i.e. a policy like:
                    # modify(srcip=1) >> ToController.
                    return Rule(rule.match,[Controller])
                else:
                    return rule
            return Classifier(controllerify_rule(rule) 
                              for rule in classifier.rules)

        def vlan_specialize(classifier):
            """Add Openflow's "default" VLAN match to identify packets which
            don't have any VLAN tags on them.
            """
            specialized_rules = []
            default_vlan_match = match(vlan_id=0xFFFF, vlan_pcp=0)
            for rule in classifier.rules:
                if ( ( isinstance(rule.match, match) and
                       not 'vlan_id' in rule.match.map ) or
                     rule.match == identity ):
                    specialized_rules.append(Rule(rule.match.intersect(default_vlan_match),
                                                  rule.actions))
                else:
                    specialized_rules.append(rule)
            return Classifier(specialized_rules)

        def layer_3_specialize(classifier):
            specialized_rules = []
            #Add a rule that routes the LLDP messages to the controller for topology maintenance.
            specialized_rules.append(Rule(match(ethtype=LLDP_TYPE),[Controller]))
            for rule in classifier.rules:
                if ( isinstance(rule.match, match) and
                     ( 'srcip' in rule.match.map or 
                       'dstip' in rule.match.map ) and 
                     not 'ethtype' in rule.match.map ):
                    specialized_rules.append(Rule(rule.match & match(ethtype=IP_TYPE),rule.actions))

                    # DEAL W/ BUG IN OVS ACCEPTING ARP RULES THAT AREN'T ACTUALLY EXECUTED
                    arp_bug = False
                    for action in rule.actions:
                        if action == Controller or isinstance(action, CountBucket):
                            pass
                        elif len(action.map) > 1:
                            arp_bug = True
                            break
                    if arp_bug:
                        specialized_rules.append(Rule(rule.match & match(ethtype=ARP_TYPE),[Controller]))
                    else:
                        specialized_rules.append(Rule(rule.match & match(ethtype=ARP_TYPE),rule.actions))
                else:
                    specialized_rules.append(rule)
            return Classifier(specialized_rules)

        def bookkeep_buckets(classifier):
            """Whenever rules are associated with counting buckets,
            add a reference to the classifier rule into the respective
            bucket for querying later. Count bucket actions operate at
            the pyretic level and are removed before installing rules.
            """
            def collect_buckets(rules):
                """Scan classifier rules and collect distinct buckets into a
                dictionary.
                """
                bucket_list = {}
                for rule in rules:
                    for act in rule.actions:
                        if isinstance(act, CountBucket):
                            if not id(act) in bucket_list:
                                bucket_list[id(act)] = act
                return bucket_list

            def start_update(bucket_list):
                for b in bucket_list.values():
                    b.start_update()

            def hook_buckets_to_rule(rule):
                for act in rule.actions:
                    if isinstance(act, CountBucket):
                        act.add_match(rule.match)

            def hook_buckets_to_pull_stats(bucket_list):
                for b in bucket_list.values():
                    b.add_pull_stats(self.pull_stats_for_bucket(b))

            def finish_update(bucket_list):
                for b in bucket_list.values():
                    b.finish_update()

            with self.update_buckets_lock:
                """The start_update and finish_update functions per bucket guard
                against inconsistent state in a single bucket, and the global
                "update buckets" lock guards against inconsistent classifier
                match state *across* buckets.
                """
                bucket_list = collect_buckets(classifier.rules)
                start_update(bucket_list)
                map(hook_buckets_to_rule, classifier.rules)
                hook_buckets_to_pull_stats(bucket_list)
                finish_update(bucket_list)
        
        def remove_buckets(classifier):
            return Classifier(Rule(rule.match,
                                   filter(lambda a: 
                                          not isinstance(a, CountBucket),
                                          rule.actions))
                              for rule in classifier.rules)

        def switchify(classifier,switches):
            new_rules = list()
            for rule in classifier.rules:
                if isinstance(rule.match, match) and 'switch' in rule.match.map:
                    if not rule.match.map['switch'] in switches:
                        continue
                    new_rules.append(rule)
                else:
                    for s in switches:
                        new_rules.append(Rule(
                                rule.match.intersect(match(switch=s)),
                                rule.actions))
            return Classifier(new_rules)

        def concretize(classifier):
            def concretize_rule_actions(rule):
                def concretize_match(pred):
                    if pred == false:
                        return None
                    elif pred == true:
                        return {}
                    elif isinstance(pred, match):
                        return { k:v for (k,v) in pred.map.items() }
                def concretize_action(a):
                    if a == Controller:
                        return {'outport' : OFPP_CONTROLLER}
                    elif isinstance(a,modify):
                        return { k:v for (k,v) in a.map.items() }
                    else: # default
                        return a
                m = concretize_match(rule.match)
                acts = [concretize_action(a) for a in rule.actions]
                if m is None:
                    return None
                else:
                    return Rule(m,acts)
            crs = [concretize_rule_actions(r) for r in classifier.rules]
            crs = filter(lambda cr: not cr is None,crs)
            return Classifier(crs)

        def portize(classifier,switch_to_attrs):
            import copy
            specialized_rules = []
            for rule in classifier.rules:
                phys_actions = filter(lambda a: a['outport'] != OFPP_CONTROLLER and a['outport'] != OFPP_IN_PORT,rule.actions)
                phys_outports = map(lambda a: a['outport'], phys_actions)
                if not 'inport' in rule.match:
                    switch = rule.match['switch']
                    phys_outports = switch_to_attrs[switch]['ports'].keys()
                    for outport in phys_outports:
                        new_match = copy.deepcopy(rule.match)
                        new_match['inport'] = outport
                        new_actions = copy.deepcopy(rule.actions)
                        for action in new_actions:
                            try:
                                if action['outport'] == outport:
                                    action['outport'] = OFPP_IN_PORT
                            except:
                                raise TypeError  # INVARIANT: every set of actions must go out a port
                            # this may not hold when we move to OF 1.3
                        specialized_rules.append(Rule(new_match,new_actions))
                specialized_rules.append(rule)
            return Classifier(specialized_rules)

        def prioritize(classifier,switches):
            priority = {}
            for s in switches:
                priority[s] = 60000
            tuple_rules = list()
            for rule in classifier.rules:
                s = rule.match['switch']
                tuple_rules.append((rule.match,priority[s],rule.actions))
                priority[s] -= 1
            return tuple_rules

        ### UPDATE LOGIC

        def nuclear_install(classifier):
            switch_attrs_tuples = self.network.topology.nodes(data=True)
            switch_to_attrs = { k : v for (k,v) in switch_attrs_tuples }
            switches = switch_to_attrs.keys()
            classifier = switchify(classifier,switches)
            classifier = concretize(classifier)
            classifier = portize(classifier,switch_to_attrs)
            new_rules = prioritize(classifier,switches)

            for s in switches:
                self.send_barrier(s)
                self.send_clear(s)
                self.send_barrier(s)
                self.install_rule(({'switch' : s},TABLE_MISS_PRIORITY,[{'outport' : OFPP_CONTROLLER}]))

            for rule in new_rules:
                self.install_rule(rule)
                
            for s in switches:
                self.send_barrier(s)
                if self.verbosity >= self.verbosity_numeric('please-make-it-stop'):
                    self.request_flow_stats(s)


        ### INCREMENTAL UPDATE LOGIC

        def find_same_rule(target, rule_list):
            if rule_list is None:
                return None
            for rule in rule_list:
                if target[0] == rule[0] and target[1] == rule[1]:
                    return rule
            return None

        def install_diff_rules(classifier):
            with self.old_rules_lock:
                old_rules = self.old_rules
                switch_attrs_tuples = self.network.topology.nodes(data=True)
                switch_to_attrs = { k : v for (k,v) in switch_attrs_tuples }
                switches = switch_to_attrs.keys()
                classifier = switchify(classifier,switches)
                classifier = concretize(classifier)
                classifier = portize(classifier,switch_to_attrs)
                new_rules = prioritize(classifier,switches)

                # calculate diff
                to_add = list()
                to_delete = list()
                to_modify = list()
                for old in old_rules:
                    new = find_same_rule(old, new_rules)
                    if new is None:
                        to_delete.append(old)
                    else:
                        if old[2] != new[2]:
                            to_modify.append(new)
    
                for new in new_rules:
                    old = find_same_rule(new, old_rules)
                    if old is None:
                        to_add.append(new)
    
                # install diff
                if not to_add is None:
                    for rule in to_add:
                        self.install_rule(rule)
                for rule in to_delete:
                    if rule[0]['switch'] in switches:
                        self.delete_rule((rule[0], rule[1]))
                for rule in to_modify:
                    self.delete_rule((rule[0], rule[1]))
                    self.install_rule(rule)
    
                # update old_rule
                del old_rules[0:len(old_rules)]
                for rule in new_rules:
                    old_rules.append(rule)

                for s in switches:
                    self.send_barrier(s)

        ### PROCESS THAT DOES INSTALL

        def f(classifier, this_update_no, current_update_no):
            if not this_update_no is None:
                time.sleep(0.1)
                if this_update_no != current_update_no.value:
                    return

            if self.mode == 'proactive0':
                nuclear_install(classifier)
            elif self.mode == 'proactive1':
                install_diff_rules(classifier)

        # Process classifier to an openflow-compatible format before
        # sending out rule installs
        classifier = remove_drop(classifier)
        #classifier = send_drops_to_controller(classifier)
        classifier = remove_identity(classifier)
        classifier = controllerify(classifier)
        classifier = layer_3_specialize(classifier)
        classifier = vlan_specialize(classifier)
        bookkeep_buckets(classifier)
        classifier = remove_buckets(classifier)

        p = Process(target=f,args=(classifier,this_update_no,current_update_no))
        p.daemon = True
        p.start()
            
    def install_rule(self,(concrete_pred,priority,action_list)):
        self.log.debug(
            '|%s|\n\t%s\n\t%s\n' % (str(datetime.now()),
                "sending openflow rule:",
                (str(priority) + " " + repr(concrete_pred) + " "+ repr(action_list))))
        self.backend.send_install(concrete_pred,priority,action_list)

    def delete_rule(self,(concrete_pred,priority)):
        self.backend.send_delete(concrete_pred,priority)

    def send_barrier(self,switch):
        self.backend.send_barrier(switch)

    def send_clear(self,switch):
        self.backend.send_clear(switch)

    def clear_all(self,this_update_no=None,current_update_no=None):
        def f(this_update_no, current_update_no):
            if not this_update_no is None:
                time.sleep(0.1)
                if this_update_no != current_update_no.value:
                    return
            switches = self.network.topology.nodes()
            for s in switches:
                self.send_barrier(s)
                self.send_clear(s)
                self.send_barrier(s)
                self.install_rule(({'switch' : s},TABLE_MISS_PRIORITY,[{'outport' : OFPP_CONTROLLER}]))
        p = Process(target=f,args=(this_update_no,current_update_no))
        p.daemon = True
        p.start()

    def pull_stats_for_bucket(self,bucket):
        """Returns a function that can be used by counting buckets to
        issue queries from the runtime."""
        def pull_bucket_stats():
            switch_list = []
            for m in bucket.matches:
                if m == identity:
                    concrete_pred = {}
                else:
                    assert(isinstance(m, match))
                    concrete_pred = { k:v for (k,v) in m.map.items() }
                if 'switch' in concrete_pred:
                    switch_list.append(concrete_pred['switch'])
                else:
                    switch_list = self.network.topology.nodes()
                    break
            for s in switch_list:
                bucket.add_outstanding_switch_query(s)
                already_queried = self.add_global_outstanding_query(s, bucket)
                if not already_queried:
                    self.request_flow_stats(s)
        return pull_bucket_stats

    def add_global_outstanding_query(self, s, bucket):
        already_queried = False
        with self.global_outstanding_queries_lock:
            if not s in self.global_outstanding_queries:
                self.global_outstanding_queries[s] = [bucket]
            else:
                self.global_outstanding_queries[s].append(bucket)
                already_queried = True
        return already_queried

    def request_flow_stats(self,switch):
        self.backend.send_flow_stats_request(switch)

    def inject_discovery_packet(self,dpid, port):
        self.backend.inject_discovery_packet(dpid,port)

    def encode_extended_values(self, extended_values):
        with self.extended_values_lock:
            vlan = self.extended_values_to_vlan_db.get(extended_values)
            if vlan is not None:
                return vlan
            r = 1+len(self.extended_values_to_vlan_db) #VLAN ZERO IS RESERVED
            pcp = r & 0b111000000000000
            vid = r & 0b000111111111111
            self.extended_values_to_vlan_db[extended_values] = (vid, pcp)
            self.vlan_to_extended_values_db[(vid, pcp)] = extended_values
            return (vid, pcp)
        
    def decode_extended_values(self, vid, pcp):
        with self.extended_values_lock:
            extended_values = self.vlan_to_extended_values_db.get((vid, pcp))
            assert extended_values is not None, "use of vlan that pyretic didn't allocate! not allowed."
            return extended_values


################################################################################
# Extended Values
################################################################################

@util.cached
def extended_values_from(packet):
    extended_values = {}
    for k, v in packet.header.items():
        if k not in basic_headers + content_headers + location_headers and v:
            extended_values[k] = v
    return util.frozendict(extended_values)


################################################################################
# Concrete Packet and Network
################################################################################

class ConcretePacket(dict):
    pass

class ConcreteNetwork(Network):
    def __init__(self,runtime=None):
        super(ConcreteNetwork,self).__init__()
        self.runtime = runtime
        self.log = logging.getLogger('%s.ConcreteNetwork' % __name__)
        self.debug_log = logging.getLogger('%s.DEBUG_TOPO_DISCOVERY' % __name__)
        self.debug_log.setLevel(logging.WARNING)

    def inject_packet(self, pkt):
        self.runtime.send_packet(pkt)

    #
    # Topology Detection
    #

    def update_network(self):
        self.runtime.update_network()
           
    def inject_discovery_packet(self, dpid, port_no):
        self.runtime.inject_discovery_packet(dpid, port_no)
        
    def handle_switch_join(self, switch):
        self.debug_log.debug("handle_switch_joins")
        ## PROBABLY SHOULD CHECK TO SEE IF SWITCH ALREADY IN TOPOLOGY
        self.topology.add_switch(switch)
        self.log.info("OpenFlow switch %s connected" % switch)
        self.debug_log.debug(str(self.topology))
        self.update_network()

    def remove_associated_link(self,location):
        port = self.topology.node[location.switch]["ports"][location.port_no]
        if not port.linked_to is None:
            # REMOVE CORRESPONDING EDGE
            try:      
                self.topology.remove_edge(location.switch, port.linked_to.switch)
            except:
                pass  # ALREADY REMOVED
            # UNLINK LINKED_TO PORT
            try:      
                self.topology.node[port.linked_to.switch]["ports"][port.linked_to.port_no].linked_to = None
            except KeyError:
                pass  # LINKED TO PORT ALREADY DELETED
            # UNLINK SELF
            self.topology.node[location.switch]["ports"][location.port_no].linked_to = None
        
    def handle_switch_part(self, switch):
        self.log.info("OpenFlow switch %s disconnected" % switch)
        self.debug_log.debug("handle_switch_parts")
        # REMOVE ALL ASSOCIATED LINKS
        for port_no in self.topology.node[switch]["ports"].keys():
            self.remove_associated_link(Location(switch,port_no))
        self.topology.remove_node(switch)
        self.debug_log.debug(str(self.topology))
        self.update_network()
        
    def handle_port_join(self, switch, port_no, config, status):
        self.debug_log.debug("handle_port_joins %s:%s:%s:%s" % (switch, port_no, config, status))
        self.topology.add_port(switch,port_no,config,status)
        if config or status:
            self.inject_discovery_packet(switch,port_no)
            self.debug_log.debug(str(self.topology))
            self.update_network()

    def handle_port_part(self, switch, port_no):
        self.debug_log.debug("handle_port_parts")
        try:
            self.remove_associated_link(Location(switch,port_no))
            del self.topology.node[switch]["ports"][port_no]
            self.debug_log.debug(str(self.topology))
            self.update_network()
        except KeyError:
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY handle_switch_parts
        
    def handle_port_mod(self, switch, port_no, config, status):
        self.debug_log.debug("handle_port_mods %s:%s:%s:%s" % (switch, port_no, config, status))
        # GET PREV VALUES
        try:
            prev_config = self.topology.node[switch]["ports"][port_no].config
            prev_status = self.topology.node[switch]["ports"][port_no].status
        except KeyError:
            self.log.warning("KeyError CASE!!!!!!!!")
            self.port_down(switch, port_no)
            return

        # UPDATE VALUES
        self.topology.node[switch]["ports"][port_no].config = config
        self.topology.node[switch]["ports"][port_no].status = status

        # DETERMINE IF/WHAT CHANGED
        if (prev_config and not config):
            self.port_down(switch, port_no)
        if (prev_status and not status):
            self.port_down(switch, port_no,double_check=True)

        if (not prev_config and config) or (not prev_status and status):
            self.port_up(switch, port_no)

    def port_up(self, switch, port_no):
        self.debug_log.debug("port_up %s:%s" % (switch,port_no))
        self.inject_discovery_packet(switch,port_no)
        self.debug_log.debug(str(self.topology))
        self.update_network()

    def port_down(self, switch, port_no, double_check=False):
        self.debug_log.debug("port_down %s:%s:double_check=%s" % (switch,port_no,double_check))
        try:
            self.remove_associated_link(Location(switch,port_no))
            self.debug_log.debug(str(self.topology))
            self.update_network()
            if double_check: self.inject_discovery_packet(switch,port_no)
        except KeyError:  
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY handle_switch_parts

    def handle_link_update(self, s1, p_no1, s2, p_no2):
        self.debug_log.debug("handle_link_updates")
        try:
            p1 = self.topology.node[s1]["ports"][p_no1]
            p2 = self.topology.node[s2]["ports"][p_no2]
        except KeyError:
            self.log.warning("node doesn't yet exist")
            return  # at least one of these ports isn't (yet) in the topology

        # LINK ALREADY EXISTS
        try:
            link = self.topology[s1][s2]

            # LINK ON SAME PORT PAIR
            if link[s1] == p_no1 and link[s2] == p_no2:         
                if p1.possibly_up() and p2.possibly_up():   
                    self.debug_log.debug("nothing to do")
                    return                                      #   NOTHING TO DO
                else:                                           # ELSE RAISE AN ERROR - SOMETHING WEIRD IS HAPPENING
                    raise RuntimeError('Link update w/ bad port status %s,%s' % (p1,p2))
            # LINK PORTS CHANGED
            else:                                               
                # REMOVE OLD LINKS
                if link[s1] != p_no1:
                    self.remove_associated_link(Location(s1,link[s1]))
                if link[s2] != p_no2:
                    self.remove_associated_link(Location(s2,link[s2]))

        # COMPLETELY NEW LINK
        except KeyError:     
            pass
        
        # ADD LINK IF PORTS ARE UP
        if p1.possibly_up() and p2.possibly_up():
            self.topology.node[s1]["ports"][p_no1].linked_to = Location(s2,p_no2)
            self.topology.node[s2]["ports"][p_no2].linked_to = Location(s1,p_no1)   
            self.topology.add_edge(s1, s2, {s1: p_no1, s2: p_no2})
            
        # IF REACHED, WE'VE REMOVED AN EDGE, OR ADDED ONE, OR BOTH
        self.debug_log.debug(self.topology)
        self.update_network()

