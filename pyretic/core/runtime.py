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
from pyretic.core.language_tools import *
from pyretic.core.network import *
from pyretic.core.packet import *

from multiprocessing import Process, Manager, RLock, Lock, Value, Queue, Condition
import logging, sys, time
from datetime import datetime

TABLE_MISS_PRIORITY = 0

class Runtime(object):
    """
    The Runtime system.  Includes packet handling, compilation to OF switches,
    topology maintenance, dynamic update of policies, querying support, etc.
    
    :param backend: handles the connection to switches
    :type backend: Backend
    :param main: the program to run
    :type main: pyretic program (.py)
    :param kwargs: arguments to main
    :type kwargs: dict from strings to values
    :param mode: one of interpreted/i, reactive0/r0, proactive0/p0
    :type mode: string
    :param verbosity: one of low, normal, high, please-make-it-stop
    :type verbosity: string
    """
    def __init__(self, backend, main, kwargs, mode='interpreted', verbosity='normal'):
        self.verbosity = self.verbosity_numeric(verbosity)
        self.log = logging.getLogger('%s.Runtime' % __name__)
        self.network = ConcreteNetwork(self)
        self.prev_network = self.network.copy()
        self.policy = main(**kwargs)
        self.mode = mode
        self.backend = backend
        self.backend.runtime = self
        self.policy_lock = RLock()
        self.network_lock = Lock()
        self.switch_lock = Lock()
        self.vlan_to_extended_values_db = {}
        self.extended_values_to_vlan_db = {}
        self.extended_values_lock = RLock()
        self.dynamic_sub_pols = set()
        self.update_dynamic_sub_pols()
        self.in_network_update = False
        self.in_bucket_apply = False
        self.network_triggered_policy_update = False
        self.bucket_triggered_policy_update = False
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


######################
# PACKET INTERPRETER 
######################

    def handle_packet_in(self, concrete_pkt):
        """
        The packet interpreter.
        
        :param concrete_packet: the packet to be interpreted.
        :type limit: payload of an OpenFlow packet_in message.
        """
        with self.policy_lock:
            pyretic_pkt = self.concrete2pyretic(concrete_pkt)

            # find the queries, if any in the policy, that will be evaluated
            queries,pkts = queries_in_eval((set(),{pyretic_pkt}),self.policy)

            # evaluate the policy
            output = self.policy.eval(pyretic_pkt)

            # apply the queries whose buckets have received new packets
            self.in_bucket_apply = True
            for q in queries:
                q.apply()
            self.in_bucket_apply = False
            
            # if the query changed the policy, update the controller and switch state
            if self.bucket_triggered_policy_update:
                self.update_dynamic_sub_pols()
                self.update_switch_classifiers()
                self.bucket_triggered_policy_update = False
                    
        # send output of evaluation into the network
        concrete_output = map(self.pyretic2concrete,output)
        map(self.send_packet,concrete_output)

        # if in reactive mode and no packets are forwarded to buckets, install microflow
        # Note: lack of forwarding to bucket implies no bucket-trigger update could have occured
        if self.mode == 'reactive0' and not queries:
            self.reactive0_install(pyretic_pkt,output)


#############
# DYNAMICS  
#############

    def handle_policy_change(self,sub_pol):
        """
        Updates runtime behavior (both interpreter and switch classifiers)
        some sub-policy in self.policy changes.
        """
        with self.policy_lock:

            # tag stale classifiers as invalid
            map(lambda p: p.invalidate_classifier(), 
                on_recompile_path(set(),id(sub_pol),self.policy))

            # if change was driven by a network update, flag
            if self.in_network_update:
                self.network_triggered_policy_update = True

            # if this change driven by a bucket side-effect, flag
            elif self.in_bucket_apply:
                self.bucket_triggered_policy_update = True

            # otherwise, update controller and switches accordingly
            else:
                self.update_dynamic_sub_pols()
                self.update_switch_classifiers()


    def handle_network_change(self):
        """
        Updates runtime behavior (both interpreter and switch classifiers)
        when the concrete network topology changes.
        """
        with self.network_lock:

            # if the topology hasn't changed, ignore
            if self.network.topology == self.prev_network.topology:
                return

            # otherwise copy the network object
            self.in_network_update = True
            self.prev_network = self.network.copy()

            # update the policy w/ the new network object
            with self.policy_lock:
                for policy in self.dynamic_sub_pols:
                    policy.set_network(self.network)

                # FIXME(joshreich) :-)
                # This is a temporary fix. We need to specialize the check below
                # instead of removing it completely, but will let @joshreich
                # take care of it. -- ngsrinivas
                # if self.network_triggered_policy_update:
                self.update_dynamic_sub_pols()
                self.update_switch_classifiers()
                self.network_triggered_policy_update = False

            self.in_network_update = False

    
    def update_switch_classifiers(self):
        """
        Updates switch classifiers
        """
        classifier = None
        
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


    def update_dynamic_sub_pols(self):
        """
        Updates the set of active dynamic sub-policies in self.policy
        """
        import copy
        old_dynamic_sub_pols = copy.copy(self.dynamic_sub_pols)
        self.dynamic_sub_pols = ast_fold(add_dynamic_sub_pols, set(), self.policy)
        for p in (old_dynamic_sub_pols - self.dynamic_sub_pols):
            p.detach()
        for p in (self.dynamic_sub_pols - old_dynamic_sub_pols):
            p.set_network(self.network)
            p.attach(self.handle_policy_change)


#######################
# REACTIVE COMPILATION
#######################

    def reactive0_install(self,in_pkt,out_pkts):
        """
        Reactively installs switch table entries based on a given policy evaluation.

        :param in_pkt: the input on which the policy was evaluated
        :type in_pkt: Packet
        :param out_pkts: the output of the evaluation
        :type out_pkts: set Packet
        """
        rule_tuple = self.match_on_all_fields_rule_tuple(in_pkt,out_pkts)
        if rule_tuple:
            self.install_rule(rule_tuple)
            self.log.debug(
                '|%s|\n\t%s\n\t%s\n\t%s\n' % (str(datetime.now()),
                                              " | install rule",
                                              rule_tuple[0],
                                              'actions='+repr(rule_tuple[2])))

    def match_on_all_fields(self, pkt):
        """
        Produces a concrete predicate exactly matching a given packet.

        :param pkt: the packet to match
        :type pkt: Packet
        :returns: an exact-match predicate 
        :rtype: dict of strings to values
        """        
        pred = pkt.copy()
        del pred['header_len']
        del pred['payload_len']
        del pred['raw']
        return pred

    def match_on_all_fields_rule_tuple(self, pkt_in, pkts_out):
        """
        Produces a rule tuple exactly matching a given packet 
        and outputing a given set of packets..

        :param pkt_in: the input packet
        :type pkt_in: Packet
        :param pkts_out: the output packets
        :type pkts_out: set Packet
        :returns: an exact-match (microflow) rule 
        :rtype: (dict of strings to values, int, list int)
        """        
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


#########################
# PROACTIVE COMPILATION 
#########################

    def install_classifier(self, classifier):
        """
        Proactively installs switch table entries based on the input classifier

        :param classifier: the input classifer
        :type classifier: Classifier
        """
        if classifier is None:
            return

        ### CLASSIFIER TRANSFORMS 

        # TODO (josh) logic for detecting action sets that can't be compiled
        # e.g., {modify(dstip='10.0.0.1',outport=1),modify(srcip='10.0.0.2',outport=2)]

        def remove_identity(classifier):
            """
            Removes identity policies from the action list.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
            return Classifier(Rule(rule.match,
                                   filter(lambda a: a != identity,rule.actions))
                              for rule in classifier.rules)
                
        def controllerify(classifier):
            """
            Replaces each rule whose actions includes a send to controller action
            with one whose sole action sends packets to the controller. (Thereby
            avoiding the tricky situation of needing to determine whether a given 
            packet reached the controller b/c that packet is being forwarded to a 
            query bucket or b/c corresponding rules haven't yet been installed.
                        
            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
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
            """
            Add Openflow's "default" VLAN match to identify packets which
            don't have any VLAN tags on them.

            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
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
            """
            Specialize a layer-3 rule to several rules that match on layer-2 fields.
            OpenFlow requires a layer-3 match to match on layer-2 ethtype.  Also, 
            make sure that LLDP packets are reserved for use by the runtime.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
            specialized_rules = []
            # Add a rule that routes the LLDP messages to the controller for topology maintenance.
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
            """
            Whenever rules are associated with counting buckets,
            add a reference to the classifier rule into the respective
            bucket for querying later. Count bucket actions operate at
            the pyretic level and are removed before installing rules.

            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
            def collect_buckets(rules):
                """
                Scan classifier rules and collect distinct buckets into a
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
            """
            Remove CountBucket policies from classifier rule actions.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
            return Classifier(Rule(rule.match,
                                   filter(lambda a: 
                                          not isinstance(a, CountBucket),
                                          rule.actions))
                              for rule in classifier.rules)

        def switchify(classifier,switches):
            """
            Specialize a classifer to a set of switches.  Any rule that doesn't 
            specify a match on switch is turned into a set of rules matching on
            each switch respectively.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            :param switches: the network switches
            :type switches: set int
            :returns: the output classifier
            :rtype: Classifier
            """
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
            """
            Convert policies into dictionaries.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
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

        def check_OF_rules(classifier):
            def check_OF_rule_has_outport(r):
                for a in r.actions:
                    if not 'outport' in a:
                        raise TypeError('Invalid rule: concrete actions must have an outport',str(r))  
            def check_OF_rule_has_compilable_action_list(r):
                if len(r.actions)<2:
                    pass
                else:
                    moded_fields = set(r.actions[0].keys())
                    for a in r.actions:
                        fields = set(a.keys())
                        if fields - moded_fields:
                            raise TypeError('Non-compilable rule',str(r))  
            for r in classifier.rules:
                check_OF_rule_has_outport(r)
                check_OF_rule_has_compilable_action_list(r)
            return Classifier(classifier.rules)

        def OF_inportize(classifier):
            """
            Specialize classifier to ensure that packets to be forwarded 
            out the inport on which they arrived are handled correctly.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
            import copy
            def specialize_actions(actions,outport):
                new_actions = copy.deepcopy(actions)
                for action in new_actions:
                    try:
                        if action['outport'] == outport:
                            action['outport'] = OFPP_IN_PORT
                    except:
                        raise TypeError  # INVARIANT: every set of actions must go out a port
                                         # this may not hold when we move to OF 1.3
                return new_actions

            specialized_rules = []
            for rule in classifier.rules:
                phys_actions = filter(lambda a: (a['outport'] != OFPP_CONTROLLER 
                                                 and a['outport'] != OFPP_IN_PORT),
                                      rule.actions)
                outports_used = map(lambda a: a['outport'], phys_actions)
                if not 'inport' in rule.match:
                    # Add a modified rule for each of the outports_used
                    switch = rule.match['switch']
                    for outport in outports_used:
                        new_match = copy.deepcopy(rule.match)
                        new_match['inport'] = outport
                        new_actions = specialize_actions(rule.actions,outport)
                        specialized_rules.append(Rule(new_match,new_actions))
                    # And a default rule for any inport outside the set of outports_used
                    specialized_rules.append(rule)
                else:
                    if rule.match['inport'] in outports_used:
                        # Modify the set of actions
                        new_actions = specialize_actions(rule.actions,rule.match['inport'])
                        specialized_rules.append(Rule(rule.match,new_actions))
                    else:
                        # Leave as before
                        specialized_rules.append(rule)

            return Classifier(specialized_rules)

        def prioritize(classifier):
            """
            Add priorities to classifier rules based on their ordering.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
            priority = {}
            tuple_rules = list()
            for rule in classifier.rules:
                s = rule.match['switch']
                try:
                    priority[s] -= 1
                except KeyError:
                    priority[s] = 60000
                tuple_rules.append((rule.match,priority[s],rule.actions))
            return tuple_rules

        ### UPDATE LOGIC

        def nuclear_install(classifier):
            """
            Delete all rules currently installed on switches and then
            install input classifier from scratch.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            """
            switch_attrs_tuples = self.network.topology.nodes(data=True)
            switch_to_attrs = { k : v for (k,v) in switch_attrs_tuples }
            switches = switch_to_attrs.keys()
            classifier = switchify(classifier,switches)
            classifier = concretize(classifier)
            classifier = check_OF_rules(classifier)
            classifier = OF_inportize(classifier)
            new_rules = prioritize(classifier)

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
            """
            Calculate and install the difference between the input classifier
            and the current switch tables.
            
            :param classifier: the input classifer
            :type classifier: Classifier
            """
            with self.old_rules_lock:
                old_rules = self.old_rules
                switch_attrs_tuples = self.network.topology.nodes(data=True)
                switch_to_attrs = { k : v for (k,v) in switch_attrs_tuples }
                switches = switch_to_attrs.keys()
                classifier = switchify(classifier,switches)
                classifier = concretize(classifier)
                classifier = OF_inportize(classifier)
                new_rules = prioritize(classifier)

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

        def f(classifier):
            with self.switch_lock:
                if self.mode == 'proactive0':
                    nuclear_install(classifier)
                elif self.mode == 'proactive1':
                    install_diff_rules(classifier)

        # Process classifier to an openflow-compatible format before
        # sending out rule installs
        #classifier = send_drops_to_controller(classifier)
        classifier = remove_identity(classifier)
        classifier = controllerify(classifier)
        classifier = layer_3_specialize(classifier)
        classifier = vlan_specialize(classifier)
        bookkeep_buckets(classifier)
        classifier = remove_buckets(classifier)

        p = Process(target=f,args=(classifier,))
        p.daemon = True
        p.start()


###################
# QUERYING SUPPORT
###################

    def pull_stats_for_bucket(self,bucket):
        """
        Returns a function that can be used by counting buckets to
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


####################################
# PACKET MARSHALLING/UNMARSHALLING 
####################################

    def concrete2pyretic(self,raw_pkt):
        packet = get_packet_processor().unpack(raw_pkt['raw'])
        packet['raw'] = raw_pkt['raw']
        packet['switch'] = raw_pkt['switch']
        packet['inport'] = raw_pkt['inport']

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
    def pyretic2concrete(self,packet):
        concrete_packet = {}
        headers         = {}

        for header in ['switch','inport','outport']:
            try:
                concrete_packet[header] = packet[header]
                headers[header]         = packet[header]
                packet = packet.pop(header)
            except:
                pass
        for header in native_headers + content_headers:
            try:
                val = packet[header]
                concrete_packet[header] = val
            except:
                pass
        for header in packet.header:
            try:
                if header in ['switch', 'inport', 'outport']: next
                val = packet[header]
                headers[header] = val
            except:
                pass
        extended_values = extended_values_from(packet)
        if extended_values:
            vlan_id, vlan_pcp = self.encode_extended_values(extended_values)
            concrete_packet['vlan_id'] = vlan_id
            concrete_packet['vlan_pcp'] = vlan_pcp
        concrete_packet['raw'] = get_packet_processor().pack(headers)
        return concrete_packet

#######################
# TO OPENFLOW         
#######################

    def send_packet(self,concrete_packet):
        self.backend.send_packet(concrete_packet)

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

    def clear_all(self):
        def f():
            switches = self.network.topology.nodes()
            for s in switches:
                self.send_barrier(s)
                self.send_clear(s)
                self.send_barrier(s)
                self.install_rule(({'switch' : s},TABLE_MISS_PRIORITY,[{'outport' : OFPP_CONTROLLER}]))
        p = Process(target=f)
        p.daemon = True
        p.start()

    def request_flow_stats(self,switch):
        self.backend.send_flow_stats_request(switch)

    def inject_discovery_packet(self,dpid, port):
        self.backend.inject_discovery_packet(dpid,port)


#######################
# FROM OPENFLOW       
#######################

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
            

##########################
# VIRTUAL HEADER SUPPORT 
##########################

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

@util.cached
def extended_values_from(packet):
    extended_values = {}
    for k, v in packet.header.items():
        if k not in basic_headers + content_headers + location_headers and v:
            extended_values[k] = v
    return util.frozendict(extended_values)


################################################################################
# Concrete Network
################################################################################

import threading 

class ConcreteNetwork(Network):
    def __init__(self,runtime=None):
        super(ConcreteNetwork,self).__init__()
        self.next_topo = self.topology.copy()
        self.runtime = runtime
        self.wait_period = 0.25
        self.update_no_lock = threading.Lock()
        self.update_no = 0
        self.log = logging.getLogger('%s.ConcreteNetwork' % __name__)
        self.debug_log = logging.getLogger('%s.DEBUG_TOPO_DISCOVERY' % __name__)
        self.debug_log.setLevel(logging.DEBUG)

    def inject_packet(self, pkt):
        concrete_pkt = self.runtime.pyretic2concrete(pkt)
        self.runtime.send_packet(concrete_pkt)

    #
    # Topology Detection
    #

    def queue_update(self,this_update_no):
        def f(this_update_no):
            time.sleep(self.wait_period)
            with self.update_no_lock:
                if this_update_no != self.update_no:
                    return

            self.topology = self.next_topo.copy()
            self.runtime.handle_network_change()

        p = threading.Thread(target=f,args=(this_update_no,))
        p.start()

    def get_update_no(self):
        with self.update_no_lock:
            self.update_no += 1
            return self.update_no
           
    def inject_discovery_packet(self, dpid, port_no):
        self.runtime.inject_discovery_packet(dpid, port_no)
        
    def handle_switch_join(self, switch):
        self.debug_log.debug("handle_switch_joins")
        ## PROBABLY SHOULD CHECK TO SEE IF SWITCH ALREADY IN NEXT_TOPO
        self.next_topo.add_switch(switch)
        self.log.info("OpenFlow switch %s connected" % switch)
        self.debug_log.debug(str(self.next_topo))
        
    def remove_associated_link(self,location):
        port = self.next_topo.node[location.switch]["ports"][location.port_no]
        if not port.linked_to is None:
            # REMOVE CORRESPONDING EDGE
            try:      
                self.next_topo.remove_edge(location.switch, port.linked_to.switch)
            except:
                pass  # ALREADY REMOVED
            # UNLINK LINKED_TO PORT
            try:      
                self.next_topo.node[port.linked_to.switch]["ports"][port.linked_to.port_no].linked_to = None
            except KeyError:
                pass  # LINKED TO PORT ALREADY DELETED
            # UNLINK SELF
            self.next_topo.node[location.switch]["ports"][location.port_no].linked_to = None
        
    def handle_switch_part(self, switch):
        self.log.info("OpenFlow switch %s disconnected" % switch)
        self.debug_log.debug("handle_switch_parts")
        # REMOVE ALL ASSOCIATED LINKS
        for port_no in self.next_topo.node[switch]["ports"].keys():
            self.remove_associated_link(Location(switch,port_no))
        self.next_topo.remove_node(switch)
        self.debug_log.debug(str(self.next_topo))
        self.queue_update(self.get_update_no())
        
    def handle_port_join(self, switch, port_no, config, status):
        self.debug_log.debug("handle_port_joins %s:%s:%s:%s" % (switch, port_no, config, status))
        this_update_no = self.get_update_no()
        self.next_topo.add_port(switch,port_no,config,status)
        if config or status:
            self.inject_discovery_packet(switch,port_no)
            self.debug_log.debug(str(self.next_topo))
            self.queue_update(this_update_no)
            
    def handle_port_part(self, switch, port_no):
        self.debug_log.debug("handle_port_parts")
        try:
            self.remove_associated_link(Location(switch,port_no))
            del self.next_topo.node[switch]["ports"][port_no]
            self.debug_log.debug(str(self.next_topo))
            self.queue_update(self.get_update_no())
        except KeyError:
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY handle_switch_parts
        
    def handle_port_mod(self, switch, port_no, config, status):
        self.debug_log.debug("handle_port_mods %s:%s:%s:%s" % (switch, port_no, config, status))
        # GET PREV VALUES
        try:
            prev_config = self.next_topo.node[switch]["ports"][port_no].config
            prev_status = self.next_topo.node[switch]["ports"][port_no].status
        except KeyError:
            self.log.warning("KeyError CASE!!!!!!!!")
            self.port_down(switch, port_no)
            return

        # UPDATE VALUES
        self.next_topo.node[switch]["ports"][port_no].config = config
        self.next_topo.node[switch]["ports"][port_no].status = status

        # DETERMINE IF/WHAT CHANGED
        if (prev_config and not config):
            self.port_down(switch, port_no)
        if (prev_status and not status):
            self.port_down(switch, port_no,double_check=True)

        if (not prev_config and config) or (not prev_status and status):
            self.port_up(switch, port_no)

    def port_up(self, switch, port_no):
        this_update_no = self.get_update_no()
        self.debug_log.debug("port_up %s:%s" % (switch,port_no))
        self.inject_discovery_packet(switch,port_no)
        self.debug_log.debug(str(self.next_topo))
        self.queue_update(this_update_no)

    def port_down(self, switch, port_no, double_check=False):
        self.debug_log.debug("port_down %s:%s:double_check=%s" % (switch,port_no,double_check))
        try:
            self.remove_associated_link(Location(switch,port_no))
            self.debug_log.debug(str(self.next_topo))
            self.queue_update(self.get_update_no())
            if double_check: self.inject_discovery_packet(switch,port_no)
        except KeyError:  
            pass  # THE SWITCH HAS ALREADY BEEN REMOVED BY handle_switch_parts

    def handle_link_update(self, s1, p_no1, s2, p_no2):
        self.debug_log.debug("handle_link_updates")
        try:
            p1 = self.next_topo.node[s1]["ports"][p_no1]
            p2 = self.next_topo.node[s2]["ports"][p_no2]
        except KeyError:
            self.log.warning("node doesn't yet exist")
            return  # at least one of these ports isn't (yet) in the next_topo

        # LINK ALREADY EXISTS
        try:
            link = self.next_topo[s1][s2]

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
            self.next_topo.node[s1]["ports"][p_no1].linked_to = Location(s2,p_no2)
            self.next_topo.node[s2]["ports"][p_no2].linked_to = Location(s1,p_no1)   
            self.next_topo.add_edge(s1, s2, {s1: p_no1, s2: p_no2})
            
        # IF REACHED, WE'VE REMOVED AN EDGE, OR ADDED ONE, OR BOTH
        self.debug_log.debug(self.next_topo)
        self.queue_update(self.get_update_no())
