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
from pyretic.core.classifier import get_rule_exact_match
from pyretic.core.classifier import get_rule_derivation_tree

from multiprocessing import Process, Manager, RLock, Lock, Value, Queue, Condition
import logging, sys, time
from datetime import datetime
import copy

TABLE_MISS_PRIORITY = 0
TABLE_START_PRIORITY = 60000
STATS_REQUERY_THRESHOLD_SEC = 10
NUM_PATH_TAGS=1022

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
    def __init__(self, backend, main, path_main, kwargs, mode='interpreted',
                 verbosity='normal'):
        self.verbosity = self.verbosity_numeric(verbosity)
        self.log = logging.getLogger('%s.Runtime' % __name__)
        self.network = ConcreteNetwork(self)
        self.prev_network = self.network.copy()
        self.policy = main(**kwargs)
        self.path_policy = None
        self.path_in_tagging  = DynamicPolicy(identity)
        self.path_in_capture  = DynamicPolicy(drop)
        self.path_out_tagging = DynamicPolicy(identity)
        self.path_out_capture = DynamicPolicy(drop)
        self.dynamic_sub_path_pols = set()
        self.dynamic_path_preds    = set()

        if path_main:
            from pyretic.lib.path import pathcomp
            pathcomp.init(NUM_PATH_TAGS)
            self.path_policy = path_main(**kwargs)
            self.handle_path_change()
            in_tag_policy = self.path_in_tagging >> self.policy
            forwarding = (in_tag_policy >> self.path_out_tagging)
            in_capture  = self.path_in_capture
            out_capture = (in_tag_policy >> self.path_out_capture)
            virtual_tag = virtual_field_tagging()
            virtual_untag = virtual_field_untagging()
            self.policy = ((virtual_tag >> forwarding >> virtual_untag) +
                           (virtual_tag >> in_capture) +
                           (virtual_tag >> out_capture))

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
        self.in_network_update = False
        self.in_bucket_apply = False
        self.network_triggered_policy_update = False
        self.bucket_triggered_policy_update = False
        self.global_outstanding_queries_lock = Lock()
        self.global_outstanding_queries = {}
        self.last_queried_time_lock = Lock()
        self.last_queried_time = {}
        self.global_outstanding_deletes_lock = Lock()
        self.global_outstanding_deletes = {}
        self.manager = Manager()
        self.old_rules_lock = Lock()
        # self.old_rules = self.manager.list() # not multiprocess state anymore!
        self.old_rules = []
        self.update_rules_lock = Lock()
        self.update_buckets_lock = Lock()
        self.classifier_version_no = 0
        self.classifier_version_lock = Lock()
        self.default_cookie = 0
        self.packet_in_time = 0
        self.num_packet_ins = 0
        self.update_dynamic_sub_pols()
        self.total_packets_removed = 0 # pkt count from flow removed messages

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
        start_time = time.time()
        self.num_packet_ins += 1
        with self.policy_lock:
            pyretic_pkt = self.concrete2pyretic(concrete_pkt)

            # find the queries, if any in the policy, that will be evaluated
            queries,pkts = queries_in_eval((set(),{pyretic_pkt}),self.policy)

            # evaluate the policy
            output = self.policy.eval(pyretic_pkt)

            # apply the queries whose buckets have received new packets
            self.in_bucket_apply = True
            for q in queries:
                if isinstance(q, PathBucket):
                    q.apply(pyretic_pkt)
                else:
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

        self.packet_in_time += (time.time() - start_time)
        self.log.debug("handle_packet_in cumulative: %f %d"
                       % (self.packet_in_time, self.num_packet_ins))

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
            recompile_list = on_recompile_path_list(id(sub_pol),
                                                    self.policy)
            map(lambda p: p.invalidate_classifier(), recompile_list)

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
            if self.network == self.prev_network:
                return

            # otherwise copy the network object
            self.in_network_update = True
            self.prev_network = self.network.copy()

            # update the policy w/ the new network object
            with self.policy_lock:
                for policy in self.dynamic_sub_pols:
                    policy.set_network(self.network)
                for (sub_pol, full_pol) in self.dynamic_path_preds:
                    sub_pol.set_network(self.network)

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
                                              "policy=\n"+repr(self.policy),
                                              "classifier=\n"+repr(classifier)))
            self.install_classifier(classifier)


    def update_dynamic_sub_pols(self):
        """
        Updates the set of active dynamic sub-policies in self.policy
        """
        def list_diff_by_f(list1, list2, f):
            list_diff = []
            for i in list1:
                found_i = False
                for j in list2:
                    if f(i) == f(j):
                        found_i = True
                        break
                if not found_i:
                    list_diff.append(i)
            return list_diff

        def old_but_not_new(old, new):
            return list_diff_by_f(old, new, id)

        def new_but_not_old(old, new):
            return list_diff_by_f(new, old, id)

        import copy
        old_dynamic_sub_pols = copy.copy(self.dynamic_sub_pols)
        self.dynamic_sub_pols = ast_fold(add_dynamic_sub_pols, list(), self.policy)
        old = old_dynamic_sub_pols
        new = self.dynamic_sub_pols
        for p in old_but_not_new(old, new):
            p.detach()
        for p in new_but_not_old(old, new):
            p.set_network(self.network)
            p.attach(self.handle_policy_change)


    def handle_path_change(self):
        """ When a dynamic path policy updates its path_policy, initiate
        recompilation of the path (and hence pyretic) policy. """
        self.recompile_paths()
        self.update_dynamic_sub_path_pols(self.path_policy)

    def handle_path_change_dyn_pred(self, sub_pol, full_pol):
        recompile_list = on_recompile_path_list(id(sub_pol), full_pol)
        map(lambda p: p.invalidate_classifier(), recompile_list)
        self.handle_path_change()

    def update_dynamic_sub_path_pols(self, path_pol):
        """ Update runtime internal structures which keep track of dynamic
        members of the path policy AST.
        """
        import copy
        from pyretic.lib.path import path, path_policy_utils
        from pyretic.lib.path import __in_re_tree_gen__ as in_cg
        from pyretic.lib.path import __out_re_tree_gen__ as out_cg
        old_dynamic_sub_path_pols = copy.copy(self.dynamic_sub_path_pols)
        ast_fold = path_policy_utils.path_policy_ast_fold
        add_pols = path_policy_utils.add_dynamic_path_pols
        self.dynamic_sub_path_pols = ast_fold(path_pol, add_pols, set())
        for pp in (old_dynamic_sub_path_pols - self.dynamic_sub_path_pols):
            pp.path_detach()
        for pp in (self.dynamic_sub_path_pols - old_dynamic_sub_path_pols):
            pp.path_attach(self.handle_path_change)
        old_dynamic_path_preds = copy.copy(self.dynamic_path_preds)
        self.dynamic_path_preds = set(in_cg.get_dyn_preds() +
                                      out_cg.get_dyn_preds())
        for (sp, fp) in (old_dynamic_path_preds - self.dynamic_path_preds):
            sp.path_detach()
        for (sp, fp) in (self.dynamic_path_preds - old_dynamic_path_preds):
            sp.set_network(self.network)
            f = lambda x: self.handle_path_change_dyn_pred(x, fp)
            sp.path_attach(f)

    def recompile_paths(self):
        """ Recompile DFA based on new path policy, which in turns updates the
        runtime's policy member. """
        from pyretic.lib.path import pathcomp
        policy_fragments = pathcomp.compile(self.path_policy, NUM_PATH_TAGS)
        (in_tag, in_cap, out_tag, out_cap) = policy_fragments
        self.path_in_tagging.policy  = in_tag
        self.path_in_capture.policy  = in_cap
        self.path_out_tagging.policy = out_tag
        self.path_out_capture.policy = out_cap


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
            return (concrete_pred,0,action_list,self.default_cookie,False)

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

        return (concrete_pred,0,action_list,self.default_cookie,False)

#########################
# PROACTIVE COMPILATION 
#########################

    def install_defaults(self, s):
        """ Install backup rules on switch s by default. """
        # Fallback "send to controller" rule under table miss
        self.install_rule(({'switch' : s},
                           TABLE_MISS_PRIORITY,
                           [{'outport' : OFPP_CONTROLLER}],
                           self.default_cookie,
                           False))
        # Send all LLDP packets to controller for topology maintenance
        self.install_rule(({'switch' : s, 'ethtype': LLDP_TYPE},
                           TABLE_START_PRIORITY + 2,
                           [{'outport' : OFPP_CONTROLLER}],
                           self.default_cookie,
                           False))
        # Drop all IPv6 packets by default.
        self.install_rule(({'switch':s, 'ethtype':IPV6_TYPE},
                           TABLE_START_PRIORITY + 1,
                           [],
                           self.default_cookie,
                           False))

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

        def remove_path_buckets(classifier):
            """
            Removes "path buckets" from the action list. Also hooks up runtime
            functions to the path bucket objects to query for latest policy and
            topology transfer functions.

            :param classifier: the input classifier
            :type classifier: Classifier
            :returns the output classifier.
            :rtype: Classifier
            """
            new_rules = []
            for rule in classifier.rules:
                new_acts = []
                for act in rule.actions:
                    if isinstance(act, PathBucket):
                        act.set_topology_policy_fun(self.get_topology_policy)
                        act.set_fwding_policy_fun(self.get_fwding_policy)
                        act.set_egress_policy_fun(self.get_egress_policy)
                        new_acts.append(Controller)
                    else:
                        new_acts.append(act)
                new_rules.append(Rule(rule.match, new_acts))
            return Classifier(new_rules)

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
            default_vlan_match = match(vlan_id=0xffff)
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

        def bookkeep_buckets(diff_lists):
            """Whenever rules are associated with counting buckets,
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
                    (_,_,actions,_) = rule
                    for act in actions:
                        if isinstance(act, CountBucket):
                            if not id(act) in bucket_list:
                                bucket_list[id(act)] = act
                return bucket_list

            def update_rules_for_buckets(rule, op):
                (match, priority, actions, version) = rule
                hashable_match = util.frozendict(match)
                rule_key = (hashable_match, priority, version)
                for act in actions:
                    if isinstance(act, CountBucket):
                        if op == "add":
                            act.add_match(match, priority, version)
                        elif op == "delete":
                            act.delete_match(match, priority, version)
                            self.add_global_outstanding_delete(rule_key, act)
                        elif op == "stay" or op == "modify":
                            if act.is_new_bucket():
                                act.add_match(match, priority, version,
                                              existing_rule=True)

                # debug: check the existence of entries in outstanding_deletes
                # for all buckets in actions list, if op is deleting the rule.
                if op == "delete":
                    with self.global_outstanding_deletes_lock:
                        for act in actions:
                            if isinstance(act, CountBucket):
                                assert (rule_key in
                                        self.global_outstanding_deletes)
                                assert (act in
                                        self.global_outstanding_deletes[rule_key])

            with self.update_buckets_lock:
                """The start_update and finish_update functions per bucket guard
                against inconsistent state in a single bucket, and the global
                "update buckets" lock guards against inconsistent classifier
                match state *across* buckets.
                """
                (to_add, to_delete, to_modify, to_stay) = diff_lists
                all_rules = to_add + to_delete + to_modify + to_stay
                bucket_list = collect_buckets(all_rules)
                map(lambda x: x.start_update(), bucket_list.values())
                map(lambda x: update_rules_for_buckets(x, "add"), to_add)
                map(lambda x: update_rules_for_buckets(x, "delete"), to_delete)
                map(lambda x: update_rules_for_buckets(x, "stay"), to_stay)
                map(lambda x: update_rules_for_buckets(x, "modify"), to_modify)
                map(lambda x: x.add_pull_stats(self.pull_stats_for_bucket(x)),
                    bucket_list.values())
                map(lambda x: x.add_pull_existing_stats(
                        self.pull_existing_stats_for_bucket(x)),
                    bucket_list.values())
                map(lambda x: x.finish_update(), bucket_list.values())
        
        def remove_buckets(diff_lists):
            """
            Remove CountBucket policies from classifier rule actions.
            
            :param diff_lists: difference lists between new and old classifier
            :type diff_lists: 4 tuple of rule lists.
            :returns: new difference lists with bucket actions removed
            :rtype: 4 tuple of rule lists.
            """
            new_diff_lists = []
            for lst in diff_lists:
                new_lst = []
                for rule in lst:
                    (match,priority,acts,version) = rule
                    new_acts = filter(lambda x: not isinstance(x, CountBucket),
                                      acts)
                    if len(new_acts) < len(acts):
                        new_rule = (match, priority, new_acts, version, True)
                    else:
                        new_rule = (match, priority, new_acts, version, False)
                    new_lst.append(new_rule)
                new_diff_lists.append(new_lst)
            return new_diff_lists

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
                        concrete_match = { k:v for (k,v) in pred.map.items() }
                        net_to_str = util.network_to_string
                        for field in ['srcip', 'dstip']:
                            try:
                                val = net_to_str(concrete_match[field])
                                concrete_match.update({field: val})
                            except KeyError:
                                pass
                        return concrete_match
                def concretize_action(a):
                    if a == Controller:
                        return {'outport' : OFPP_CONTROLLER}
                    elif isinstance(a,modify):
                        return { k:v for (k,v) in a.map.iteritems() }
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
                r_minus_queries = Rule(r.match,
                                       filter(lambda x:
                                              not isinstance(x, Query),
                                              r.actions))
                check_OF_rule_has_outport(r_minus_queries)
                check_OF_rule_has_compilable_action_list(r_minus_queries)
            return Classifier(classifier.rules)

        def OF_inportize(classifier):
            """
            Specialize classifier to ensure that packets to be forwarded 
            out the inport on which they arrived are handled correctly.

            :param classifier: the input classifer
            :param switch_to_attrs: switch to attributes map
            :type classifier: Classifier
            :type switch_to_attrs: dictionary switch to attrs
            :returns: the output classifier
            :rtype: Classifier
            """
            import copy
            def specialize_actions(actions,outport):
                new_actions = []
                for act in actions:
                    if not isinstance(act, CountBucket):
                        new_actions.append(copy.deepcopy(act))
                    else:
                        new_actions.append(act) # can't make copies of
                                                # CountBuckets without
                                                # forking
                for action in new_actions:
                    try:
                        if not isinstance(action, CountBucket):
                            if action['outport'] == outport:
                                action['outport'] = OFPP_IN_PORT
                    except:
                        raise TypeError  # INVARIANT: every set of actions must go out a port
                                         # this may not hold when we move to OF 1.3
                return new_actions

            specialized_rules = []
            for rule in classifier.rules:
                phys_actions = filter(lambda a: (not isinstance(a, CountBucket)
                                                 and a['outport'] != OFPP_CONTROLLER
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
                    priority[s] = TABLE_START_PRIORITY
                tuple_rules.append((rule.match,priority[s],rule.actions))
            return tuple_rules

        ### UPDATE LOGIC

        def nuclear_install(new_rules, curr_classifier_no):
            """Delete all rules currently installed on switches and then install
            input classifier from scratch. This function installs the new
            classifier through send_clear's first followed by install_rule's,
            instead of the (safer) rule deletes and rule adds. However it's
            retained here in case it's needed later for performance.

            The main trouble with clearing a switch flow table with a send_clear
            instead of a rule-by-rule send_delete is that there are no flow
            removed messages which get to the controller. These flow removed
            messages are important to accurately count buckets as rules get
            deleted due to classifier revisions.

            :param classifier: the input classifer
            :type classifier: Classifier
            """
            switches = self.network.switch_list()

            for s in switches:
                self.send_barrier(s)
                self.send_clear(s)
                self.send_barrier(s)
                self.install_defaults(s)

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

        def get_new_rules(classifier, curr_classifier_no):
            def add_version(rules, version):
                new_rules = []
                for r in rules:
                    new_rules.append(r + (version,))
                return new_rules

            switches = self.network.switch_list()

            classifier = switchify(classifier,switches)
            classifier = concretize(classifier)
            classifier = check_OF_rules(classifier)
            classifier = OF_inportize(classifier)
            new_rules = prioritize(classifier)
            new_rules = add_version(new_rules, curr_classifier_no)
            return new_rules

        def get_nuclear_diff(new_rules):
            """Compute diff lists for a nuclear install, i.e., when all rules
            are removed and the full new classifier is installed afresh.
            """
            with self.old_rules_lock:
                import copy
                to_delete = copy.copy(self.old_rules)
                to_add = new_rules
                to_modify = list()
                to_stay = list()
                self.old_rules = new_rules
            return (to_add, to_delete, to_modify, to_stay)

        def get_incremental_diff(new_rules):
            """Compute diff lists, i.e., (+), (-) and (0) rules from the earlier
            (versioned) classifier."""
            def different_actions(old_acts, new_acts):
                def buckets_removed(acts):
                    return filter(lambda a: not isinstance(a, CountBucket),
                                  acts)
                return buckets_removed(old_acts) != buckets_removed(new_acts)

            with self.old_rules_lock:
                # calculate diff
                old_rules = self.old_rules
                to_add = list()
                to_delete = list()
                to_modify = list()
                to_modify_old = list() # old counterparts of modified rules
                to_stay = list()
                for old in old_rules:
                    new = find_same_rule(old, new_rules)
                    if new is None:
                        to_delete.append(old)
                    else:
                        (new_match,new_priority,new_actions,_) = new
                        (_,_,old_actions,old_version) = old
                        if different_actions(old_actions, new_actions):
                            modified_rule = (new_match, new_priority,
                                             new_actions, old_version)
                            to_modify.append(modified_rule)
                            to_modify_old.append(old)
                            # We also add the new and old rules to the to_add
                            # and to_delete lists (resp.) to keep track of the
                            # changes to be made to old_rules. These are later
                            # removed from to_add and to_delete when returning.
                            to_add.append(modified_rule)
                            to_delete.append(old)
                        else:
                            to_stay.append(old)

                for new in new_rules:
                    old = find_same_rule(new, old_rules)
                    if old is None:
                        to_add.append(new)

                # update old_rules to reflect changes in the classifier
                for rule in to_delete:
                    self.old_rules.remove(rule)
                for rule in to_add:
                    self.old_rules.append(rule)
                # see note above where to_modify* lists are populated.
                for rule in to_modify:
                    to_add.remove(rule)
                for rule in to_modify_old:
                    to_delete.remove(rule)

            return (to_add, to_delete, to_modify, to_stay)

        def get_diff_lists(new_rules):
            assert self.mode in ['proactive0', 'proactive1']
            if self.mode == 'proactive0':
                return get_nuclear_diff(new_rules)
            elif self.mode == 'proactive1':
                return get_incremental_diff(new_rules)

        def install_diff_lists(diff_lists, classifier_version_no):
            """Install the difference between the input classifier and the
            current switch tables. The function takes the set of rules (added,
            deleted, modified, untouched), and does necessary flow
            installs/deletes/modifies.
            
            :param diff_lists: list of rules to add, delete, modify, stay.
            :type diff_lists: 4 tuple of rule lists
            :param classifier_version_no: version of the classifier after
            controller bootup
            :type classifier_version_no: int
            """
            (to_add, to_delete, to_modify, to_stay) = diff_lists
            switches = self.network.switch_list()

            # If the controller just came up, clear out the switches.
            if classifier_version_no == 1 or self.mode == 'proactive0':
                for s in switches:
                    self.send_barrier(s)
                    self.send_clear(s)
                    self.send_barrier(s)
                    self.install_defaults(s)

            # There's no need to delete rules if nuclear install:
            if self.mode == 'proactive0':
                to_delete = list()
                to_modify = list()
                to_stay   = list()

            if to_delete:
                for rule in to_delete:
                    (match_dict,priority,_,_) = rule
                    if match_dict['switch'] in switches:
                        self.delete_rule((match_dict, priority))
            if to_add:
                for rule in to_add:
                    self.install_rule(rule)
            if to_modify:
                for rule in to_modify:
                    self.modify_rule(rule)
            for s in switches:
                self.send_barrier(s)
            self.log.debug('\n-----\n\n\ninstalled new set of rules\n\n\n----')


        ### PROCESS THAT DOES INSTALL

        def f(diff_lists,curr_version_no):
            self.send_reset_install_time()
            with self.switch_lock:
                install_diff_lists(diff_lists,curr_version_no)

        curr_version_no = None
        with self.classifier_version_lock:
            self.classifier_version_no += 1
            curr_version_no = self.classifier_version_no

        # Process classifier to an openflow-compatible format before
        # sending out rule installs
        #classifier = send_drops_to_controller(classifier)
        classifier = remove_identity(classifier)
        classifier = remove_path_buckets(classifier)
        classifier = controllerify(classifier)
        classifier = layer_3_specialize(classifier)

        # TODO(ngsrinivas): As of OVS 1.9, vlan_specialize seems unnecessary to
        # keep track of rules that match packets without a VLAN, to the best of
        # my knowledge. I'm retaining this here just in case there are VLAN rule
        # installation issues later on. Can be removed in the future if there
        # are no obvious issues.

        # classifier = vlan_specialize(classifier)

        # Get diffs of rules to install from the old (versioned) classifier. The
        # bookkeeping and removing of bucket actions happens at the end of the
        # whole pipeline, because buckets need very precise mappings to the
        # rules installed by the runtime.
        new_rules = get_new_rules(classifier, curr_version_no)
        self.log.debug("Number of rules in classifier: %d" % len(new_rules))
        diff_lists = get_diff_lists(new_rules)
        bookkeep_buckets(diff_lists)
        diff_lists = remove_buckets(diff_lists)

        self.log.debug('================================')
        self.log.debug('Final classifier to be installed:')
        for rule in new_rules:
            self.log.debug(str(rule))
        self.log.debug('================================')

        p = Process(target=f, args=(diff_lists,curr_version_no))
        p.daemon = True
        p.start()

###################
# QUERYING SUPPORT
###################

    def pull_switches_for_preds(self, concrete_preds, bucket):
        """Given a list of concrete predicates, query the list of switches
        corresponding to the switches where these predicates apply.
        """
        switch_list = []
        if not concrete_preds:
            return False
        self.log.debug('-------------------------------------------------------------')
        self.log.debug('--- In pull_switches_for_preds: printing concrete predicates:')
        for concrete_pred in concrete_preds:
            self.log.debug(str(concrete_pred))
        self.log.debug('-------------------------------------------------------------')
        for concrete_pred in concrete_preds:
            if 'switch' in concrete_pred:
                switch_id = concrete_pred['switch']
                if ((not switch_id in switch_list) and
                    (switch_id in self.network.switch_list())):
                    switch_list.append(switch_id)
            else:
                switch_list = self.network.switch_list()
                break
        self.log.info('Pulling stats from switches '
                      + str(switch_list) + ' for bucket ' +
                      str(id(bucket)))
        if not switch_list:
            """ This means no switch will actually be queried. This happens if
            none of the switches associated with any of the concrete_preds is
            actually _up_ in the network currently. These data plane counts can
            be transiently or permanently lost as they are fate-shared with
            switches."""
            return False
        self.log.debug('Non-empty query switch list.')
        for s in switch_list:
            bucket.add_outstanding_switch_query(s)
            already_queried = self.add_global_outstanding_query(s, bucket)
            need_to_query = not already_queried
            """ Also check if some time has passed since the switch was last
            queried. """
            if already_queried:
                with self.last_queried_time_lock:
                    assert s in self.last_queried_time
                    need_to_query = ((time.time() - self.last_queried_time[s])
                                       > STATS_REQUERY_THRESHOLD_SEC)
            if need_to_query:
                self.request_flow_stats(s)
                self.add_last_queried_time(s)
                self.log.debug('in pull_stats: sent out stats query to switch '
                               + str(s))
            else:
                self.log.debug("in pull_stats: didn't send stats req to switch"
                               + str(s))
        return True

    def pull_stats_for_bucket(self,bucket):
        """
        Returns a function that can be used by counting buckets to
        issue queries from the runtime."""
        def pull_bucket_stats():
            preds = [me.match for me in bucket.matches.keys()]
            return self.pull_switches_for_preds(preds, bucket)
        return pull_bucket_stats

    def pull_existing_stats_for_bucket(self,bucket):
        """Returns a function that is called by new counting buckets which have
        at least one rule that was already created in an earlier classifier.
        """
        def pull_existing_bucket_stats():
            preds = [me.match for me,ms in bucket.matches.items() if ms.existing_rule]
            return self.pull_switches_for_preds(preds, bucket)
        return pull_existing_bucket_stats

    def add_global_outstanding(self, global_dict, global_lock, key, val):
        """Helper function for adding a mapping for an outstanding query or rule
        to objects (i.e., buckets) which are waiting for them."""
        entry_found = False
        with global_lock:
            if not key in global_dict:
                global_dict[key] = [val]
            else:
                if not val in global_dict[key]:
                    global_dict[key].append(val)
                entry_found = True
        return entry_found

    def add_global_outstanding_query(self, s, bucket):
        return self.add_global_outstanding(self.global_outstanding_queries,
                                           self.global_outstanding_queries_lock,
                                           s, bucket)

    def add_global_outstanding_delete(self, rule, bucket):
        return self.add_global_outstanding(self.global_outstanding_deletes,
                                           self.global_outstanding_deletes_lock,
                                           rule, bucket)

    def add_last_queried_time(self, s):
        with self.last_queried_time_lock:
            self.last_queried_time[s] = time.time()

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

        pyretic_packet = Packet(util.frozendict())
        d = { h : convert(h,v) for (h,v) in packet.items() }
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
                concrete_packet[header] = packet[header]
            except KeyError:
                pass
        for header in packet.header:
            try:
                if header in ['switch', 'inport', 'outport']: next
                val = packet[header]
                headers[header] = val
            except:
                pass

        concrete_packet = dict(concrete_packet.items() + virtual_field.expand(headers).items())
        concrete_packet['raw'] = get_packet_processor().pack(headers)
        return concrete_packet

#######################
# TO OPENFLOW         
#######################

    def send_reset_install_time(self):
        self.backend.send_reset_install_time()

    def send_packet(self,concrete_packet):
        self.backend.send_packet(concrete_packet)

    def install_rule(self,(concrete_pred,priority,action_list,cookie,notify)):
        self.log.debug(
            '|%s|\n\t%s\n\t%s\n' % (str(datetime.now()),
                "sending openflow rule:",
                (str(priority) + " " + repr(concrete_pred) + " "+
                 repr(action_list) + " " + repr(cookie))))
        self.backend.send_install(concrete_pred,priority,action_list,cookie,notify)

    def modify_rule(self, (concrete_pred,priority,action_list,cookie,notify)):
        self.backend.send_modify(concrete_pred,priority,action_list,cookie,notify)

    def delete_rule(self,(concrete_pred,priority)):
        self.backend.send_delete(concrete_pred,priority)

    def send_barrier(self,switch):
        self.backend.send_barrier(switch)

    def send_clear(self,switch):
        self.backend.send_clear(switch)

    def clear_all(self):
        def f():
            switches = self.network.switch_list()
            for s in switches:
                self.send_barrier(s)
                self.send_clear(s)
                self.send_barrier(s)
                self.install_defaults(s)
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

    def handle_port_join(self,switch_id,port_id,conf_up,stat_up,port_type):
        self.network.handle_port_join(switch_id,port_id,conf_up,stat_up,port_type)

    def handle_port_mod(self,switch_id,port_id,conf_up,stat_up,port_type):
        self.network.handle_port_mod(switch_id,port_id,conf_up,stat_up,port_type)

    def handle_port_part(self, switch, port_no):
        self.network.handle_port_part(switch, port_no)

    def handle_link_update(self, s1, p_no1, s2, p_no2):
        self.network.handle_link_update(s1, p_no1, s2, p_no2)

    def ofp_convert(self,f,val):
        """Helper to parse the match structure received from the backend."""
        if f == 'match':
            import ast
            val = ast.literal_eval(val)
            return { g : self.ofp_convert(g,v) for g,v in val.items() }
        if f == 'actions':
            import ast
            vals = ast.literal_eval(val)
            return [ { g : self.ofp_convert(g,v) for g,v in val.items() }
                     for val in vals ]
        if f in ['srcmac','dstmac']:
            return MAC(val)
        elif f in ['srcip','dstip']:
            return IP(val)
        else:
            return val

    def flow_stat_str(self, flow_stat):
        """Helper to print flow stats as strings."""
        output = str(flow_stat['priority']) + ':\t'
        output += str(flow_stat['match']) + '\n\t->'
        output += str(flow_stat.get('actions', [])) + '\n\t'
        output += 'packet_count=' + str(flow_stat['packet_count'])
        output += '\tbyte_count=' + str(flow_stat['byte_count'])
        output += '\n\t cookie: \t' + str(flow_stat['cookie'])
        return output

    def handle_flow_stats_reply(self, switch, flow_stats):
        self.log.info('received a flow stats reply from switch ' + str(switch))
        flow_stats = [ { f : self.ofp_convert(f,v)
                         for (f,v) in flow_stat.items() }
                       for flow_stat in flow_stats       ]
        flow_stats = sorted(flow_stats, key=lambda d: -d['priority'])
        self.log.debug(
            '|%s|\n\t%s\n' % (str(datetime.now()),
                '\n'.join(['flow table for switch='+repr(switch)] + 
                    [self.flow_stat_str(f) for f in flow_stats])))
        # Debug prints whenever some flow has non-zero counters
        for f in flow_stats:
            extracted_pkts = f['packet_count']
            extracted_bytes = f['byte_count']
            if extracted_pkts > 0:
                self.log.debug('in stats_reply: found a non-zero stats match:\n' +
                               str(f))
                self.log.debug('packets: ' + str(extracted_pkts) + ' bytes: ' +
                               str(extracted_bytes))
        buckets_list = []
        with self.global_outstanding_queries_lock:
            if switch in self.global_outstanding_queries:
                buckets_list = self.global_outstanding_queries[switch]
                del self.global_outstanding_queries[switch]
            self.log.debug('in stats_reply: outstanding switches is now:' +
                           str(self.global_outstanding_queries) )
        for bucket in buckets_list:
            bucket.handle_flow_stats_reply(switch, flow_stats)

    def handle_flow_removed(self, dpid, flow_stat_dict):
        def str_convert_match(m):
            """ Convert incoming flow stat matches into a form compatible with
            stored match entries. """
            new_dict = {}
            for k,v in m.iteritems():
                if not (k == 'srcip' or k == 'dstip'):
                    new_dict[k] = v
                else:
                    new_dict[k] = str(v.ip)
            return new_dict
        flow_stat = { f : self.ofp_convert(f,v)
                      for (f,v) in flow_stat_dict.items() }
        self.log.debug(
            '|%s|\n\t%s\n\t%s' %
            (str(datetime.now()), "flow removed message: rule:",
             self.flow_stat_str(flow_stat)))
        with self.global_outstanding_deletes_lock:
            f = flow_stat
            rule_match = str_convert_match(
                match(f['match']).intersect(match(switch=dpid)).map)
            priority = f['priority']
            version = f['cookie']
            match_entry = (util.frozendict(rule_match), priority, version)
            if f['packet_count'] > 0:
                self.log.debug("Got removed flow\n%s with counts %d %d" %
                               (str(match_entry), f['packet_count'],
                                f['byte_count']) )
                if version > 0:
                    self.total_packets_removed += f['packet_count']
                    self.log.debug("Total packets removed: %d" %
                                   self.total_packets_removed)
                self.log.debug('Printing global structure for deleted rules:')
                for k,v in self.global_outstanding_deletes.iteritems():
                    self.log.debug(str(k) + " : " + str(v))
            if match_entry in self.global_outstanding_deletes:
                if f['packet_count'] > 0:
                    self.log.debug("Membership test passed; non-zero # packets!")
                bucket_list = self.global_outstanding_deletes[match_entry]
                for bucket in bucket_list:
                    self.log.debug("Sending bucket %d a flow removed msg" %
                                  id(bucket))
                    bucket.handle_flow_removed(rule_match, priority, version, f)
                del self.global_outstanding_deletes[match_entry]

################################################################################
# Topology Transfer and Full Policy Functions
################################################################################
    def get_topology_policy(self):
        switch_edges = self.network.topology.edges(data=True)
        pol = drop
        for (s1, s2, ports) in switch_edges:
            p1 = ports[s1]
            p2 = ports[s2]
            link_transfer_policy = ((match(switch=s1,outport=p1) >>
                                     modify(switch=s2,inport=p2,outport=None)) +
                                    (match(switch=s2,outport=p2) >>
                                     modify(switch=s1,inport=p1,outport=None)))
            if pol == drop:
                pol = link_transfer_policy
            else:
                pol += link_transfer_policy
        return pol

    def get_egress_policy(self):
        pol = drop
        for p in self.network.topology.egress_locations():
            sw_no = p.switch
            port_no = p.port_no
            egress_match = match(switch=sw_no,outport=port_no)
            if pol == drop:
                pol = egress_match
            else:
                pol += egress_match
        return pol

    def get_fwding_policy(self):
        return self.policy

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
        if ((k not in basic_headers + content_headers + location_headers) and
            (not v is None)):
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
        
    def handle_port_join(self, switch, port_no, config, status, port_type):
        self.debug_log.debug("handle_port_joins %s:%s:%s:%s" % (switch, port_no, config, status))
        this_update_no = self.get_update_no()
        self.next_topo.add_port(switch,port_no,config,status,port_type)
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
        
    def handle_port_mod(self, switch, port_no, config, status, port_type):
        self.debug_log.debug("handle_port_mods %s:%s:%s:%s" % (switch, port_no, config, status))
        # GET PREV VALUES
        try:
            prev_config = self.next_topo.node[switch]["ports"][port_no].config
            prev_status = self.next_topo.node[switch]["ports"][port_no].status
            prev_port_type = self.next_topo.node[switch]["ports"][port_no].port_type
        except KeyError:
            self.log.warning("KeyError CASE!!!!!!!!")
            self.port_down(switch, port_no)
            return

        # UPDATE VALUES
        self.next_topo.node[switch]["ports"][port_no].config = config
        self.next_topo.node[switch]["ports"][port_no].status = status
        self.next_topo.node[switch]["ports"][port_no].port_type = port_type
        

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
            pt1 = self.next_topo.node[s1]["ports"][p_no1].port_type 
            pt2 = self.next_topo.node[s2]["ports"][p_no2].port_type 
            if pt1 != pt2:
                print "MISMATCH ",
                print pt1
                print pt2
            self.next_topo.add_edge(s1, s2, {s1: p_no1, s2: p_no2, 'type' : pt1})
            
        # IF REACHED, WE'VE REMOVED AN EDGE, OR ADDED ONE, OR BOTH
        self.debug_log.debug(self.next_topo)
        self.queue_update(self.get_update_no())

################################################################################
# Virtual Fields
################################################################################
class virtual_field:
    def __init__(self, name, values, type="string"):
        self.name   = name
        self.values = values
        # We need a None value as well
        self.cardinality = len(values) + 1
        self.type   = type
        virtual_field.fields[name] = self

    def index(self,key):
        try:
            return self.values.index(key) + 1
        except ValueError as e:
            if key == None:
                return 0
            raise e

    def value(self,index):
        try:
            return self.values[index-1]
        except ValueError as e:
            if index == 0:
                return None
            raise e

    @classmethod
    def compress(cls,fields):
        virtual_fields = virtual_field.fields
        vf_names       = virtual_fields.keys()

        def vhs_to_num(fields):
            vheaders = dict(filter(lambda a: a[0] in vf_names, fields.iteritems()))
            # If we there are no virtual_fields specified we wouldn't want to match on them at all
            # Just return -1 so that calling function knows that the predicate doesn't have any virtual
            # fields on it
            if len(vheaders) == 0: return -1

            for n in vf_names:
                if n not in vheaders:
                    vheaders[n] = None
            ret,temp = 0,1
            for n,vf in virtual_fields.iteritems():
                ret *= temp
                ret += vf.index(vheaders[n])
                temp = vf.cardinality

            return ret
        return vhs_to_num(fields)

    @classmethod
    def expand(cls,fields):
        if 'vlan_id' not in fields:
            return {}

        virtual_fields = virtual_field.fields
        vf_names       = virtual_fields.keys()
        num = fields['vlan_pcp'] << 12 + fields['vlan_id']

        def num_to_vhs(num):
            # If we there are no virtual_fields specified we wouldn't want to match on them at all
            # Just return -1 so that calling function knows that the predicate doesn't have any virtual
            # fields on it
            vfs = {}
            tmp = num
            for n,vf in reversed(virtual_fields.items()):
                val    = tmp % vf.cardinality
                tmp    = tmp / vf.cardinality
                vfs[n] = vf.value(val)

            return vfs
        return num_to_vhs(num)

    @classmethod
    def map_to_vlan(cls,num):
        if num == -1: return {}
        return {
           "vlan_id" : 0b000111111111111 & num,
           "vlan_pcp": 0b111000000000000 & num
        }

virtual_field.fields = {}
