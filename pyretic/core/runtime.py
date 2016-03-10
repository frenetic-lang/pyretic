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
from pyretic.core.classifier import get_rule_derivation_leaves

from multiprocessing import Process, Manager, RLock, Lock, Value, Queue, Condition
import logging, sys, time
from datetime import datetime
import copy

TABLE_MISS_PRIORITY = 0
TABLE_START_PRIORITY = 60000
STATS_REQUERY_THRESHOLD_SEC = 4
NUM_PATH_TAGS = 32000
DEFAULT_NX_TABLE_ID=1
MAX_STAGES = 13 # max. for extensively multi-staged pipelines

from pyretic.evaluations.stat import Stat

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
    :param use_nx: use nicira extensions for multi-table rule installation
    :type use_nx: boolean
    :param pipeline: for multi-stage switches, a pipeline configuration
    :type pipeline: pipeline_config
    """
    
    
    def __init__(self, backend, main, path_main, kwargs, mode='interpreted',
                 verbosity='normal',use_nx=False, pipeline="default_pipeline",
                 opt_flags=None, use_pyretic=False, use_fdd=False, offline=False,
                 write_log='rt_log.txt', restart_frenetic=False):
        self.verbosity = self.verbosity_numeric(verbosity)
        self.use_nx = use_nx
        self.pipeline = pipeline
        self.log = logging.getLogger('%s.Runtime' % __name__)
        self.setup_write_logging(write_log)
        self.network = ConcreteNetwork(self)
        self.prev_network = self.network.copy()
        self.forwarding = main(**kwargs)
        self.get_subpol_stats = True # TODO: make cmdline option to pyretic.py
        self.use_pyretic_compiler = use_pyretic

        """ Set runtime flags for specific optimizations. """
        self.set_optimization_opts(path_main, opt_flags)
        """ If there are path-policies, initialize path query components. """
        self.path_triggered_policy_update = False
        self.in_path_recompile = False
        self.init_path_query(path_main, kwargs, self.partition_cnt,
                             self.cache_enabled, self.edge_contraction_enabled,
                             use_fdd=use_fdd, write_log=self.write_log)
        """ Initialize a `policy map', which determines how the network policy
        is mapped onto the tables on switches. By default (i.e., a single stage
        table), the entire policy goes into the first table on each switch.

        Based on the policy map, the member variable `self.policy' is also
        initialized, which denotes the final network policy that is installed on
        devices.
        """
        self.set_policy_map(path_main)

        """ If subpolicy stats are required, compute them. """
        if self.get_subpol_stats:
            self.get_subpolicy_compile_stats(path_main, restart_frenetic)

        self.mode = mode
        if not offline:
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

######################
# Logging setup
######################

    def setup_write_logging(self, logfile):
        """ Configure write logging for runtime debugging with large automated
        runs. """
        self.write_log = logging.getLogger('%s.Runtime_write' % __name__)
        self.write_log.setLevel(logging.INFO)
        fh = logging.FileHandler(logfile, mode='w')
        fh.setLevel(logging.INFO)
        self.write_log.addHandler(fh)

######################
# Stat Methods 
######################


    ###### Runtime initialization routines to extract stats ######
    def set_optimization_opts(self, path_main, opt_flags):
        """ Set runtime flags for various optimization settings from the command
        line. """
        if not path_main or opt_flags is None:
            self.disjoint_enabled = False
            self.default_enabled = False
            self.integrate_enabled = False
            self.multitable_enabled = False
            self.ragel_enabled = False
            self.partition_cnt = None
            self.cache_enabled = False
            self.edge_contraction_enabled = False
            self.partition_enabled = False
            self.preddecomp_enabled = False
        else:
            (self.disjoint_enabled, self.default_enabled,
             self.integrate_enabled, self.multitable_enabled,
             self.ragel_enabled, self.partition_enabled,
             self.partition_cnt, self.cache_enabled,
             self.edge_contraction_enabled, self.preddecomp_enabled) = opt_flags
             
            self.partition_enabled &= not self.partition_cnt is None
        ''' Set multitable_enabled to True if other run-time options indicate
        that we are using multi-stage tables with separate forwarding and
        queries. :) '''
        if self.use_nx and self.pipeline in ['path_query_pipeline','mt']:
            self.log.info("Multitable option enabled gratuitously from other "
                          "options")
            self.multitable_enabled = True
        elif self.use_nx and self.pipeline in ['default_pipeline']:
            pass
        elif self.use_nx:
            raise NotImplementedError("Unknown pipeline configuration")
        else:
            pass

    def sw_port_ids(self):
        return self.network.switch_with_port_ids_list()

    def nw_edges(self):
        return self.network.topology.edges(data=True)

    def sw_cnt(self):
        """ Switch count for netkat compilation """
        return (self.partition_cnt if self.partition_cnt
                else len(self.network.topology.nodes()))
        
    def get_subpolicy_compile_stats(self, path_main, restart_frenetic=False):
        """ TODO(ngsrinivas): the stuff stored in the in_table_list;
        out_table_list, etc. has changed. May need to update this function to
        reflect statistics. See recompile_paths() for latest updated assignments
        to these runtime variables. """
        if path_main:
            if self.integrate_enabled:
                for (in_table, out_table) in zip(self.path_in_table_list, self.path_out_table_list):
                    self.get_subpolicy_compile_stats_per_stage(in_table,
                                                               out_table,
                                                               restart_frenetic=restart_frenetic)
            else:
                for (in_table, out_table, (in_tag, in_cap),
                     (out_tag, out_cap)) in zip(self.path_in_table_list,
                                                self.path_out_table_list,
                                                self.path_ingress,
                                                self.path_egress):
                    self.get_subpolicy_compile_stats_per_stage(
                        in_table, out_table, in_tag, in_cap, out_tag, out_cap,
                        restart_frenetic=restart_frenetic)
    
    def get_subpolicy_compile_stats_per_stage(self, in_table, out_table,
                                              in_tag = None, in_cap = None,
                                              out_tag = None,
                                              out_cap = None,
                                              restart_frenetic = False):
        """ In the "offline" case, get compile time and classifier size stats
        for sub-policies. This function only compiles the sub-parts of the
        policy. It neither compiles the entire policy, nor touches the
        self.policy in the runtime. This is done in update_switch_classifiers()
        and set_policy_map(), respectively.
        """
        sketch = None
        from pyretic.lib.path import LeafSketch

        forwarding = LeafSketch('forwarding', self.forwarding)
        vf_tag = LeafSketch('vf_tag', self.virtual_tag)
        vf_untag = LeafSketch('vf_untag', self.virtual_untag)

        self.write_log.info("compiling new stage.")

        if self.multitable_enabled:
            

            if self.integrate_enabled:
                in_table = LeafSketch('in_table', in_table)
                out_table = LeafSketch('out_table', out_table)
                
                sketch = [(in_table, False), (out_table, True)] 
                            #(vf_tag, False), (vf_untag, True)]
                
            else:
                
                in_tag = LeafSketch('in_tag', in_tag)
                out_tag = LeafSketch('out_tag', out_tag)
                in_capture = LeafSketch('in_capture', in_cap)
                out_capture = LeafSketch('out_capture', out_cap)
                in_table = in_tag // in_capture
                in_table.name = 'in_table'
                out_table = out_tag // out_capture
                out_table.name = 'out_table'
                sketch = [(in_table, False), 
                            (out_table, True),] 
                            #(vf_tag, False), (vf_untag, True)]
                
        else:
            in_tag = LeafSketch('in_tag', in_tag)
            out_tag = LeafSketch('out_tag', out_tag)
            in_capture = LeafSketch('in_capture', in_cap)
            out_capture = LeafSketch('out_capture', out_cap)
            
            in_tag_policy = in_tag * forwarding
            in_fwd_out = (in_tag_policy * out_tag)
            full_out_cap = (in_tag_policy * out_capture)

            vtag_forwarding = vf_tag * in_fwd_out * vf_untag
            vtag_in_cap = vf_tag * in_capture
            vtag_out_cap = vf_tag * full_out_cap

            final_pol = vtag_forwarding / vtag_in_cap // vtag_out_cap
            final_pol.name = 'final_pol'
            #TODO: This is currently not what happens
            #      in actual compilation with netkat
            sketch = [(final_pol, False)] 

        if sketch:
            for s in sketch:
                if self.use_pyretic_compiler:
                    s[0].compile()
                else:
                    self.write_log.info("starting to compile %s" % s[0].name)
                    if restart_frenetic:
                        import subprocess
                        netkat_cmd = "bash restart-frenetic.sh"
                        try:
                            output = subprocess.Popen(netkat_cmd, shell=True,
                                                      stderr=subprocess.STDOUT)
                            self.write_log.info("restarted frenetic")
                        except Exception as e:
                            print "Could not restart frenetic successfully."
                            print e
                            sys.exit(1)
                        time.sleep(2)
                    s[0].netkat_compile(self.sw_cnt(), multistage=True)
                    self.write_log.info("done compiling %s" % s[0].name)

    def verbosity_numeric(self,verbosity_option):
        numeric_map = { 'low': 1,
                        'normal': 2,
                        'high': 3,
                        'please-make-it-stop': 4}
        return numeric_map.get(verbosity_option, 0)


######################
# PACKET INTERPRETER 
######################

    def handle_packet_in(self, concrete_pkt, cookie):
        """
        The packet interpreter.
        
        :param concrete_packet: the packet to be interpreted.
        :type limit: payload of an OpenFlow packet_in message.
        """
        start_time = time.time()
        self.num_packet_ins += 1
        # TODO: revert to debug logging
        self.log.info("Packet-in # %d" % self.num_packet_ins)
        with self.policy_lock:
            pyretic_pkt = self.concrete2pyretic(concrete_pkt)

            # Set policy to be used for evaluation, depending on whether
            # multiple tables are enabled, and the table packet is coming from.
            eff_policy = self.policy
            if self.use_nx:
                (version, table) = self.get_version_table_from_cookie(cookie)
                eff_policy = self.get_effective_policy_from_table(table)

            # find the queries, if any in the policy, that will be evaluated
            queries,pkts = queries_in_eval((set(),{pyretic_pkt}),eff_policy)

            # evaluate the policy
            output = eff_policy.eval(pyretic_pkt)

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
        self.log.debug("Corresponding packetouts: %d" %
                       len(concrete_output))
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

            # if this change driven by a path recompilation, flag
            elif self.in_path_recompile:
                self.path_triggered_policy_update = True

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

                """ Update network objects for dynamic predicates in path
                queries as well. If any of them changed its policy, path queries
                must be recompiled.
                """
                self.dyn_path_pred_changed = False
                for dyn_pred_obj in self.dynamic_path_preds:
                    dyn_pred_obj.pred.set_network(self.network)
                from pyretic.lib.path import path_empty
                if (self.dyn_path_pred_changed or ((not self.us_path_policy is
                        None) and not isinstance(self.us_path_policy,
                                                path_empty))):
                    self.handle_path_change()
                    self.dyn_path_pred_changed = False

                # FIXME(joshreich) :-)
                # This is a temporary fix. We need to specialize the check below
                # instead of removing it completely, but will let @joshreich
                # take care of it. -- ngsrinivas
                # if self.network_triggered_policy_update:
                self.update_dynamic_sub_pols()
                self.update_switch_classifiers()
                self.network_triggered_policy_update = False

            self.in_network_update = False

    
    def netkat_classifier_compile(self, pol):
        # Force recompilation overriding cached policies, if the network has
        # changed. This is to ensure that a local classifier is regenerated for
        # each switch in the (new) network topology.
        force_compile = self.in_network_update
        return pol.netkat_compile(self.sw_cnt(),
                                  force_compile=force_compile)[0]

    def vlan_preprocessed_policy(self, p):
        from pyretic.core.language_tools import default_mapper, ast_map
        from pyretic.core.language import _match, _modify

        def need_vlan_preprocess():
            """ A boolean check function to know whether helper tagging headers must
            be removed before sending the policy to the compiler. """
            return self.use_pyretic_compiler and ((not self.use_nx) or
                    (self.use_nx and self.pipeline == 'default_pipeline'))

        def remove_vlan_helpers(parent, children):
            """ Remove VLAN helper metadata from policies. """
            if isinstance(parent, _modify) or isinstance(parent, _match):
                # Use a modified _match or _modify *in place* in the policy
                return parent.remove_extra_tagging_headers()
            else:
                return default_mapper(parent, children)

        if need_vlan_preprocess():
            # Pre-process policy to remove tagging helper fields
            from pyretic.core.language_tools import ast_map
            cp = ast_map(remove_vlan_helpers, p)
        else:
            cp = p
        return cp

    @Stat.classifier_stat
    @Stat.elapsed_time
    def whole_policy_compile(self):
        cp = self.vlan_preprocessed_policy(self.policy)
        if self.use_pyretic_compiler:
            p = cp.compile()
        elif self.path_policy:
            p = self.netkat_classifier_compile(cp)
        else:
            p = cp.netkat_compile(self.sw_cnt())[0] # directly compile with netkat
        #print "rule count", len(p.rules)
        return p

    def mt_specific_policy_compile(self, fpol, table):
        """ Multi-table specific policy compilation. Pol is the policy argument
        which is then compiled by netkat and returned.
        """
        assert self.pipeline in ["default_pipeline", "path_query_pipeline", "mt"]
        t = '0'
        self.log.debug("Attempting to compile table %d with netkat" % table)
        pol = self.vlan_preprocessed_policy(fpol)
        if self.pipeline == 'default_pipeline':
            if table > 0 and not self.use_pyretic_compiler:
                (c, t) = pol.netkat_compile(self.sw_cnt(), multistage=True)
            else:
                c = pol.compile()
        elif self.pipeline == 'path_query_pipeline' or self.pipeline == 'mt':
            if self.use_pyretic_compiler:
                c = pol.compile()
            else:
                (c, t) = pol.netkat_compile(self.sw_cnt(), multistage=True)
        else:
            raise RuntimeError("Unknown pipeline type for multitable specific "
                                + "policy compilation")
        self.log.debug("Recompiled table %d in %s secs" % (table, t))
        return c

    def update_switch_classifiers(self):
        """
        Updates switch classifiers
        """
        classifier = None
        
        if self.mode == 'reactive0':
            self.clear_all()

        elif self.mode == 'proactive0' or self.mode == 'proactive1':
            if not self.use_nx:
                classifier = self.whole_policy_compile()
                self.log.debug(
                    '|%s|\n\t%s\n\t%s\n\t%s\n' % (str(datetime.now()),
                                                  "generate classifier",
                                                  "policy=\n"+repr(self.policy),
                                                  "classifier=\n"+repr(classifier)))
                self.install_classifier(classifier)
            else:
                classifier_map = {}
                table_list = []
                classifier_string = ''
                classifier_lens = ''
                for (table, pol) in self.policy_map.iteritems():
                    if ((not pol.has_active_classifier()) or
                        self.in_network_update):
                        table_list.append(table)
                        classifier_map[table] = self.mt_specific_policy_compile(pol,
                                                                                table)
                        classifier_string += "%s\n%s\n" % (
                            "Table %d classifier:" % table,
                            repr(classifier_map[table]))
                        classifier_lens += "Table %d: %d rules\n" % (
                            table, len(classifier_map[table].rules))
                self.log.debug(
                    '|%s|\n\t%s\n\t%s\n\t%s\n' % (str(datetime.now()),
                                                  "generate classifier",
                                                  "policy=\n"+repr(self.policy),
                                                  classifier_string))
                for table in table_list:
                    self.log.debug("Installing table %d" % table)
                    self.install_classifier(classifier_map[table], table)

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
        if self.path_triggered_policy_update:
            self.update_switch_classifiers()
            self.path_triggered_policy_update = False

    def handle_path_change_dyn_pred(self, sub_pol):
        dyn_preds = self.dynamic_path_preds
        for policy_tuple in dyn_preds:
            if id(policy_tuple.pred) == id(sub_pol):
                full_pol = policy_tuple.pol
                recomp_list = on_recompile_path_list(id(sub_pol), full_pol)
                map(lambda p: p.invalidate_classifier(), recomp_list)
        if not self.in_network_update:
            self.handle_path_change()
        else:
            self.dyn_path_pred_changed = True

    def update_dynamic_sub_path_pols(self, path_pol):
        """ Update runtime internal structures which keep track of dynamic
        members of the path policy AST.
        """
        import copy
        from pyretic.lib.path import path, path_policy_utils
        #from pyretic.lib.path import __in_re_tree_gen__ as in_cg
        #from pyretic.lib.path import __out_re_tree_gen__ as out_cg
        from pyretic.lib.path import re_tree_gen
        old_dynamic_sub_path_pols = copy.copy(self.dynamic_sub_path_pols)
        ast_fold = path_policy_utils.path_policy_ast_fold
        add_pols = path_policy_utils.add_dynamic_path_pols
        self.dynamic_sub_path_pols = ast_fold(path_pol, add_pols, set())
        for pp in (old_dynamic_sub_path_pols - self.dynamic_sub_path_pols):
            pp.path_detach()
        for pp in (self.dynamic_sub_path_pols - old_dynamic_sub_path_pols):
            pp.path_attach(self.handle_path_change)
        old_dynamic_path_preds = copy.copy(self.dynamic_path_preds)
        dyn_preds_tuples = re_tree_gen.global_dyn_list()
        self.dynamic_path_preds = set(re_tree_gen.global_dyn_list())
        #self.dynamic_path_preds = set(in_cg.get_dyn_preds() +
        #                              out_cg.get_dyn_preds())
        for olds in (old_dynamic_path_preds - self.dynamic_path_preds):
            olds.pred.path_detach()
        for news in (self.dynamic_path_preds - old_dynamic_path_preds):
            news.pred.set_network(self.network)
            news.pred.path_attach(self.handle_path_change_dyn_pred)

    def recompile_paths(self):
        """ Recompile DFA based on new path policy, which in turns updates the
        runtime's policy member. """
        self.in_path_recompile = True
        from pyretic.lib.path import pathcomp, path, path_grouping, path_empty
        path_grouping.set_rtm_fvlist(self.sw_port_ids())
        """ TODO(ngsrinivas): Clearing of virtual fields assumes that path
        queries are the only users of virtual fields. This may not at all be
        true in general!
        """
        virtual_field.clear()
        expanded_paths = path_grouping.expand_groupby(self.path_policy)
        self.ds_path_policy = pathcomp.get_directional_pathpol(expanded_paths,
                                                               path.MEASURE_LOC_DOWNSTREAM)
        self.us_path_policy = pathcomp.get_directional_pathpol(expanded_paths,
                                                               path.MEASURE_LOC_UPSTREAM)

        ds_policy_fragments = pathcomp.compile_downstream(self.ds_path_policy,
            NUM_PATH_TAGS, self.disjoint_enabled, self.default_enabled,
            self.integrate_enabled,
            self.ragel_enabled, self.partition_enabled, self.preddecomp_enabled)

        if self.us_path_policy == path_empty():
            us_policy = drop
        else:
            us_policy = pathcomp.compile_upstream(self.us_path_policy,
                self.sw_port_ids(), self.nw_edges(), self.forwarding,
                self.sw_cnt(),
                NUM_PATH_TAGS, self.disjoint_enabled, self.default_enabled,
                self.integrate_enabled,
                self.ragel_enabled, self.partition_enabled)
        self.path_up_table.policy = us_policy

        (in_res, out_res) = ds_policy_fragments
        if self.integrate_enabled:
            assert len(in_res) == len(out_res)
            for i in range(0, len(in_res)):
                self.path_in_table_list[i].policy  =  in_res[i]
                self.path_out_table_list[i].policy = out_res[i]
        else:
            self.path_ingress = in_res
            self.path_egress  = out_res
            assert len(in_res) == len(out_res)
            for i in range(0, len(in_res)):
                (intagp , incapp)  =  in_res[i]
                (outtagp, outcapp) = out_res[i]
                self.path_in_table_list[i].policy  =  intagp + incapp
                self.path_out_table_list[i].policy = outtagp + outcapp
        self.path_in_table.policy = sequential(self.path_in_table_list)
        self.path_out_table.policy = sequential(self.path_out_table_list)
        self.in_path_recompile = False
        '''(in_tag, in_cap, out_tag, out_cap) = policy_fragments
        self.path_in_tagging.policy  = in_tag
        self.path_in_capture.policy  = in_cap
        self.path_out_tagging.policy = out_tag
        self.path_out_capture.policy = out_cap
        self.path_in_table.policy = in_tag + in_cap
        self.path_out_table.policy = out_tag + out_cap
        '''

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
        default_table = 0
        
        ### IF NO PKTS OUT THEN INSTALL DROP (EMPTY ACTION LIST)
        if len(pkts_out) == 0:
            return (concrete_pred,0,action_list,self.default_cookie,False,default_table)

        for pkt_out in pkts_out:
            concrete_pkt_out = self.pyretic2concrete(pkt_out)
            actions = {}
            header_fields = set(concrete_pkt_out.keys()) | set(concrete_pkt_in.keys())
            for field in header_fields:
                if field not in native_headers + ['port']:
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

        return (concrete_pred,0,action_list,self.default_cookie,False,default_table)

#########################
# PROACTIVE COMPILATION 
#########################

    def get_cookie(self, version, table_id):
        """ Set a cookie which contains information both about the
        classifier version of the rule as well as the table it's going
        into. """
        return (((table_id & 0b11111) << 11) | (version & 0x7ff))

    def get_version_table_from_cookie(self, cookie):
        """ Return a classifier version number and table_id from a cookie. """
        table_id = (cookie >> 11) & 0b11111
        version  = cookie & 0x7ff
        return (version, table_id)

    def install_defaults(self, s, table_id):
        """ Install backup rules on switch s by default. """
        # Fallback "send to controller" rule under table miss
        self.install_rule(({'switch' : s},
                           TABLE_MISS_PRIORITY,
                           [{'port' : OFPP_CONTROLLER}],
                           self.get_cookie(self.default_cookie, table_id),
                           False,
                           table_id))
        # Send all LLDP packets to controller for topology maintenance
        self.install_rule(({'switch' : s, 'ethtype': LLDP_TYPE},
                           TABLE_START_PRIORITY + 2,
                           [{'port' : OFPP_CONTROLLER}],
                           self.get_cookie(self.default_cookie, table_id),
                           False,
                           table_id))
        # Drop all IPv6 packets by default.
        self.install_rule(({'switch':s, 'ethtype':IPV6_TYPE},
                           TABLE_START_PRIORITY + 1,
                           [],
                           self.get_cookie(self.default_cookie, table_id),
                           False,
                           table_id))

    @Stat.collects(['switch count', 'rule count'])
    def install_classifier(self, classifier, table_id=DEFAULT_NX_TABLE_ID):
        """
        Proactively installs switch table entries based on the input classifier

        :param classifier: the input classifer
        :type classifier: Classifier
        """
        if classifier is None:
            return
        if not self.use_nx:
            table_id = 0

        class ListedRule(object):
            """ Rule class used by half of the classifier processing pipeline
            to keep track of various data plane installation parameters, outside
            of the normal classifier.
            """
            def __init__(self, mat=drop, priority=0, actions=[],
                         version=0, cookie=0,
                         table_id=0, notify=False,
                         parents=None, op="policy"):
                self.mat = mat
                self.priority = priority
                self.actions = actions
                self.version = version
                self.cookie = cookie
                self.table_id = table_id
                self.parents = parents
                self.op = op
                self.notify = notify # flow removed notification

            def to_tuple(self):
                return (self.mat, self.priority, self.actions, self.cookie,
                        self.notify, self.table_id)

            def to_rule(self):
                return Rule(self.mat, self.actions,
                            parents=self.parents, op=self.op)

            def __repr__(self):
                out = '\nRule\n  table: %d\n' % self.table_id
                out += '  priority: %d\n' % self.priority
                out += '  cookie: %d\n' % self.cookie
                out += '  match: %s\n' % str(self.mat)
                out += '  actions: %s\n' % str(self.actions)
                return out

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
            if not self.use_nx:
                """ Remove identity policies if using single-stage table. """
                return Classifier(Rule(rule.match,
                                       filter(lambda a: a !=
                                              identity,rule.actions),
                                       parents=rule.parents,
                                       op=rule.op)
                                  for rule in classifier.rules)
            else:
                """ Don't remove identity actions from multi-stage policies. """
                return classifier

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
                new_rules.append(Rule(rule.match, new_acts,
                                      parents=rule.parents,
                                      op=rule.op))
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
                    return Rule(rule.match,[Controller],
                                parents=rule.parents,
                                op=rule.op)
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
                                                  rule.actions,
                                                  parents=rule.parents,
                                                  op=rule.op))
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
                    specialized_rules.append(Rule(rule.match &
                                                  match(ethtype=IP_TYPE),
                                                  rule.actions,
                                                  parents=rule.parents,
                                                  op=rule.op))

                    # DEAL W/ BUG IN OVS ACCEPTING ARP RULES THAT AREN'T ACTUALLY EXECUTED
                    arp_bug = False
                    for action in rule.actions:
                        if ((action == Controller) or
                            isinstance(action, MatchingAggregateBucket) or
                            (self.use_nx and action == identity)):
                            pass
                        elif len(action.map) > 1:
                            """TODO(ngsrinivas): test ARP packet modification
                            behavior and permanently remove arp_bug checks. But
                            for now, commented out.
                            """
                            arp_bug = False
                            # arp_bug = True
                            break
                    if arp_bug:
                        specialized_rules.append(Rule(rule.match &
                                                      match(ethtype=ARP_TYPE),
                                                      [Controller],
                                                      parents=rule.parents,
                                                      op=rule.op))
                    else:
                        specialized_rules.append(Rule(rule.match &
                                                      match(ethtype=ARP_TYPE),
                                                      rule.actions,
                                                      parents=rule.parents,
                                                      op=rule.op))
                else:
                    specialized_rules.append(rule)
            return Classifier(specialized_rules)

        def _collect_buckets(rules, typ):
            """
            Scan classifier rules and collect distinct buckets into a
            dictionary.
            """
            bucket_list = {}
            for rule in rules:
                actions = rule.actions
                for act in actions:
                    if isinstance(act, typ):
                        if not id(act) in bucket_list:
                            bucket_list[id(act)] = act
            return bucket_list

        def bookkeep_count_buckets(diff_lists, table_id):
            """Whenever rules are associated with counting buckets,
            add a reference to the classifier rule into the respective
            bucket for querying later. Count bucket actions operate at
            the pyretic level and are removed before installing rules.

            :param classifier: the input classifer
            :type classifier: Classifier
            :returns: the output classifier
            :rtype: Classifier
            """
            def update_rules_for_buckets(rule, op, table_id):
                match = copy.copy(rule.mat)
                """When running multi-stage table with nicira extensions, we remove
                matches on outports. The flow stats reply matches don't come
                with the outport (or the metadata register) match
                information. Since the priority and version, and rest of the
                match without the outport will match anyhow, we can safely
                remove the outport field from the stored match!

                Such matches still get sent out to the backend with the outport
                field match intact, and data plane forwarding behavior is
                unaffected.
                """
                if self.use_nx:
                    """If the rule is from the first table of the multi-stage pipeline, then retain
                    the port match, else remove it.
                    """
                    if table_id != 0:
                        match.pop('port', None)
                priority = rule.priority
                actions = rule.actions
                version = rule.version
                table_id = rule.table_id
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
                bucket_list = _collect_buckets(all_rules, CountBucket)
                map(lambda x: x.start_update(), bucket_list.values())
                map(lambda x: update_rules_for_buckets(x, "add", table_id), to_add)
                map(lambda x: update_rules_for_buckets(x, "delete", table_id), to_delete)
                map(lambda x: update_rules_for_buckets(x, "stay", table_id), to_stay)
                map(lambda x: update_rules_for_buckets(x, "modify", table_id), to_modify)
                map(lambda x: x.add_pull_stats(self.pull_stats_for_bucket(x)),
                    bucket_list.values())
                map(lambda x: x.add_pull_existing_stats(
                        self.pull_existing_stats_for_bucket(x)),
                    bucket_list.values())
                map(lambda x: x.finish_update(), bucket_list.values())

        def bookkeep_netflow_buckets(diff_lists, table_id):
            """Book-keep netflow buckets in the policy by updating the set of matches
            referred to by each NetflowBucket.
            """
            from pyretic.lib.netflow import NetflowBucket
            def add_rules_for_buckets(rule, table_id):
                """This method is very similar to `update_rules_for_buckets` under
                `bookkeep_count_buckets` above. The operations required to
                update the matches corresponding to NetflowBuckets are similar
                to but simpler than those of CountBuckets.
                """
                match = copy.copy(rule.mat)
                if self.use_nx:
                    if table_id != 0:
                        match.pop('port', None)
                hashable_match = util.frozendict(match)
                rule_key = (hashable_match, rule.priority, rule.version)
                for act in rule.actions:
                    if isinstance(act, NetflowBucket):
                            act.add_match(rule.mat,
                                          rule.priority,
                                          rule.version,
                                          table_id)

            with self.update_buckets_lock:
                (to_add, to_delete, to_modify, to_stay) = diff_lists
                all_rules = to_add + to_delete + to_modify + to_stay
                bucket_list = _collect_buckets(all_rules, NetflowBucket)
                added_rules = to_add + to_modify + to_stay
                curr_buckets = _collect_buckets(added_rules, NetflowBucket)
                NetflowBucket.set_active_buckets(curr_buckets.values(),
                                                 table_id)
                map(lambda x: x.start_update(table_id),  bucket_list.values())
                map(lambda x: x.clear_matches(table_id), bucket_list.values())
                map(lambda x: add_rules_for_buckets(x, table_id), added_rules)
                map(lambda x: x.set_sw_cnt_fun(self.sw_cnt),
                    curr_buckets.values())
                map(lambda x: x.set_sw_port_ids_fun(self.sw_port_ids),
                    curr_buckets.values())
                preproc_pol = self.get_effective_policy_to_table(table_id)
                map(lambda x: x.set_preproc_pol(preproc_pol, table_id),
                    curr_buckets.values())
                map(lambda x: x.finish_update(), bucket_list.values())
                ''' Sufficient to configure OVS from any one active
                NetflowBucket.

                Caution: this statement in the runtime assumes that the
                underlying switches are all OVS, and uses ovs-vsctl both to
                configure netflow/sflow in the network, as well as obtain
                mappings between the interface indices maintained by OVS and the
                (sw,port) values that pyretic uses.
                '''
                if curr_buckets:
                    curr_buckets.values()[0].config_ovs_flow()

        def remove_matching_aggregate_buckets(diff_lists):
            """
            Remove CountBucket policies from classifier rule actions.
            
            :param diff_lists: difference lists between new and old classifier
            :type diff_lists: 4 tuple of rule lists.
            :returns: new difference lists with bucket actions removed
            :rtype: 4 tuple of rule lists.
            """
            from pyretic.lib.netflow import NetflowBucket
            new_diff_lists = []
            for lst in diff_lists:
                new_lst = []
                for rule in lst:
                    acts = rule.actions
                    new_acts = filter(lambda x: not isinstance(x, CountBucket),
                                      acts)
                    notify_flag = True if len(new_acts) < len(acts) else False
                    newer_acts = filter(lambda x:
                                        not isinstance(x, NetflowBucket), new_acts)
                    new_rule = ListedRule(mat=rule.mat,
                                          priority=rule.priority,
                                          actions=newer_acts,
                                          version=rule.version,
                                          cookie=rule.cookie,
                                          notify=notify_flag,
                                          table_id=rule.table_id,
                                          parents=rule.parents,
                                          op=rule.op)
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
                            rule.actions,
                            parents=rule.parents,
                            op=rule.op))
            return Classifier(new_rules)

        def concretize(classifier, table_id):
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
                        return {'port' : OFPP_CONTROLLER}
                    elif isinstance(a,modify):
                        return { k:v for (k,v) in a.map.iteritems() }
                    elif self.use_nx and a == identity:
                        return {'port' : CUSTOM_NEXT_TABLE_PORT }
                    else: # default
                        return a
                m = concretize_match(rule.match)
                acts = [concretize_action(a) for a in rule.actions]
                if m is None:
                    return None
                else:
                    return Rule(m,acts,parents=rule.parents,op=rule.op)
            crs = [concretize_rule_actions(r) for r in classifier.rules]
            crs = filter(lambda cr: not cr is None,crs)
            return Classifier(crs)

        def set_next_table_port(classifier):
            def set_next_table_outport(acts):
                """ If an action in acts does not contain an outport, add the
                "next table" outport to it. Applicable only in multi-stage table
                mode."""
                new_acts = []
                for act in acts:
                    if not isinstance(act, Query) and not 'port' in act:
                        act['port'] = CUSTOM_NEXT_TABLE_PORT
                    new_acts.append(act)
                return new_acts
            return Classifier([Rule(r.match,
                                    set_next_table_outport(r.actions),
                                    parents=r.parents, op=r.op)
                               for r in classifier.rules])

        def check_OF_rules(classifier):
            def check_OF_rule_has_outport(acts):
                for a in acts:
                    if not 'port' in a:
                        raise TypeError('Invalid rule: concrete actions must have an outport',str(r))  
            def check_OF_rule_has_compilable_action_list(acts):
                if len(acts)<2:
                    pass
                else:
                    prev_moded_fields = set(acts[0].keys())
                    for a in acts:
                        curr_moded_fields = set(a.keys())
                        if prev_moded_fields - curr_moded_fields:
                            raise TypeError('Non-compilable rule',str(r))  
                        prev_moded_fields = curr_moded_fields
            new_rules = list()
            for r in classifier.rules:
                r_minus_queries = Rule(r.match,
                                       filter(lambda x:
                                              not isinstance(x, Query),
                                              r.actions))
                modify_acts = sorted(filter(lambda x: not isinstance(x, Query),
                                       r.actions), key=len)
                query_acts = filter(lambda x: isinstance(x, Query), r.actions)
                check_OF_rule_has_outport(modify_acts)
                check_OF_rule_has_compilable_action_list(modify_acts)
                new_rules.append(Rule(r.match, modify_acts + query_acts,
                                      r.parents, r.op))
            return Classifier(new_rules)

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
                    if not isinstance(act, MatchingAggregateBucket):
                        new_actions.append(copy.deepcopy(act))
                    else:
                        new_actions.append(act) # can't make copies of
                                                # CountBuckets without
                                                # forking
                for action in new_actions:
                    try:
                        if not isinstance(action, MatchingAggregateBucket):
                            if action['port'] == outport:
                                action['port'] = OFPP_IN_PORT
                    except:
                        raise TypeError  # INVARIANT: every set of actions must go out a port
                                         # this may not hold when we move to OF 1.3
                return new_actions

            specialized_rules = []
            for rule in classifier.rules:
                phys_actions = filter(lambda a: (
                        not isinstance(a, MatchingAggregateBucket)
                        and a['port'] != OFPP_CONTROLLER
                        and a['port'] != OFPP_IN_PORT
                        and a['port'] != CUSTOM_NEXT_TABLE_PORT),
                                      rule.actions)
                outports_used = map(lambda a: a['port'], phys_actions)
                if not 'port' in rule.match:
                    # Add a modified rule for each of the outports_used
                    switch = rule.match['switch']
                    for outport in outports_used:
                        new_match = copy.deepcopy(rule.match)
                        new_match['port'] = outport
                        new_actions = specialize_actions(rule.actions,outport)
                        specialized_rules.append(Rule(new_match,new_actions,
                                                      parents=rule.parents,
                                                      op=rule.op))
                    # And a default rule for any inport outside the set of outports_used
                    specialized_rules.append(rule)
                else:
                    if rule.match['port'] in outports_used:
                        # Modify the set of actions
                        new_actions = specialize_actions(rule.actions,rule.match['port'])
                        specialized_rules.append(Rule(rule.match,new_actions,
                                                      parents=rule.parents,
                                                      op=rule.op))
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
                r = ListedRule(mat=rule.match,
                               priority=priority[s],
                               actions=rule.actions,
                               parents=rule.parents,
                               op=rule.op)
                tuple_rules.append(r)
            return tuple_rules

        ### UPDATE LOGIC

        def nuclear_install(new_rules, curr_classifier_no, table_id):
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
                self.send_clear(s, table_id)
                self.send_barrier(s)
                self.install_defaults(s, table_id)

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
                if target.mat == rule.mat and target.priority == rule.priority:
                    return rule
            return None

        def get_new_rules(classifier, curr_classifier_no, table_id):
            def add_cookie(rules, cookie_val):
                new_rules = []
                for r in rules:
                    new_rules.append(ListedRule(mat=r.mat,
                                                priority=r.priority,
                                                actions=r.actions,
                                                version=cookie_val,
                                                cookie=cookie_val,
                                                table_id=r.table_id,
                                                parents=r.parents,
                                                op=r.op))
                return new_rules

            def add_table_id(rules, table_id_val):
                new_rules = []
                for r in rules:
                    new_rules.append(ListedRule(mat=r.mat,
                                                priority=r.priority,
                                                actions=r.actions,
                                                version=r.version,
                                                cookie=r.cookie,
                                                table_id=table_id_val,
                                                parents=r.parents,
                                                op=r.op))
                return new_rules

            switches = self.network.switch_list()

            classifier = switchify(classifier,switches)
            classifier = concretize(classifier, table_id)
            if self.use_nx:
                classifier = set_next_table_port(classifier)
            classifier = check_OF_rules(classifier)
            classifier = OF_inportize(classifier)
            new_rules = prioritize(classifier)
            cookie = self.get_cookie(curr_classifier_no, table_id)
            new_rules = add_cookie(new_rules, cookie)
            new_rules = add_table_id(new_rules, table_id)
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
            """ TODO: this function needs to be updated with multiple
            tables. There must now be one old_rules structure corresponding
            to each table_id. """
            def different_actions(old_acts, new_acts):
                def buckets_removed(acts):
                    return filter(lambda a: not isinstance(a, MatchingAggregateBucket),
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
                        new_match = new.mat
                        new_priority = new.priority
                        new_actions = new.actions
                        old_actions = old.actions
                        old_version = old.version
                        if different_actions(old_actions, new_actions):
                            modified_rule = ListedRule(mat=new_match,
                                                       priority=new_priority,
                                                       actions=new_actions,
                                                       version=old_version,
                                                       cookie=new.cookie,
                                                       table_id=new.table_id,
                                                       parents=new.parents,
                                                       op=new.op)
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

        def convert_to_tuple(diff_lists):
            new_diff_lists = []
            for lst in diff_lists:
                new_lst = []
                for lr in lst:
                    new_lst.append(lr.to_tuple())
                new_diff_lists.append(new_lst)
            return new_diff_lists

        def install_diff_lists(diff_lists, classifier_version_no, table_id):
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
                    self.send_clear(s, table_id)
                    self.send_barrier(s)
                    self.install_defaults(s, table_id)

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

        def f(diff_lists,curr_version_no,table_id):
            self.send_reset_install_time()
            with self.switch_lock:
                install_diff_lists(diff_lists,curr_version_no,table_id)

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
        new_rules = get_new_rules(classifier, curr_version_no, table_id)
        self.log.debug("Number of rules in classifier: %d" % len(new_rules))

        # Get statistics
        stat_switch_cnt = len(self.network.topology.nodes())
        Stat.collect_stat('switch count', stat_switch_cnt)
        Stat.collect_stat('rule count', len(new_rules))

        diff_lists = get_diff_lists(new_rules)
        bookkeep_count_buckets(diff_lists, table_id)
        bookkeep_netflow_buckets(diff_lists, table_id)
        diff_lists = remove_matching_aggregate_buckets(diff_lists)

        self.log.debug('================================')
        self.log.debug('Final classifier to be installed:')
        for rule in new_rules:
            self.log.debug(str(rule))
        self.log.debug('================================')

        # This is the point to do any diagnostics on classifier rules, since the
        # ListedRule structure contains parents and operation pointers.
        # These are removed before being passed on to the data plane rule
        # installation routine below.
        diff_lists = convert_to_tuple(diff_lists)

        p = Process(target=f, args=(diff_lists,curr_version_no,table_id))
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
                    if not s in self.last_queried_time:
                        self.log.error("Did not find the switch in last queried table!!")
                        self.log.error("Switch %s" % s)
                        self.log.error("last queried time list: %s" %
                                       str(self.last_queried_time))
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
        packet['port'] = raw_pkt['port']

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

        for header in ['switch', 'port']:
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
                if header in ['switch', 'port']: next
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

    def install_rule(self,(concrete_pred,priority,action_list,cookie,notify,table_id)):
        self.log.debug(
            '|%s|\n\t%s\n\t%s\n' % (str(datetime.now()),
                "sending openflow rule:",
                (str(priority) + " " + repr(concrete_pred) + " "+
                 repr(action_list) + " " + repr(cookie))))
        self.backend.send_install(concrete_pred,priority,action_list,cookie,notify,table_id)

    def modify_rule(self, (concrete_pred,priority,action_list,cookie,notify,table_id)):
        self.backend.send_modify(concrete_pred,priority,action_list,cookie,notify,table_id)

    def delete_rule(self,(concrete_pred,priority)):
        self.backend.send_delete(concrete_pred,priority)

    def send_barrier(self,switch):
        self.backend.send_barrier(switch)

    def send_clear(self,switch,table_id):
        self.backend.send_clear(switch,table_id)

    def clear_all(self, table_id=0):
        def f():
            switches = self.network.switch_list()
            for s in switches:
                self.send_barrier(s)
                self.send_clear(s, table_id)
                self.send_barrier(s)
                self.install_defaults(s, table_id)
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
            link_transfer_policy = ((match(switch=s1,port=p1) >>
                                     modify(switch=s2,port=p2)) +
                                    (match(switch=s2,port=p2) >>
                                     modify(switch=s1,port=p1)))
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
            egress_match = match(switch=sw_no,port=port_no)
            if pol == drop:
                pol = egress_match
            else:
                pol += egress_match
        return pol

    def get_fwding_policy(self):
        return self.policy

################################################################################
# MULTI-STAGE TABLE CONFIGURATION
################################################################################

    def set_policy_map(self, path_main):
        """ Set up the mapping between specific policies and tables in a
        multi-stage pipeline. This loosely corresponds to the ``configuration''
        phase of a reprogrammable switch, such as RMT.
        """
        def get_effective_forwarding_policy(path_main):
            if path_main:
                return self.path_based_forwarding
            else:
                return self.forwarding
        use_nx = self.use_nx
        pipeline = self.pipeline
        assert pipeline in ['default_pipeline', 'path_query_pipeline', 'mt']
        if use_nx and pipeline == 'default_pipeline':
            self.policy_map = self.default_pipeline_policy_map(
                get_effective_forwarding_policy(path_main))
            self.policy = self.policy_map[1]
        elif use_nx and pipeline == 'path_query_pipeline' and path_main:
            self.policy_map = self.path_query_pipeline_policy_map(
                self.virtual_tag, self.path_in_table,
                self.forwarding, self.path_out_table,
                self.virtual_untag, self.path_up_table)
            self.policy = (self.policy_map[0] >>
                           self.policy_map[1] >>
                           self.policy_map[2] >>
                           self.policy_map[3] >>
                           self.policy_map[4] >>
                           self.policy_map[5])
        elif use_nx and pipeline == 'mt' and path_main:
            """ EXTENSIVELY multi-staged pipeline """
            self.policy_map = self.mt_policy_map(
                self.virtual_tag, self.path_in_table_list,
                self.forwarding, self.path_out_table_list,
                self.virtual_untag, self.path_up_table)
            self.policy = sequential([self.policy_map[x] for x in sorted(self.policy_map.keys())])
        elif use_nx:
            path_exists = 'not' if path_main is None else ''
            raise RuntimeError("No table to policy map configuration defined for"
                               " pipeline %s (path_main %s provided)" % (
                                   pipeline, path_exists))
        else:
            self.policy_map = self.single_stage_policy_map(
                get_effective_forwarding_policy(path_main))
            self.policy = self.policy_map[0]

    def get_effective_policy_from_table(self, table_id):
        """ Return the effective policy to evaluate a policy, if a packet is
        sent to controller from table `table_id`.
        """
        num_tables = len(self.policy_map.keys())
        """ Assume a sequential pipeline of policies. """
        seq_list = [self.policy_map[k] for k in range(table_id, num_tables)]
        return sequential(seq_list)

    def get_effective_policy_to_table(self, table_id):
        """ Return the effective policy to evaluate a packet, if a packet
        arrives at a switch inport before it arrives at table `table_id`. Assume
        a sequentual pipeline of policies stored in `policy_map`.
        """
        seq_list = [self.policy_map[k] for k in range(0, table_id-1)]
        return sequential(seq_list)

    def single_stage_policy_map(self, pol):
        """ A dummy policy map for single-stage tables. Useful for
        uniformity. """
        return {0: pol}

    def default_pipeline_policy_map(self, pol):
        """ The default pipeline for multi-stage tables with pyretic. Simple
        configuration:

        table with a single fallthrough rule ->
        actual rule with _full_ policy
        """
        return {0: identity,
                1: pol}

    def path_query_pipeline_policy_map(self, virtual_tag, in_table, forwarding,
                                       out_table, virtual_untag, up_table):
        return {0: identity + up_table,
                1: virtual_tag,
                2: in_table,
                3: forwarding,
                4: out_table,
                5: virtual_untag}

    def mt_policy_map(self, virtual_tag, in_table_list, forwarding,
                      out_table_list, virtual_untag, up_table):
        m = {0: identity + up_table,
             1: virtual_tag,
             MAX_STAGES + 2: forwarding,
             (2*MAX_STAGES) + 3: virtual_untag}
        m.update({k+2: in_table_list[k] for k in range(0, MAX_STAGES)})
        m.update({k+MAX_STAGES+3: out_table_list[k]
                  for k in range(0, MAX_STAGES)})
        return m


###############################
# PATH QUERY INITIALIZATION
###############################

    def init_path_query(self, path_main, kwargs, partition_cnt, cache_enabled,
                        edge_contraction_enabled, use_fdd=False, write_log=None):
        """
        Initialization of path query library with optimization parameters.
        * partition_cnt: how many partitions for predicate overlap detection?
        * cache_enabled: is caching of predicates enabled?
        * edge_contraction_enabled: is contraction of DFA edges enabled?
        """
        self.path_policy = None
        self.us_path_policy = None
        self.ds_path_policy = None
        self.path_in_tagging  = DynamicPolicy(identity)
        self.path_in_capture  = DynamicPolicy(drop)
        self.path_out_tagging = DynamicPolicy(identity)
        self.path_out_capture = DynamicPolicy(drop)
        self.path_in_table = DynamicPolicy(identity)
        self.path_out_table = DynamicPolicy(identity)
        self.path_in_table_list = [DynamicPolicy(identity) for k in range(0,MAX_STAGES)]
        self.path_out_table_list = [DynamicPolicy(identity) for k in range(0,MAX_STAGES)]
        self.path_up_table = DynamicPolicy(drop)
        self.dynamic_sub_path_pols = set()
        self.dynamic_path_preds    = set()
        self.vf_tag_pol = None
        self.vf_untag_pol = None
        self.virtual_tag = identity
        self.virtual_untag = identity
        self.path_policy = None

        if path_main:
            from pyretic.lib.path import pathcomp
            pathcomp.init(NUM_PATH_TAGS, self.sw_cnt(),
                          self.cache_enabled, self.edge_contraction_enabled,
                          self.partition_enabled, use_fdd = use_fdd,
                          write_log=write_log)
            t_s = time.time()
            self.path_policy = path_main(**kwargs)
            self.log.debug("query instantiation time : %f" % (time.time() - t_s))
            t_s = time.time()
            self.handle_path_change()
            self.log.debug("total handle_path_change time: %f" % (
                time.time() - t_s))
            self.virtual_tag = virtual_field_tagging()
            self.virtual_untag = virtual_field_untagging()
            # Path_based_forwarding, below, is the policy used in the
            # interpreter, and to compile down when running single-table
            # switches.
            self.path_based_forwarding = (self.path_up_table +
                (self.virtual_tag >>
                 self.path_in_table  >>
                 self.forwarding >>
                 self.path_out_table >>
                 self.virtual_untag))

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
        try:
            self.next_topo.add_port(switch,port_no,config,status,port_type)
        except KeyError:
            self.log.error("Couldn't handle port join. Switch likely "
                           "doesn't exist yet")
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
class abstract_virtual_field(object):
    """ Class members for book-keeping across multiple virtual fields. """
    fields = {}
    stages = {}
    stage_offset_nbits = {}
    virtual_none = DynamicPolicy(identity)

    def __init__(self, name, values, type="string", stage=0):
        self.name   = name
        self.values = values
        self.stage = stage
        # We need a None value as well
        self.cardinality = len(values) + 1
        self.type   = type
        cls = self.__class__
        cls.fields[name] = self
        try:
           cls.stages[stage].append(self)
        except KeyError:
            cls.stages[stage] = [self]
        cls.allocate_stage_bits()
        cls.reset_virtual_none()

    @classmethod
    def clear(cls):
        """ Clear all state associated with virtual header. Useful for unit
        testing. """
        cls.fields = {}
        cls.stages = {}
        cls.stage_offset_nbits = {}
        cls.virtual_none.policy = identity

    @classmethod
    def get_class(cls, name):
        if name in virtual_field.fields:
            return virtual_field
        elif name in virtual_virtual_field.fields:
            return virtual_virtual_field
        else:
            return None

    @classmethod
    def allocate_stage_bits(cls):
        """Compute the bits used to represent virtual header fields at each stage.
        """
        stages_dict = cls.stages
        fields_dict = cls.fields
        import math
        bit_offset = 0
        stages = sorted(stages_dict.keys())
        cls.stage_offset_nbits = {}
        for s in stages:
            cardinality_list = map(lambda x: x.cardinality, stages_dict[s])
            num_total_values = reduce(lambda acc, x: acc * x,
                                      cardinality_list, 1)
            nbits = int(math.ceil(math.log(num_total_values, 2)))
            cls.stage_offset_nbits[s] = (bit_offset, nbits)
            bit_offset += nbits

    def index(self,key):
        try:
            return self.values.index(key)
        except ValueError as e:
            if key == None:
                return len(self.values)
            raise e

    def value(self,index):
        try:
            return self.values[index]
        except IndexError as e:
            if index == len(self.values):
                return None
            raise e

    @classmethod
    def compress(cls,fields):
        virtual_fields = cls.fields
        vf_names       = virtual_fields.keys()

        undeclared_vfs = set(fields.keys()) - set(vf_names)
        if undeclared_vfs:
            raise RuntimeError("Detected use of undefined fields: %s" %
                               str(undeclared_vfs))

        def vhs_to_num(fields):
            vheaders = dict(filter(lambda a: a[0] in vf_names, fields.iteritems()))
            # If we there are no virtual_fields specified we wouldn't want to match on them at all
            # Just return -1 so that calling function knows that the predicate doesn't have any virtual
            # fields on it
            if len(vheaders) == 0: return (-1, 0, 0)
            stages = set()

            for n in vf_names:
                if n not in vheaders:
                    vheaders[n] = None
                else:
                    stages.add(virtual_fields[n].stage)
            if len(stages) != 1:
                raise RuntimeError("Can't compile virtual headers from different"
                                   " stages together!")
            active_stage = list(stages)[0]

            # sort the field name list to have deterministic ordering by field
            # name
            field_list = sorted(virtual_fields.items(), key=lambda z: z[0])
            ret = 0
            for n,vf in field_list:
                if virtual_fields[n].stage == active_stage:
                    ret *= vf.cardinality
                    ret += vf.index(vheaders[n])

            (offset, nbits) = cls.stage_offset_nbits[active_stage]
            # shift virtual headers into position
            ret = ret << offset
            return (ret, offset, nbits)
        return vhs_to_num(fields)

    @classmethod
    def expand(cls,fields):
        if 'vlan_id' not in fields:
            return {}

        virtual_fields = cls.fields
        vf_names       = virtual_fields.keys()
        num = (fields['vlan_pcp'] << 12) + fields['vlan_id']

        def num_to_vhs(num):
            # If we there are no virtual_fields specified we wouldn't want to match on them at all
            # Just return -1 so that calling function knows that the predicate doesn't have any virtual
            # fields on it
            vfs = {}
            for stage in cls.stages.keys():
                (offset, nbits) = cls.stage_offset_nbits[stage]
                tmp = (num >> offset) & ((1 << nbits) - 1)
                # sort the field name list to have deterministic ordering by
                # field name
                field_list = sorted(virtual_fields.items(), key=lambda z:z[0])
                for n,vf in reversed(field_list):
                    if vf.stage == stage:
                        val    = tmp % vf.cardinality
                        tmp    = tmp / vf.cardinality
                        vfs[n] = vf.value(val)

            return vfs
        return num_to_vhs(num)

    @classmethod
    def map_to_vlan(cls,compressed):
        (num, offset, nbits) = compressed
        if num == -1: return {}
        if num > (1 << 15):
            raise RuntimeError("Too many virtual values to stuff into VLAN.")
        return {
            "vlan_id" : 0b000111111111111 & num,
            "vlan_pcp": (0b111000000000000 & num) >> 12,
            "vlan_offset": offset,
            "vlan_nbits": nbits,
            "vlan_total_stages": len(cls.stages.keys())
        }

    @classmethod
    def reset_virtual_none(cls):
        """ Return a VLAN header corresponding to all `None` virtual fields. """
        vlan = 0
        for (stage, vals) in cls.stages.items():
            (num, offset, nbits) = cls.compress({vals[0].name: None})
            vlan = vlan | (num & (((1 << nbits)-1)<<offset))
        from pyretic.core.language import _modify
        cls.virtual_none.policy = _modify(cls.map_to_vlan((vlan, 0, 15)))

    @classmethod
    def get_virtual_none(cls):
        return cls.virtual_none

class virtual_field(abstract_virtual_field):
    """ Virtual header fields which eventually do make it to the data plane. """
    fields = {}
    stages = {}
    stage_offset_nbits = {}
    virtual_none = DynamicPolicy(identity)

class virtual_virtual_field(abstract_virtual_field):
    """ Keeping the virtual fields which don't make it to the data plane
    separate. Bit allocations, etc. will be separate. """
    fields = {}
    stages = {}
    stage_offset_nbits = {}
    virtual_none = DynamicPolicy(identity)
