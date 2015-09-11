import sys
sys.path.append('/home/mina/pyretic')
sys.path.append('/home/mina/mininet')
import os
import shutil
import subprocess, shlex

from pyretic.core.runtime import Runtime, NUM_PATH_TAGS
from pyretic.core.language import *
from pyretic.lib.corelib import *
from pyretic.lib.path import *

from pyretic.evaluations.stat import Stat
from pyretic.evaluations import eval_path

import argparse

class eval_compilation:

    def __init__(self, args, kwargs):
        
        self.add_calls = 0       
        self.results_folder = args.results_folder

        self.disjoint_enabled = args.disjoint_enabled
        self.default_enabled = args.default_enabled
        self.integrate_enabled = args.integrate_enabled
        self.multitable_enabled = args.multitable_enabled
        self.ragel_enabled = args.ragel_enabled
        self.partition_enabled = args.partition_enabled
        self.switch_cnt = args.switch_cnt
        self.cache_enabled = args.cache_enabled
        self.edge_contraction_enabled = args.edge_contraction_enabled
        self.preddecomp_enabled = args.preddecomp_enabled
        self.use_pyretic = args.use_pyretic 
        if args.write_log:
            self.write_log = args.write_log
        else:
            self.write_log = os.path.join('pyretic/evaluations',
                                          self.results_folder, 'rt_log.txt')
        self.use_fdd = args.use_fdd
        
        opt_flags = (self.disjoint_enabled, self.default_enabled, 
                     self.integrate_enabled, self.multitable_enabled,
                     self.ragel_enabled, self.partition_enabled, 
                     self.switch_cnt,
                     self.cache_enabled, self.edge_contraction_enabled,
                     self.preddecomp_enabled
                     )
        """ Start the frenetic compiler-server """
        netkat_out = None
        if not self.use_pyretic:
            netkat_cmd = "bash ~/pyretic/start-frenetic.sh"
            try:
                netkat_out = subprocess.Popen(netkat_cmd, shell=True,
                                          stderr=subprocess.STDOUT)
            except Exception as e:
                print "Could not start frenetic server successfully."
                print e
                sys.exit(1)
        
        Stat.start(self.results_folder, (self.disjoint_enabled, self.integrate_enabled, self.multitable_enabled, self.ragel_enabled))
        self.runtime = Runtime(None, eval_path.main, eval_path.path_main, kwargs,
                               opt_flags = opt_flags, mode = 'proactive0',
                               use_pyretic = self.use_pyretic, use_fdd = self.use_fdd,
                               offline=True,
                               write_log = self.write_log, restart_frenetic = False)
        Stat.stop()
        if netkat_out:
            netkat_out.kill()
        self.kill_netkat_server()

    def kill_netkat_server(self):
        print "Killing frenetic.."
        kill_cmd = "sudo bash kill-frenetic.sh"
        try:
            netkat_out = subprocess.check_output(shlex.split(kill_cmd))
        except Exception as e:
            print "Could not kill the frenetic server."
            print e
            sys.exit(1)
    
    def recompile_paths(self):
        """ Recompile DFA based on new path policy, which in turns updates the
        runtime's policy member. """
        policy_fragments = pathcomp.add_query(self.path_policy, NUM_PATH_TAGS, 
                self.disjoint_enabled, self.default_enabled, self.multitable_enabled and self.integrate_enabled, 
                self.ragel_enabled, self.partition_enabled)

        if self.multitable_enabled and self.integrate_enabled:
            (self.runtime.path_in_table.policy, self.runtime.path_out_table.policy) = policy_fragments
        else:
            (in_tag, in_cap, out_tag, out_cap) = policy_fragments
            self.runtime.path_in_tagging.policy  = in_tag
            self.runtime.path_in_capture.policy  = in_cap
            self.runtime.path_out_tagging.policy = out_tag
            self.runtime.path_out_capture.policy = out_cap
            self.runtime.path_in_table.policy = in_tag + in_cap
            self.runtime.path_out_table.policy = out_tag + out_cap    
    
    def add(self, **aparams):
        self.path_policy = eval_path.path_main(**aparams)
        
        self.add_calls += 1
        results_folder = "%s_%d" % (self.results_folder[:-1], self.add_calls)
        
        Stat.start(results_folder, (self.disjoint_enabled, self.integrate_enabled, self.multitable_enabled, self.ragel_enabled))
        
        self.recompile_paths()
        self.runtime.get_subpolicy_compile_stats(eval_path.path_main)
        
        Stat.stop()

    def get_vf_tagging_policy(self):
        return None


    def get_vf_untagging_policy(self):
        return None


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluates compilation of path query toghether with the forwarding policy")
    parser.add_argument("-t", "--test", required=True
                        , help="Test case to run")
    
    parser.add_argument("--added_query", nargs = '+'
                        , help= "Test case to be added to the main test")

    parser.add_argument("-f", "--results_folder",
                        default="./results/",
                        help="Folder to put the raw results data into")

    parser.add_argument("-polargs", "--policy_args", nargs='+')

    parser.add_argument("-apolargs", "--added_policy_args", nargs='+')

    parser.add_argument( '--enable_disjoint', '-d', action="store_true",
                    dest="disjoint_enabled",
                    help = 'enable disjoint optimization')

    parser.add_argument( '--enable_default_link', '-l', action="store_true",
                    dest="default_enabled",
                    help = 'enable default link optimization, only works with disjoint on')

    parser.add_argument('--enable_integration', '-i', action="store_true",
                    dest='integrate_enabled',
                    help = 'enable integration of tag and capture optimization, only works with multitable on')

    parser.add_argument('--enable_multitable', '-u', action="store_true",
                    dest = 'multitable_enabled',
                    help = 'enable multitable optimization')

    parser.add_argument('--enable_ragel', '-r', action="store_true",
                    dest = 'ragel_enabled',
                    help = 'enable ragel optimization')

    parser.add_argument('--enable_partition', '-a', action = "store_true",
                    dest = 'partition_enabled',
                    help = 'enable partition optimization')
    
    parser.add_argument('--switch_count', '-s', type = int,
                    dest = 'switch_cnt',
                    help = 'The expected number of switches, used for offline analysis')

    parser.add_argument('--enable_cache', '-c', action="store_true",
                    dest = 'cache_enabled',
                    help = 'enable cache optimization')

    parser.add_argument('--enable_edge_contraction', '-g', action="store_true",
                    dest = 'edge_contraction_enabled',
                    help = 'enable edge contratction optimization, works only with cache enabled')

    parser.add_argument('--enable_preddecomp', '-b', action="store_true",
                    dest = "preddecomp_enabled",
                    help = "enable predicate decomposition into multiple stages")

    parser.add_argument('--use_pyretic', action="store_true",
                    dest = 'use_pyretic',
                    help = 'Use the pyretic compiler (uses netkat by default)')
    parser.add_argument('--write_log', dest="write_log",
                        help = "Runtime write log file location")
    parser.add_argument('--use_fdd', action="store_true",
                    dest = 'use_fdd',
                    help = 'Use FDD for predicate decomposition')

    args = parser.parse_args()

    return args



def get_testwise_params(args):
    params = {}
    if args.policy_args:
        arg_iter = iter(args.policy_args)
        for arg in arg_iter:
            val = next(arg_iter)
            params[arg] = val
    params['test'] = args.test
    print params
    return params

def get_added_query_params(args):
    params = {}
    if args.added_policy_args:
        arg_iter = iter(args.added_policy_args)
        for arg in arg_iter:
            val = next(arg_iter)
            params[arg] = val
    params['test'] = args.added_query
    print params
    return params

def get_optimization_flags(args):
    params = []
    d = args.__dict__
    for arg in d:
        if (('enabled' in arg or arg == 'switch_cnt' or arg == 'use_fdd')
            and d[arg]):
            params.append(arg)

    return params

if __name__ == '__main__':
    args = parse_args()
    print get_optimization_flags(args)
    
    #import cProfile
    #cProfile.run('eval_comp = eval_compilation(args, get_testwise_params(args))')
    eval_comp = eval_compilation(args, get_testwise_params(args)) 
    print "Returned from eval_compilation"
    
    if args.added_query:
        for aq in args.added_query:
            #aparams = get_added_query_params(args)
            aparams = {'test': aq}
            print aparams 
            eval_comp.add(**aparams)

    sys.exit(0)
    
