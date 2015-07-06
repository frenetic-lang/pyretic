import sys
sys.path.append('/home/mina/pyretic')
sys.path.append('/home/mina/mininet')
import os
import shutil

from pyretic.core.runtime import Runtime
from pyretic.core.language import *
from pyretic.lib.corelib import *
from pyretic.lib.path import *

from pyretic.evaluations.stat import Stat
from pyretic.evaluations import eval_path

import argparse

class eval_compilation:

    def __init__(self, args, kwargs):
       
        self.results_folder = args.results_folder

        self.disjoint_enabled = args.disjoint_enabled
        self.default_enabled = args.default_enabled
        self.integrate_enabled = args.integrate_enabled
        self.multitable_enabled = args.multitable_enabled
        self.ragel_enabled = args.ragel_enabled

        if args.switch_cnt:
            self.partition_enabled = True
            self.switch_cnt = args.switch_cnt
        else:
            self.partition_enabled = False
            self.switch_cnt = None

        self.cache_enabled = args.cache_enabled
        self.edge_contraction_enabled = args.edge_contraction_enabled
        self.use_pyretic = args.use_pyretic 
        
        opt_flags = (self.disjoint_enabled, self.default_enabled, 
                     self.integrate_enabled, self.multitable_enabled,
                     self.ragel_enabled, self.switch_cnt,
                     self.cache_enabled, self.edge_contraction_enabled,
                     )
        """ Start the frenetic compiler-server """
        if not self.use_pyretic:
            netkat_cmd = "bash start-frenetic.sh"
            try:
                output = subprocess.Popen(netkat_cmd, shell=True,
                                          stderr=subprocess.STDOUT)
            except Exception as e:
                print "Could not start frenetic server successfully."
                print e
                sys.exit(1)
        
        Stat.start(self.results_folder, (self.disjoint_enabled, self.integrate_enabled, self.multitable_enabled, self.ragel_enabled))
        self.runtime = Runtime(None, eval_path.main, eval_path.path_main, kwargs,
                    opt_flags = opt_flags, mode = 'proactive0', 
                    use_pyretic = self.use_pyretic, offline=True)
        
        Stat.stop()
     
    '''
    def add(self, full_compile, **aparams):
        self.path_policy = eval_path.path_main(**aparams)
        
        self.add_calls += 1
        results_folder = "%s_%d" % (self.results_folder[:-1], self.add_calls)
        stat.start(results_folder, (self.disjoint_enabled, self.integrate_enabled, self.multitable_enabled, self.ragel_enabled))
        
        policy_fragments = pathcomp.add_query(self.path_policy, self.max_states, 
                self.disjoint_enabled, self.default_enabled, self.multitable_enabled and self.integrate_enabled, 
                self.ragel_enabled, self.partition_enabled)
        
        #return
        if self.multitable_enabled and self.integrate_enabled:
            (self.path_in_table, self.path_out_table) = policy_fragments
        else:
            (in_tag, in_cap, out_tag, out_cap) = policy_fragments
            self.path_in_tagging  = in_tag
            self.path_in_capture = in_cap
            self.path_out_tagging= out_tag
            self.path_out_capture = out_cap

                
        if self.multitable_enabled:
            if self.integrate_enabled:
                self.forwarding_compile(self.switch_cnt)
                self.in_table_compile(self.switch_cnt)
                self.out_table_compile(self.switch_cnt)
                
            else:
                
                self.forwarding_compile()
                self.tagging_compile()
                self.out_tagging_compile()
                self.capture_compile()
                self.out_capture_compile()
                
                self.path_in_table = self.path_in_tagging + self.path_in_capture
                self.path_out_table = self.path_out_tagging + self.path_out_capture
                
                self.in_table_compile()
                self.out_table_compile()

                
        else:
            
            in_tag_policy = self.path_in_tagging >> self.policy
            self.forwarding = (in_tag_policy >> self.path_out_tagging)
            in_capture  = self.path_in_capture
            self.out_capture = (in_tag_policy >> self.path_out_capture)

            ## gathering stats
            # forwarding
            self.forwarding_compile()
            self.tagging_compile()
            self.out_tagging_compile()
            self.tag_fwd_compile()

        
            #capture
            self.capture_compile()
            self.out_capture_compile()
            self.full_out_capture_compile()


        if full_compile:
            self.virtual_tag = self.get_vf_tagging_policy()
            self.virtual_untag = self.get_vf_untagging_policy()

            # virtual tags
            self.vf_tag_compile()
            self.vf_untag_compile()
            
            
            if multitable_enabled:
                self.overall_policy = self.virtual_tag >> self.policy >> self.virtual_untag
                self.whole_policy_compile()

            else:
                self.vtag_forwarding = (self.virtual_tag >> self.forwarding >> self.virtual_untag)
                self.vtag_in_capture = (self.virtual_tag >> in_capture)
                self.vtag_out_capture = (self.virtual_tag >> out_capture)

                self.vtag_fw_compile()
                self.vtag_in_capture_compile()
                self.vtag_out_capture_compile()

                self.overall_policy = self.vtag_forwarding + self.vtag_in_capture + self.vtag_out_capture
                self.whole_policy_compile()


        stat.stop()
    '''

    def get_vf_tagging_policy(self):
        return None


    def get_vf_untagging_policy(self):
        return None


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluates compilation of path query toghether with the forwarding policy")
    parser.add_argument("-t", "--test", required=True
                        , help="Test case to run")
    
    parser.add_argument("-a", "--added_query", nargs = '+'
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


    parser.add_argument('--enable_partition', '-s', type=int,
                    dest = 'switch_cnt',
                    help = 'enable partition optimization')

    parser.add_argument('--enable_cache', '-c', action="store_true",
                    dest = 'cache_enabled',
                    help = 'enable cache optimization')

    parser.add_argument('--enable_edge_contraction', '-g', action="store_true",
                    dest = 'edge_contraction_enabled',
                    help = 'enable edge contratction optimization, works only with cache enabled')

    parser.add_argument('--use_pyretic', action="store_true",
                    dest = 'use_pyretic',
                    help = 'Use the pyretic compiler (uses netkat by default)')

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
        if ('enabled' in arg or arg == 'switch_cnt') and d[arg]:
            params.append(arg)

    return params

if __name__ == '__main__':
    args = parse_args()
    print get_optimization_flags(args)

    eval_comp = eval_compilation(args, get_testwise_params(args))
    #eval_comp.compile()
    
    
    if args.added_query:
        for aq in args.added_query:
            #aparams = get_added_query_params(args)
            aparams = {'test': aq}
            print aparams 
            t_s = time.time()
            eval_comp.add(False, **aparams)
            print time.time() - t_s
    

