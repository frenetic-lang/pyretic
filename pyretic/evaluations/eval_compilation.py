import sys
sys.path.append('/home/mina/pyretic')
sys.path.append('/home/mina/mininet')
import os
import shutil

from pyretic.core.language import *
from pyretic.lib.corelib import *
from pyretic.lib.path import *

from pyretic.evaluations import stat
from pyretic.evaluations import eval_path

import argparse

class eval_compilation:

    def __init__(self, args, kwargs):
        self.max_states = 65000
        self.add_calls = 0

        self.policy = eval_path.main(**kwargs)
        self.path_policy = eval_path.path_main(**kwargs)
        
        #for aq in args.added_query:
        #    self.path_policy += eval_path.path_main(test = aq)
        
        
        self.params = kwargs
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

        if os.path.exists(self.results_folder):
            for fname in os.listdir(self.results_folder):
                fpath = os.path.join(self.results_folder, fname)
                if os.path.isfile(fpath):
                    os.unlink(fpath)
                elif os.path.isdir(fpath):
                    shutil.rmtree(fpath)

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
                self.forwarding_compile()
                self.in_table_compile()
                self.out_table_compile()
                
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


    def compile(self, full_compile = False):

        stat.start(self.results_folder, (self.disjoint_enabled, self.integrate_enabled, self.multitable_enabled, self.ragel_enabled))
        
        pathcomp.init(self.max_states, self.switch_cnt, self.cache_enabled)
         
        policy_fragments = pathcomp.compile(self.path_policy, self.max_states, 
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
                self.forwarding_compile()
                self.in_table_compile()
                self.out_table_compile()
                
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

    def get_vf_tagging_policy(self):
        return None


    def get_vf_untagging_policy(self):
        return None

######################
# Stat Methods 
######################

    ##### general methods ######
    
    @stat.classifier_size
    @stat.elapsed_time
    def forwarding_compile(self):
        return self.policy.compile()
     
    @stat.classifier_size
    @stat.elapsed_time
    def whole_policy_compile(self):
        return self.overall_policy.compile()

    
    ##### tagging methods ######

    @stat.classifier_size
    @stat.elapsed_time
    def tagging_compile(self):
        return self.path_in_tagging.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def out_tagging_compile(self):
        return self.path_out_tagging.compile()

    ##### capture methods ######
    @stat.classifier_size
    @stat.elapsed_time
    def capture_compile(self):
        return self.path_in_capture.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def out_capture_compile(self):
        return self.path_out_capture.compile()

    
    ##### virtual tags methods ######
    @stat.classifier_size
    @stat.elapsed_time
    def vf_tag_compile(self):
        return self.virtual_tag.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def vf_untag_compile(self):
        return self.virtual_untag.compile()


    
    ############## composed methods #################
    
    ### single table ###

    @stat.classifier_size
    @stat.elapsed_time
    def tag_fwd_compile(self):

        ## this is in_tag >> forwarding >> out_tag 
        return self.forwarding.compile()

    
    @stat.classifier_size
    @stat.elapsed_time
    def full_out_capture_compile(self):
        ## this is in_tag_fwd >> path_out_capture
        ## tag_fwd is in_tag >> forwarding which is already compiled
        return self.out_capture.compile()

    
    @stat.classifier_size
    @stat.elapsed_time
    def vtag_fw_compile(self):
        ## this is vtag >> tag_fwd >> vuntag
        return self.vtag_forwarding.compile()


    @stat.classifier_size
    @stat.elapsed_time
    def vtag_in_capture_compile(self):
        ## this is vtag >> in_capture
        return self.vtag_in_capture.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def vtag_out_capture_compile(self):
        ## this is vtag >> out_captre
        return self.vtag_out_capture.compile()

    ### multi table ###
    @stat.classifier_size
    @stat.elapsed_time
    def in_table_compile(self):
        return self.path_in_table.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def out_table_compile(self):
        return self.path_out_table.compile()



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
#### profiling
def profile(args):
    import cProfile as profile

    p = profile.run('pathcomp.compile(p)', sort='tottime')



if __name__ == '__main__':
    args = parse_args()
    print get_optimization_flags(args)
    #p = eval_path.path_main(**get_testwise_params(args))
    #profile(args)
    import time

    eval_comp = eval_compilation(args, get_testwise_params(args))
    t_s = time.time()
    eval_comp.compile()
    print time.time() - t_s
    
    
    if args.added_query:
        for aq in args.added_query:
            #aparams = get_added_query_params(args)
            aparams = {'test': aq}
            print aparams 
            t_s = time.time()
            eval_comp.add(False, **aparams)
            print time.time() - t_s
    

#######################################################
###             Previous Tests                      ###
#######################################################

#### ml_ulex
def get_input(re_list):
    lex_input = ''
    expr_num = 0 
    for r in re_list:
        lex_input += (r.ml_ulex_repr() + ' => ( T.expr_' + str(expr_num) + ' );')
        lex_input += '\n'
        expr_num += 1
    return lex_input

def ml_ulex(args):
    import time
    start = time.time()
    p = eval_path.path_main(**get_testwise_params(args))
    print 'hi'
    re_list = pathcomp.compile(p)
    print time.time() - start
    lex_input = get_input(re_list) 
    f = open('lex_input.txt', 'w')
    f.write(lex_input)
    f.close()
    start = time.time()
    output = subprocess.check_output(["ml-ulex", "--dot", 'lex_input.txt'])
    print time.time() - start

#### profiling
def profile(args):
    import cProfile as profile

    p = profile.run('pathcomp.compile(p)', sort='tottime')


#### ragel
def get_ragel_input(re_list):
    res = '%%{\n\tmachine pyretic;\n'
    for i in range(len(re_list)):
        res += '\taction _%d {}\n' % i
    
    re_list_str = '\tmain := '
    for i,q in re_list:
        re_list_str += '((' + q.re_string_repr() + (') @_%d)|' %i)
    res += re_list_str[:-1] + ';}%%\n%% write data;'
    return res

def ragel(args):
    p = eval_path.path_main(**get_testwise_params(args))
    re_list = pathcomp.compile(p)
    re_list = zip(range(len(re_list)), re_list)
    lex_input = get_ragel_input(re_list) 
    f = open('ragel_lex_input.txt', 'w')
    f.write(lex_input)
    f.close()
    output = subprocess.check_output(["ragel", "-V", 'ragel_lex_input.txt'])
    import pydot
    g = pydot.graph_from_dot_data(output)
    print g.get_node_list()


