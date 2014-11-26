import sys
sys.path.append('/home/mininet/pyretic')
import os
import shutil

from pyretic.core.language import *
from pyretic.lib.corelib import *
from pyretic.lib.path import *

from pyretic.evaluations import stat
from pyretic.evaluations import eval_path

import argparse

class eval_compilation:

    def __init__(self, results_folder, **kwargs):
        self.main_policy = eval_path.main(**kwargs)
        self.path_policy = eval_path.path_main(**kwargs)
        self.params = kwargs
        self.results_folder = results_folder


        if os.path.exists(self.results_folder):
            for fname in os.listdir(self.results_folder):
                fpath = os.path.join(self.results_folder, fname)
                if os.path.isfile(fpath):
                    os.unlink(fpath)
                elif os.path.isdir(fpath):
                    shutil.rmtree(fpath)

    def compile(self, full_compile = False):
        stat.start(self.results_folder)

        pathcomp.init(1022)
        (self.path_in_tagging, self.path_in_capture, self.path_out_tagging, self.path_out_capture) = pathcomp.compile(self.path_policy)

        in_tag_policy = self.path_in_tagging >> self.main_policy
        self.forwarding = (in_tag_policy >> self.path_out_tagging)
        in_capture  = self.path_in_capture
        self.out_capture = (in_tag_policy >> self.path_out_capture)
        
        # forwarding
        self.forwarding_compile()
        self.tagging_compile()
        self.out_tagging_compile()
        self.tag_fwd_compile()

        # capture
        self.capture_compile()
        self.out_capture_compile()
        self.full_out_capture_compile()
        
        
        if full_compile:
            self.virtual_tag = virtual_field_tagging()
            self.virtual_untag = virtual_field_untagging()

            # virtual tags
            self.vf_tag_compile()
            self.vf_untag_compile()
            
            self.vtag_forwarding = (self.virtual_tag >> self.forwarding >> self.virtual_untag)
            self.vtag_in_capture = (self.virtual_tag >> in_capture)
            self.vtag_out_capture = (self.virtual_tag >> out_capture)

            self.vtag_fw_compile()
            self.vtag_in_capture_compile()
            self.vtag_out_capture_compile()

            self.policy = self.vtag_forwarding + self.vtag_in_capture + self.vtag_out_capture
            self.whole_policy_compile()


        stat.stop()



    def get_vf_tagging_policy():
        return None


    def get_vf_untagging_policy():
        return None



    @stat.classifier_size
    @stat.elapsed_time
    def forwarding_compile(self):
        return self.main_policy.compile()
     
    @stat.classifier_size
    @stat.elapsed_time
    def tagging_compile(self):
        return self.path_in_tagging.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def out_tagging_compile(self):
        return self.path_out_tagging.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def capture_compile(self):
        return self.path_in_capture.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def out_capture_compile(self):
        return self.path_out_capture.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def full_out_capture_compile(self):
        return self.out_capture.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def tag_fwd_compile(self):
        return self.forwarding.compile()


    @stat.classifier_size
    @stat.elapsed_time
    def vf_tag_compile(self):
        return self.virtual_tag.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def vf_untag_compile(self):
        return self.virtual_untag.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def vtag_fw_compile(self):
        return self.vtag_forwarding.compile()


    @stat.classifier_size
    @stat.elapsed_time
    def vtag_in_capture_compile(self):
        return self.vtag_in_capture.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def vtag_out_capture_compile(self):
        return self.vtag_out_capture.compile()



    @stat.classifier_size
    @stat.elapsed_time
    def whole_compile(self):
        return self.policy.compile()


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluates compilation of path query toghether with the forwarding policy")
    parser.add_argument("-t", "--test", required=True
                        , help="Test case to run")
    parser.add_argument("-r", "--results_folder",
                        default="./results/",
                        help="Folder to put the raw results data into")

    parser.add_argument("-polargs", "--policy_args", nargs='+')

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


if __name__ == '__main__':
    args = parse_args()
    eval_comp = eval_compilation(args.results_folder, **get_testwise_params(args))
    eval_comp.compile()
