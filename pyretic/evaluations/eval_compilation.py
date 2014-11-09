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

        self.forwarding_compile()
        pathcomp.init_tag_field(1022)
        (self.tagging, self.capture) = pathcomp.compile(self.path_policy)
        stat.compare_policies(self.tagging)
        self.tagging_compile()
        self.capture_compile()

        self.policy = (self.tagging >> self.main_policy) + self.capture

        self.tag_fw_cap_compile()

        if full_compile:
            self.vf_tag_pol = self.get_vf_tagging_policy()
            self.vf_untag_pol = self.get_vf_untagging_policy()

            self.vf_tag_compile()
            self.vf_untag_compile()

            self.policy = self.vf_tag_pol >> self.policy >> self.vf_untag_pol

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
        if self.tagging:
            c = self.tagging.compile()
            print c
            return c
        return None

    @stat.classifier_size
    @stat.elapsed_time
    def capture_compile(self):
        if self.capture:
            return self.capture.compile()
        return None

    @stat.classifier_size
    @stat.elapsed_time
    def vf_tag_compile(self):
        if self.vf_tag_pol:
            return self.vf_tag_pol.compile()
        return None

    @stat.classifier_size
    @stat.elapsed_time
    def vf_untag_compile(self):
        if self.vf_untag_pol:
            return self.vf_untag_pol.compile()
        return None

    @stat.classifier_size
    @stat.elapsed_time
    def tag_fw_cap_compile(self):
        return self.policy.compile()

    @stat.classifier_size
    @stat.elapsed_time
    def whole_policy_compile(self):
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
