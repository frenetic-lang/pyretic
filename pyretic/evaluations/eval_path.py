################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
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

################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet: Changes each time. Run evaluation script alongside corresponding    #
# mininet testing script                                                       #
# pyretic: pyretic.py pyretic.evaluations.eval_path -m p0 --test=<test_name>   #
################################################################################


import importlib

test_module_path = "pyretic.evaluations.Tests."
 
def test_setup(**kwargs):
    params = dict(**kwargs)
    test_module = importlib.import_module(test_module_path + params['test'])
    del params['test']
    return (test_module, params)
   
def path_main(**kwargs):
    (module, params) = test_setup(**kwargs)
    p =  module.policy.path_main(**params) 
    return p

def main(**kwargs):
    (module, params) = test_setup(**kwargs)
    p = module.policy.main(**params)
    return p


