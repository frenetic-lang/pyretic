
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

################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# input:    --module=PATH_TO_MODULE_OR_EXAMPLE --vdef=PATH_TO_VDEF             #
# mininet:  any topology with which vdef works                                 #
# test:     behavior should match that of module being virtualized             #
#           on topology defined by vdef                                        #
################################################################################


from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.virt import *
 
def virtualize_module(vdef, module, **kwargs):
    vdefns = {}
    modulens = {}
    execfile(vdef, vdefns)
    execfile(module, modulens)

    vn = vdefns["transform"]
    return virtualize(modulens["main"](**kwargs), vn)

    
main = virtualize_module
