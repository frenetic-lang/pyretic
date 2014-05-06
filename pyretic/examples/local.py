################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
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

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import *

def main():
    def f_limitFilter(context, pkt):
        try:
            done = context['done']
            seen = context['seen']
            group_by = context['group_by']
            limit = context['limit']
        except KeyError:
            print "Context isn't set up correctly!"
            raise TypeError

        if group_by:
            pred = match([(field,pkt[field]) for field in group_by])
        else:              # OTHERWISE, MATCH ON ALL AVAILABLE GROUP_BY
            pred = match([(field,pkt[field]) 
                              for field in pkt.available_group_by()])
        try:
            seen[pred] += 1
        except KeyError:
            seen[pred] = 1

        if seen[pred] == limit:
            val = {h : pkt[h] for h in group_by}
            done.append(match(val))
            policy = ~union(done)
            return (policy, context)

    def callback(update_policy):
        def actual_callback(pkt):
            update_policy(pkt)
            print "I just updated the policy using:"
            print pkt
        return actual_callback

    init_context = { 'done' : [],
                     'seen' : {},
                     'group_by' : ['srcip'],
                     'limit' : 1 }
    init_policy = identity

    a = LocalDynamicPolicy(f_limitFilter,
                    init_context,
                    init_policy,
                    True,
                    "my_test")
    b = FwdBucket()
    b.register_callback(callback(a.update_policy))

    return (a >> b) + mac_learner()
