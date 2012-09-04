
################################################################################
# The Frenetic Project                                                         #
# frenetic@frenetic-lang.org                                                   #
################################################################################
# Licensed to the Frenetic Project by one or more contributors. See the        #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Frenetic Project licenses this        #
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

from frenetic.generators import Event
from frenetic.netcore_helpers import *

class PolicyHandle(object):
    def __init__(self):
        self.policy = drop

    def install(self, pol):
        self.policy = pol

class Network(object):
    """
    - install
    - switch_joins
    - switch_parts
    """

    ph_class = PolicyHandle

    def __init__(self):
        self.switch_joins = Event()
        self.switch_parts = Event()
        
        self._policy_handles = []

        # Start us off with a default policy.
        self.new_policy_handle()
    
    def install(self, policy):
        self._policy_handles[0].update(policy)

    # TODO do this incremental
    def get_combined_policy():
        policy = self._policy_handles[0]
        for ph in self._policy_handles[1:]:
            policy += ph.policy
        return policy
                
    def new_policy_handle():
        ph = self.ph_class()
        self._policy_handles.append(ph)
        return ph
