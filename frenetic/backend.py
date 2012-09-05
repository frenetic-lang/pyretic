
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
from frenetic import netcore as nc


class PolicyHandle(object):
    def __init__(self):
        self.policy = nc.drop

    def install(self, pol):
        self.policy = pol

class Network(object):
    """
    - install
    - switch_joins
    - switch_parts
    """

    ph_class = PolicyHandle
    ev_class = Event

    def __init__(self):
        self.switch_joins = self.ev_class()
        self.switch_parts = self.ev_class()
        
        self._policy_handles = []

        # Start us off with a default policy.
        self.new_policy_handle()
    
    def install(self, policy):
        self._policy_handles[0].install(policy)

    # TODO do this incremental
    def get_combined_policy(self):
        policy = self._policy_handles[0].policy
        for ph in self._policy_handles[1:]:
            policy += ph.policy
        return policy
                
    def new_policy_handle(self):
        ph = self.ph_class()
        self._policy_handles.append(ph)
        return ph
