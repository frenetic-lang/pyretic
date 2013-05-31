
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


################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet:  mininet.sh --topo clique,4,4 (or other single subnet)              #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *


def act_like_hub():
    """Implement hub-like behavior --- send all packets to all ports on a network
    minimum spanning tree, except for the input port"""
    return flood()  # Return the policy flood

# The @dynamic decorator means that the function below will create a new dynamic
# policy class with the name "act_like_switch"
@dynamic   
def act_like_switch(self):
    """
    Implement switch-like behavior.
    """
    """ # DELETE BOTH THIS LINE AND THE ONE BELOW TO START WORKING ON THE TUTORIAL # 
    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code using Pyretic predicates
    # and policies - all of which are defined and documented in pyretic/core/language.py

    # Set up the initial forwarding behavior for your mac learning switch
    # Tip: set up a separate variable to track this
    self.forward = <some policy here>

    # Set up a query that will receive new incoming packets
    self.query = <a packets query for the first packet w/ a given (srcmac,switch) pair>

    # Set the initial interal policy value (each dynamic policy has a member 'policy'
    # when this member is assigned, the dynamic policy updates itself
    self.policy = <forwarding and query policies composed in parallel>
    # hint: '+' operator on policies is shorthand for parallel composition

    # Write a function to take each new packet p and update the forwarding policy
    # so subsequent incoming packets on this switch whose dstmac matches p's srcmac 
    # (accessed like in a dictionary p['srcmac']), those packets will be forwarded out
    # p's inport (pyretic packets are located, so this value is accessed just like srcmac
    # - i.e., p['inport'])
    def learn_from_a_packet(pkt):
        # perhaps we want to print the incoming packet so we can see it
        print pkt
        # and we will need to set the forwarding policy
        self.forward = <....>  # hint use the 'match' policy 
        # let's print it
        print self.forward
        # and don't forget to update the policy
        ...

    # And don't forget to make sure learn_from_a_packet is called back every time our
    # query sees a new packet
    self.query.register_callback(learn_from_a_packet)
    """ # DELETE BOTH THIS LINE AND THE ONE ABOVE TO START WORKING ON THE TUTORIAL # 


def main():
### Part 0 - hub  ###
    return act_like_hub()

### Part 1 - write a basic mac learning module ###
#    return act_like_switch()

### Part 2 - learn more about composition and debugging tools ###
## first, delete print statements inside act_like_switch - we don't want to have to hack
## every function to figure out what effect it is having

### now try printing packets as they enter and leave act_like_switch()
#    return (pkt_print('BEFORE act_like_switch') >> 
#            act_like_switch() >> 
#            pkt_print('AFTER act_like_switch') )

### here we use 'sequential compostion (>>)' to run one policy on the output of the previous
### the 'passthrough' policy takes a packet and returns a set containing just that packet
### hence 'passthrough' is the idenity policy for sequential composition
#   return act_like_switch() >> passthrough
#   return passthrough >> act_like_switch()
### likewise the 'drop' policy is the identity for parallel composition
#   return act_like_switch() + drop
#   return drop + act_like_switch()

# next let's set up a debugging breakpoint
#    return breakpoint(match(switch=1),act_like_switch())
