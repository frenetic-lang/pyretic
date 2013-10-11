
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
from pyretic.lib.query import *

def act_like_hub():
    """Implement hub-like behavior --- send all packets to all ports on a network
    minimum spanning tree, except for the input port"""
    return flood()  # Return the policy flood

# we create a new dynamic policy class with the name "act_like_switch"
class act_like_switch(DynamicPolicy):
    """
    Implement switch-like behavior.
    """
    """ # DELETE BOTH THIS LINE AND THE ONE BELOW TO START WORKING ON THE TUTORIAL # 
    # Here's some psuedocode to start you off implementing a learning
    # switch.  You'll need to rewrite it as real Python code using Pyretic predicates
    # and policies - all of which are defined and documented in pyretic/core/language.py

    def __init__(self):
        # Set up the initial forwarding behavior for your mac learning switch
        # Tip: set up a separate variable to track this
        self.forward = <some policy here>
        # hint, mac learning switches start off by flooding all packets

        # Set up a query that will receive new incoming packets
        self.query = <a packets query for the first packet w/ a given (srcmac,switch) pair>

        # Write a function to take each new packet p and update the forwarding policy
        # so subsequent incoming packets on this switch whose dstmac matches p's srcmac 
        # (accessed like in a dictionary p['srcmac']), those packets will be forwarded out
        # p's inport (pyretic packets are located, so we access this value just like srcmac
        # - i.e., p['inport'])
        def learn_from_a_packet(pkt):
            # perhaps we want to print the incoming packet so we can see it
            print pkt
            # and we will need to set the forwarding policy
            self.forward =  <....>  # hint use the 'match' policy and either 
                                    # if_(f,p1,p2) or
                                    # a combination of parallel and sequential composition

            # let's print the forwarding policy to see if it looks right
            print self.forward
            # and don't forget to update the dynamic policy to forward and query
            # (each dynamic policy has a member 'policy'
            # whenever this member is assigned, the dynamic policy updates itself)
            self.policy = <forwarding and query policies composed in parallel>
            # hint: 'P1 + P2'  is shorthand for parallel composition of P1 and P2
            #       'P1 >> P2' is shorthand for sequential composition of P1 and P2

        # we need to make sure learn_from_a_packet is called back 
        # every time our query sees a new packet
        self.query.register_callback(learn_from_a_packet)

        # finally, we initialize our dynamic policy 
        super(act_like_switch,self).__init__(<the first value 'self.policy' should take>)
    """ # DELETE BOTH THIS LINE AND THE ONE ABOVE TO START WORKING ON THE TUTORIAL # 


def main():
    ## The main method returns the policy that will be run  
    ## To try your code, comment the first return line and uncomment the second

    ### Part 0 - hub  ###
    return act_like_hub()

    ### Part 1 - write a basic mac learning module ###
#   return act_like_switch()

