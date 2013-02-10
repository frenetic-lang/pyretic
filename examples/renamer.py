
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

##############################################################################################################################
# TO TEST EXAMPLE                                                                                                            #
# -------------------------------------------------------------------                                                        #
# start mininet:  pyretic/mininet.sh --switch ovsk --bump_topo,1,1,1                                                         #
# run controller: pox.py --no-cli pyretic/examples/renamer.py                                                                #
# test:           h1 ping -c 1 10.0.0.100 (should work), h1 ping -c 1 hs2 (should not work)                                  #
##############################################################################################################################

from frenetic.lib import *

def renamer(client_ip, instance_ip, service_ip):
    service_to_client_pred = match(srcip=instance_ip, dstip=client_ip)
    service_to_client_mod = modify(srcip=service_ip)

    client_to_service_pred = match(srcip=client_ip, dstip=service_ip) 
    client_to_service_mod = modify(dstip=instance_ip)
  
    pol = passthrough
    pol -= service_to_client_pred | client_to_service_pred
    pol |= service_to_client_pred[service_to_client_mod] | client_to_service_pred[client_to_service_mod]
    return pol

# RENAMES PACKETS TO/FROM 10.0.0.2/10.0.0.100 
def main(service_ip='10.0.0.100', client_ip='10.0.0.1', instance_ip='10.0.0.2'):
    from examples.hub import hub
    return renamer(client_ip, instance_ip, service_ip) >> hub
