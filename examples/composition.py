
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
# start mininet:  ./pyretic/mininet.sh --switch ovsk --topo bump_clique,1,3,2                                                #
# run controller: pox.py --no-cli pyretic/examples/composition.py --clients=3 --servers=2                                    #
# test:           clients can only ping 10.0.0.100, servers cannot ping anyone                                               #
##############################################################################################################################

from frenetic.lib import *
from examples.learning_switch import learning_switch
from examples.firewall import static_fw, fw
from examples.load_balancer import static_lb, lb
from virttopos.bfs import BFS

def fw_lb_ls(clients, servers):
    num_clients = int(clients)
    num_servers = int(servers)

    print "clients %d" % num_clients
    print "servers %d" % num_servers

    # CALCULATE IPS
    ip_prefix = '10.0.0.'
    public_ip = ip_prefix + str(100)
    print "public_ip = %s" % public_ip
    
    client_ips = [ip_prefix + str(i) for i in range(1, 1+num_clients)]
    H = {c : 0 for c in client_ips}
    R = [ip_prefix + str(i) for i in range(1+num_clients, 1+num_clients+num_servers)]
    allowed = {(c,public_ip) for c in client_ips}
    from_client = union([match(srcip=c) for c in client_ips])

    alb = static_lb(public_ip,R,H)  
    #alb = dynamic(lb)(public_ip,R,H)  
    #afw = static_fw(allowed)
    afw = dynamic(fw)(allowed)
    return if_(from_client, afw >> alb, alb >> afw) >> learning_switch()

        
def main(clients,servers):
    return fw_lb_ls(clients,servers) 

## RUNNING ON ABSTRACTED NETWORK AS IN PAPER
#    return virtualize(fw_lb_ls(clients,servers), BFS())  ## VIRTUALIZED!
# CAN ALSO BE DONE BY RUNNING FROM COMMANDLINE
# pox.py --no-cli pyretic/examples/virtualize.py --program=pyretic/examples/composition.py --clients=3 --servers=2 --virttopo=pyretic/virttopos/bfs.py



