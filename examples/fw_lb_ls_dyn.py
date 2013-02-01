
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
# run controller: pox.py --no-cli pyretic/examples/firewall_dyn.py                                                           #
# test:           clients can only ping 10.0.0.100, servers can only ping clients they serve                                 #
##############################################################################################################################

from frenetic.lib import *
from examples.learning_switch_dyn import learning_switch
from examples.firewall_dyn import simple_ingress_firewall
from examples.load_balancer_dyn import static_matching, static_load_balancer

def example(network, clients, servers):
    num_clients = int(clients)
    num_servers = int(servers)
    print "clients %d" % num_clients
    print "servers %d" % num_servers

    # CALCULATE IPS
    ip_prefix = '10.0.0.'
    service_ip = ip_prefix + str(100)
    print "service_ip = %s" % service_ip
    client_ips = [ip_prefix + str(i) for i in range(1,1+num_clients)]
    instance_ips = [ip_prefix + str(i) for i in range(1+num_clients,1+num_clients+num_servers)]

    lb_matching = static_matching(client_ips,instance_ips)
    print "static_matching = %s" % lb_matching

    allowed = set([])
    for client_ip in client_ips:
        allowed.add((client_ip,service_ip))

    from_client = None
    for client_ip in client_ips:
        try:    from_client |= match(srcip=client_ip)
        except: from_client  = match(srcip=client_ip)
        
    policy = ((simple_ingress_firewall(allowed,network) >> static_load_balancer(service_ip,lb_matching)) & from_client | \
        (static_load_balancer(service_ip,lb_matching) >> simple_ingress_firewall(allowed,network)) - from_client) \
        >> learning_switch(network)

    network.install_policy(policy)

        
main = example
