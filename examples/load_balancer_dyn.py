
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

###############################################################################################################################
# TO TEST EXAMPLE                                                                                                             #
# -------------------------------------------------------------------                                                         #
# start mininet:  ./pyretic/mininet.sh --switch ovsk --topo bump_clique,1,5,3                                                 #
# run controller: pox.py --no-cli pyretic/examples/static_load_balancer.py --clients=5 --servers=3                            #
# test:           hX ping -c 1 10.0.0.100 will work from each host                                                            #
#                 all nodes will be able to ping each other, except hosts to their load-balanced instance                     #
#                 pingall will output                                                                                         #
#                 h1 -> h2 h3 h4 h5 X hs2 hs3                                                                                 #
#                 h2 -> h1 h3 h4 h5 hs1 X hs3                                                                                 #
#                 h3 -> h1 h2 h4 h5 hs1 hs2 X                                                                                 #
#                 h4 -> h1 h2 h3 h5 X hs2 hs3                                                                                 #
#                 h5 -> h1 h2 h3 h4 hs1 X hs3                                                                                 #
#                 hs1 -> h1 h2 h3 h4 h5 hs2 hs3                                                                               #
#                 hs2 -> h1 h2 h3 h4 h5 hs1 hs3                                                                               #
#                 hs3 -> h1 h2 h3 h4 h5 hs1 hs2                                                                               #
###############################################################################################################################


import math
from frenetic.lib import *
from examples.renamer import renamer
from examples.learning_switch_dyn import learning_switch

def static_load_balancer(service_ip,static_matching):

    pol = passthrough

    for client_ip,instance_ip in static_matching:
        pol >>= renamer(client_ip,instance_ip,service_ip)
    
    return pol


def static_matching(client_ips,instance_ips):
    extension_factor = int(math.ceil(float(len(client_ips))/len(instance_ips)))
    repeating_instance_ips = []
    for i in range(0,extension_factor):
        repeating_instance_ips += instance_ips
    return zip(client_ips,repeating_instance_ips)


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

    policy = static_load_balancer(service_ip,lb_matching) >> learning_switch(network)
    network.install_policy(policy)


main = example
