################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
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
from pyretic.lib.hsa import *
from pyretic.core.runtime import virtual_field
from pyretic.core.language import _modify
import copy

#### Common virtual tagging and untagging policy constructions ####
def sample_vtagging(sw_ports, network_links):
    """ Temporary helper equivalent of virtual_untagging() policy. """
    edge_net = get_hsa_edge_policy(sw_ports, network_links)
    return ((edge_net >> modify(test_tag=None)) + ~edge_net)

def sample_vuntagging(sw_ports, network_links):
    """ Temporary helper equivalent of virtual_untagging() policy. """
    edge_net = get_hsa_edge_policy(sw_ports, network_links)
    return ((edge_net >> _modify(vlan_id=0, vlan_pcp=0)) + ~edge_net)

''' Temporary helper to get network switches and ports. '''
def get_test_switch_port_ids():
    return {k: v for (k,v) in
            [(1, [1,2]), (2, [1,2,3]), (3, [1,2])]}

def get_test_network_links():
    '''Temporary helper to get network links.

    Return a list where the format of each entry is (switch_i, switch_j, {i:
    port_on_i, j: port_on_j}) for each link in the network.
    '''
    return [(1, 2, {1:1, 2:1}),
            (2, 3, {2:2, 3:1})]

### path_test_0 ###
def sample_in_table_policy_0():
    """ Temporary in_table policy corresponding to path_test_0 in
    examples/path_query.py. """
    return ((~match(switch=2) >> ~match(test_tag=2) >>
             modify(test_tag=2)) +
            (match(test_tag=2)) +
            (match(switch=2, test_tag=None) >> modify(test_tag=1)) +
            (match(switch=2, test_tag=1) >> modify(test_tag=2)) +
            (match(switch=2, test_tag=3) >> modify(test_tag=2)))

def sample_out_table_policy_0():
    """ Temporary out_table policy corresponding to path_test_0 in
    examples/path_query.py. """
    return ((match(test_tag=2)) +
            (match(test_tag=None) >> modify(test_tag=2)) +
            (match(test_tag=1) >> modify(test_tag=3)) +
            (match(test_tag=3) >> modify(test_tag=2)))

def sample_outmatches_0():
    """ Temporary list of outmatches which must be covered in the HSA
    listing, corresponding to path_test_0 in examples/path_query.py. """
    return [match(test_tag=3)]

### path test 5.1  ###
def sample_in_table_policy_5():
    return ((match(test_tag=2)) +
            (match(switch=1,test_tag=6) >> modify(test_tag=7)) +
            (match(test_tag=6) >> ~match(switch=1) >> modify(test_tag=4)) +
            (match(switch=1,test_tag=9) >> modify(test_tag=7)) +
            (match(test_tag=9) >> ~match(switch=1) >> modify(test_tag=2)) +
            (match(test_tag=5) >> modify(test_tag=2)) +
            (match(test_tag=1) >> modify(test_tag=2)) +
            (match(test_tag=3) >> modify(test_tag=4)) +
            (match(switch=1,test_tag=None) >> modify(test_tag=1)) +
            (match(test_tag=None) >> ~match(switch=1) >> modify(test_tag=8)) +
            (match(test_tag=7) >> modify(test_tag=2)) +
            (match(test_tag=8) >> modify(test_tag=2)) +
            (match(test_tag=4) >> modify(test_tag=2)))

def sample_out_table_policy_5():
    return ((match(test_tag=2)) +
            (match(test_tag=6) >> modify(test_tag=2)) +
            (match(test_tag=9) >> modify(test_tag=2)) +
            (match(test_tag=5) >> modify(test_tag=2)) +
            (match(switch=2,test_tag=1) >> modify(test_tag=6)) +
            (match(test_tag=1) >> ~match(switch=2) >> modify(test_tag=3)) +
            (match(test_tag=3) >> modify(test_tag=2)) +
            (match(test_tag=None) >> modify(test_tag=2)) +
            (match(test_tag=7) >> modify(test_tag=5)) +
            (match(switch=2,test_tag=8) >> modify(test_tag=9)) +
            (match(test_tag=8) >> ~match(switch=2) >> modify(test_tag=2)) +
            (match(switch=2,test_tag=4) >> modify(test_tag=5)) +
            (match(test_tag=4) >> ~match(switch=2) >> modify(test_tag=2)))

def sample_outmatches_5():
    return [match(test_tag=5)]

### Chain,3,3 forwarding policy ###
def static_fwding_chain_3_3():
    ip1 = IPAddr('10.0.0.1')
    ip2 = IPAddr('10.0.0.2')
    ip3 = IPAddr('10.0.0.3')
    ip4 = IPAddr('10.0.0.4')
    return (
        (match(dstip=ip1) >> ((match(switch=1) >> fwd(2)) +
                              (match(switch=2) >> modify(dstport=79)
                               >> fwd(1)) +
                              (match(switch=3) >> fwd(1)))) +
        (match(dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(3)) +
                              (match(switch=3) >> fwd(1)))) +
        (match(dstip=ip3) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(2))))# +
        #(~match(srcmac='00:00:00:00:00:01')) +
        #(match(ethtype=IP_TYPE))
    )

### Other generic testing functions ###
def test_match_from_single_elem(hsf, jsonhs):
    print_hs(hsf, jsonhs)

def test_reachability_inport_outheader(hsf, portids, sw_ports):
    def test_single_reachability(insw, inport, outmatch, testnum):
        res = reachability_inport_outheader(hsf, portids, sw_ports, insw,
                                            inport, outmatch)
        hslines = extract_inversion_results()
        print "test %d:" % testnum
        print '(s%d, port %d) --> %s' % (insw, inport, str(outmatch))
        # print hslines
        # test_match_from_single_elem(hsf, hslines)
        print '--->', get_filter_hs(hsf, hslines)
        return testnum + 1
    testnum = 0
    testnum = test_single_reachability(3, 2, match(switch=1,port=2), testnum)
    testnum = test_single_reachability(3, 2, match(switch=1, port=2,
                                                   dstip=IPAddr('10.0.0.2')),
                                       testnum)
    testnum = test_single_reachability(2, 3, match(switch=1, port=2,
                                                   srcip=IPAddr('10.0.0.2')),
                                       testnum)
    testnum = test_single_reachability(3, 2, match(switch=2,port=1,dstport=79),
                                       testnum)
    testnum = test_single_reachability(1, 2, match(switch=2,port=1,dstport=79),
                                       testnum)

def basic_test():
    hs_format = pyr_hs_format()
    sw_ports = get_test_switch_port_ids()
    net_links = get_test_network_links()
    pol = static_fwding_chain_3_3()
    setup_tfs_data_from_policy(hs_format, pol, sw_ports, net_links)
    portids = get_portid_map(sw_ports)

    # basic reachability tests with known samples
    test_reachability_inport_outheader(hs_format, portids, sw_ports)

    # Test single-shot `reachable inheaders` function
    print '****'
    print '(s%d, p%d) ---> %s' % (1, 2, str(match(switch=2,port=2,dstport=79)))
    print get_reachable_inheaders(hs_format, portids, sw_ports, 1, 2,
                                  match(switch=2,port=2,dstport=79))

    print '****'
    print '(s%d, p%d) ---> %s' % (2, 3, str(match(dstport=79)))
    print get_reachable_inheaders(hs_format, portids, sw_ports, 2, 3,
                                  match(dstport=79))

def hsa_path_test(testnum, in_table_pol, out_table_pol, outmatches_list):
    """ Generic template for path query tests on the chain,3,3 topology """
    print "Path test %s" % str(testnum)
    hs_format = pyr_hs_format()
    sw_ports = get_test_switch_port_ids()
    net_links = get_test_network_links()
    pol = (sample_vtagging(sw_ports, net_links) >>
           in_table_pol >>
           static_fwding_chain_3_3() >>
           out_table_pol)
    setup_tfs_data_from_policy(hs_format, pol, sw_ports, net_links)
    portids = get_portid_map(sw_ports)

    edge_ports = get_hsa_edge_ports(sw_ports, net_links)
    for (sw,ports) in edge_ports.iteritems():
        for p in ports:
            for outm in outmatches_list:
                print '*****'
                print "Testing reachability from sw %d p %d to %s" % (
                    sw,p,str(outm))
                print get_reachable_inheaders(hs_format, portids, sw_ports, sw,
                                              p, outm, no_vlan=True)

def hsa_path_test_0():
    hsa_path_test(0, sample_in_table_policy_0(),
                  sample_out_table_policy_0(),
                  sample_outmatches_0())

def hsa_path_test_5():
    hsa_path_test('5.1', sample_in_table_policy_5(),
                  sample_out_table_policy_5(),
                  sample_outmatches_5())

if __name__ == "__main__":
    logging.basicConfig()
    basic_test()
    virtual_field(name="test_tag", values=range(0, 10), type="integer")
    hsa_path_test_0()
    hsa_path_test_5()
