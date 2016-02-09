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

from pyretic.core.language import *
from pyretic.core.language import _modify
from pyretic.vendor.hsa.utils.wildcard import (wildcard_create_bit_repeat,
                                               wildcard_to_str,
                                               wildcard_create_from_string)
from pyretic.vendor.hsa.utils.wildcard_utils import set_header_field
from ipaddr import IPv4Network
from pyretic.vendor.hsa.headerspace.tf import TF
from pyretic.core.network import IPAddr, IPPrefix, MAC
import copy, logging
import subprocess, shlex
import json

HSL_C_FOLDER = '/home/mininet/pyretic/pyretic/lib/hassel-c'
TFS_FOLDER = '%s/tfs/pyretic' % HSL_C_FOLDER
INVERTED_OUTFILE = "%s/data/out-inverted.json" % HSL_C_FOLDER
GEN_BINARY = "%s/gen" % HSL_C_FOLDER
PYRETIC_BINARY = "%s/pyretic" % HSL_C_FOLDER
SWITCH_MULTIPLIER = 100000

def pyr_hs_format():
    '''A header-space format which defines all the packet header fields used in
    pyretic.

    Possible future TODO item. If pyretic uses additional header fields in the
    future, those should be added in here too.
    '''
    format = {}
    format["srcmac_pos"] = 0
    format["dstmac_pos"] = 6
    format["srcip_pos"] = 12
    format["dstip_pos"] = 16
    format["tos_pos"] = 20
    format["srcport_pos"] = 21
    format["dstport_pos"] = 23
    format["ethtype_pos"] = 25
    format["protocol_pos"] = 27
    format["vlan_id_pos"] = 28 # allocate full 2 bytes for 12 bits
    format["vlan_pcp_pos"] = 30 # allocate full byte for 3 bits

    format["srcmac_len"] = 6
    format["dstmac_len"] = 6
    format["srcip_len"] = 4
    format["dstip_len"] = 4
    format["tos_len"] = 1
    format["srcport_len"] = 2
    format["dstport_len"] = 2
    format["ethtype_len"] = 2
    format["protocol_len"] = 1
    format["vlan_id_len"] = 2 # allocate full 2 bytes for 12 bits
    format["vlan_pcp_len"] = 1 # allocate full byte for 3 bits

    format["length"] = 31 # 31 byte header overall
    return format

#### Generating a transfer function from a policy ####

def set_field_val(hsf, wc_obj, field, val, process_field=True):
    """ Set a specific field in a wildcard using pyretic fields. """
    def ip2int(ip):
        assert isinstance(ip, IPv4Network)
        numeric_ip = 0
        for p in str(ip.ip).split('.'):
            numeric_ip = (numeric_ip << 8) + int(p)
        return numeric_ip

    def mac2int(mac):
        assert isinstance(mac, str)
        numeric_mac = 0
        for p in mac.split(':'):
            numeric_mac = (numeric_mac << 8) + int(p, 16)
        return numeric_mac

    if field in ['srcmac', 'dstmac']:
        int_val = mac2int(val) if process_field else val
        set_header_field(hsf, wc_obj, field, int_val, 0)
    elif field in ['srcip', 'dstip']:
        int_val = ip2int(val) if process_field else val
        right_pfx = (32 - val.prefixlen) if process_field else 0
        set_header_field(hsf, wc_obj, field, int_val, right_pfx)
    elif field in ['vlan_offset', 'vlan_nbits', 'vlan_total_stages']:
        ''' ignore tagging helper fields. For now, we ensure that these fields
        are irrelevant by sending in a single-stage policy. '''
        pass
    elif not field in ['switch', 'port']:
        assert "%s_pos" % field in hsf
        assert "%s_len" % field in hsf
        set_header_field(hsf, wc_obj, field, val, 0)
    else:
        ''' do nothing '''
        pass
    return wc_obj

def get_match_wc(hsf, mat_map):
    """ Generate a wildcard from a pyretic match dictionary. """
    mat = wildcard_create_bit_repeat(hsf["length"], 3)
    for (field, val) in mat_map.iteritems():
        set_field_val(hsf, mat, field, val)
    return mat

def get_ports(hsf, portids, sw_ports, mat_map, sw):
    ''' Return network-wide unique identifiers from match information in
    classifiers. '''
    inports = []
    if 'switch' in mat_map:
        assert sw == mat_map['switch']
        if 'port' in mat_map:
            inports.append(portids[(sw, mat_map['port'])])
        else:
            for p in sw_ports[sw]:
                inports.append(portids[(sw,p)])
    else:
        if 'port' in mat_map:
            p = mat_map['port']
            if p in sw_ports[sw]:
                inports.append(portids[(sw,p)])
        else:
            inports = [portids[(sw,x)] for x in sw_ports[sw]]
    return inports

def convert_classifier(classifier, hsf, portids, sw_ports):
    """Function to convert a classifier `classifier` into a header space given by a
    header space format dictionary `hsf`.
    """
    hsalib_log = logging.getLogger('%s.convert_classifier' % __name__)

    def get_action_wc(acts):
        """Return a rewrite mask, rewrite HS, and the list of outports from the
        action list `acts` provided. For interpretation of these fields check
        the doctext of hsa.headerspace.tf create_standard_rule.

        In this function, we assume that the actions correspond to the actions
        of a single-stage table classifier, in addition to other
        restrictions. Specifically:
        - all non-`modify` actions are ignored
        - actions that do not set an output port are ignored
        - if there are multiple actions satisfying the above conditions, they
        may only simply output the packet via a port. i.e., No packet
        modifications. This is an artificial restriction because
        tf.create_standard_rule can only take a single rewrite wildcard for
        packet modification.
        """
        new_acts = filter(lambda x: isinstance(x, modify) and 'port' in x.map,
                          acts)
        outports = []
        '''The current transfer function rule implementation can only take one new
        header space in rewrite rules if there are multiple outports
        involved. If there is only one action, multiple field rewrites are
        possible. A port must be set for rewrites to be active.
        '''
        if len(new_acts) > 1:
            hsa_compilable = reduce(lambda acc, a: acc and
                                    a.map.keys() == ['port'],
                                    new_acts, True)
            outports = map(lambda x: x.map['port'], new_acts)
            if hsa_compilable:
                return (None, None, outports, False)
            else:
                raise RuntimeError("actions not HSA-compilable! %s" % acts)
        elif len(new_acts) == 1:
            mod_dict = copy.copy(new_acts[0].map)
            if 'port' in mod_dict:
                outports = [mod_dict['port']]
                del mod_dict['port']
            else:
                return (None, None, [], False)
            if len(mod_dict.keys()) > 0:
                ''' There are rewritten packet header fields. '''
                rw_rule = True
                mask = wildcard_create_bit_repeat(hsf["length"], 0x2)
                rewrite = wildcard_create_bit_repeat(hsf["length"], 0x1)
                for (field, val) in mod_dict.iteritems():
                    set_field_val(hsf, mask, field, 0, process_field=False)
                    set_field_val(hsf, rewrite, field, val)
                return (mask, rewrite, outports, True)
            else:
                return (None, None, outports, False)
        else:
            ''' No modify actions '''
            return (None, None, [], False)

    def process_outports(mat_map, acts_ports, sw, rule):
        ''' Return network-wide unique port identifiers from the port values
        present in classifier actions. '''
        def warn_nonexistent_port(p):
            print sw_ports
            hsalib_log.warn("Non-existent port specified: "
                            "(sw %d, p %d) in %s" % (
                                sw, p, str(rule)))
        out_ports = []
        for p in acts_ports:
            if p in sw_ports[sw]:
                out_ports.append(portids[(sw,p)])
            elif p == OFPP_IN_PORT:
                if 'port' in mat_map:
                    out_ports.append(portids[(sw,mat_map['port'])])
                else:
                    warn_nonexistent_port(p)
            else:
                warn_nonexistent_port(p)
        return out_ports

    def init_tfs():
        """ Initialize one transfer function per device. """
        tfs_map = {}
        for sw in sw_ports.keys():
            tfs_map[sw] = TF(hsf["length"])
            tfs_map[sw].set_prefix_id("s%d" % sw)
            tfs_map[sw].set_send_on_receiving_port(True)
        return tfs_map

    def save_tfs(tfs_map):
        """ Save a dictionary of transfer functions to various files. """
        global TFS_FOLDER
        for (sw, tf) in tfs_map.iteritems():
            tf.save_object_to_file('%s/s%d.tf' % (TFS_FOLDER, sw))

    ''' Classifier conversion core logic begins here. '''
    tfs_map = init_tfs()
    for sw in sw_ports.keys():
        tf = tfs_map[sw]
        for rule in classifier.rules:
            try:
                mat_map = {} if rule.match == identity else rule.match.map
            except:
                raise RuntimeError("unexpected rule match in classifier!")
            # determine first if this rule applicable to switch sw
            if (('switch' in mat_map and mat_map['switch'] == sw) or
                (not 'switch' in mat_map)):
                mat_wc = get_match_wc(hsf, mat_map)
                in_ports = get_ports(hsf, portids, sw_ports, mat_map, sw)
                (mask, rewrite, outports, rw) = get_action_wc(rule.actions)
                out_ports = process_outports(mat_map, outports, sw, rule)
                rule = TF.create_standard_rule(in_ports, mat_wc, out_ports,
                                               mask, rewrite)
                if rw:
                    tf.add_rewrite_rule(rule)
                else:
                    tf.add_fwd_rule(rule)
    save_tfs(tfs_map)

def convert_topology(edges, hsf, portids):
    """ Convert a list of edges representing the topology into a topology
    transfer function. """
    ttf = TF(hsf["length"] * 2)
    for (s1, p1, s2, p2) in edges:
        rule = TF.create_standard_rule([portids[(s1,p1)]], None,
                                       [portids[(s2,p2)]], None, None)
        ttf.add_link_rule(rule)
        rule = TF.create_standard_rule([portids[(s2,p2)]], None,
                                       [portids[(s1,p1)]], None, None)
        ttf.add_link_rule(rule)
    global TFS_FOLDER
    ttf.save_object_to_file("%s/topology.tf" % TFS_FOLDER)

def get_portid_map(sw_ports):
    portid_map = {}
    for (sw, ports) in sw_ports.iteritems():
        for port in ports:
            portid_map[(sw, port)] = (sw * SWITCH_MULTIPLIER) + port
    return portid_map

def get_edge_list(edges):
    edge_list = []
    for (s1, s2, ports) in edges:
        edge_list.append((s1, ports[s1], s2, ports[s2]))
    return edge_list

def get_hsa_edge_ports(sw_ports, network_links):
    edge_ports = copy.deepcopy(sw_ports)
    for (s1, s2, linkdict) in network_links:
        for s in [s1, s2]:
            if linkdict[s] in edge_ports[s]:
                edge_ports[s].remove(linkdict[s])
    return edge_ports

def get_hsa_edge_policy(sw_ports, network_links):
    """ Temporary helper to construct an equivalent of the ingress_network() or
    egress_network() Filters from a switch-ports dictionary and a list of
    network links.
    """
    edge_ports = get_hsa_edge_ports(sw_ports, network_links)
    match_pols = []
    for (sw, ports) in edge_ports.iteritems():
        for p in ports:
            match_pols.append(match(switch=sw,port=p))
    return union(match_pols)

def write_port_map(sw_ports, portids):
    f = open('%s/port_map.txt' % TFS_FOLDER, 'w')
    for (sw, ports) in sw_ports.iteritems():
        f.write('$s%d\n' % sw)
        for p in ports:
            f.write('s%d-eth%d:%d\n' % (sw, p, portids[(sw,p)]))
    f.close()

def setup_tfs_data_from_policy(hsf, pol, sw_ports, network_links):
    """ Set up transfer functions and hassel-c data files from a given policy,
    and topology information. """
    # TODO(ngsrinivas): need to investigate this further. Currently, we use
    # pyretic to compile. NetKAT produces an what seems like an unnecessarily
    # huge classifier, which may be a symptom of a buggy end-to-end compilation
    # process.
    c = pol.compile()
    setup_tfs_data_from_cls(hsf, c, sw_ports, network_links)

def setup_tfs_data_from_cls(hsf, c, sw_ports, network_links):
    """ Set up transfer functions and hassel-c data files from a given
    classifier `c`, and topology information. """
    # get a forwarding transfer function
    portids = get_portid_map(sw_ports)
    convert_classifier(c, hsf, portids, sw_ports)

    # get a topology transfer function
    edge_list = get_edge_list(network_links)
    convert_topology(edge_list, hsf, portids)

    # port map, for easy reference
    write_port_map(sw_ports, portids)

    # generate the hassel-c `dat` file
    gen_hassel_datafile()

#### Running header space analysis ####

def gen_hassel_datafile():
    datafile_cmd = "%s pyretic" % GEN_BINARY
    try:
        result =  subprocess.check_output(shlex.split(datafile_cmd),
                                          cwd=HSL_C_FOLDER)
    except subprocess.CalledProcessError as e:
        print "Could not generate pyretic network data file!"
        print e.returncode
        print e.output

def reachability_inport_outheader(hsf, portids, sw_ports, insw, inport,
                                  outmatch, no_vlan=False):
    """Function that runs reachability from a given inport to a given output header
    space, represented by the `match` in outmatch.
    """
    from pyretic.core.language import _match
    in_port = portids[(insw,inport)]
    outmat_map = dict(_match(**outmatch.map).map)
    outmat_wc = get_match_wc(hsf, outmat_map)
    outports = []
    if 'switch' in outmat_map:
        outports_lst = get_ports(hsf, portids, sw_ports, outmat_map,
                                 outmat_map['switch'])
    else:
        outports_lst = reduce(lambda acc, sw: acc +
                              get_ports(hsf, portids, sw_ports, outmat_map, sw),
                              sw_ports.keys(), [])
    outports_str = reduce(lambda acc, x: acc + ' ' + str(x), outports_lst, '')
    inmat_wc = get_match_wc(hsf, {})
    if no_vlan:
        inmat_wc = get_match_wc(hsf, {'vlan_id': 0, 'vlan_pcp': 0})
    ih_str = '-ih %s' % wildcard_to_str(inmat_wc) if no_vlan else ''
    reachability_cmd = "%s %s -oh %s %d %s" % (PYRETIC_BINARY,
                                               ih_str,
                                               wildcard_to_str(outmat_wc),
                                               in_port,
                                               outports_str)
    try:
        result = subprocess.check_output(shlex.split(reachability_cmd),
                                         cwd=HSL_C_FOLDER)
    except subprocess.CalledProcessError as e:
        print "Could not run pyretic reachability on the inputs!"
        print e.returncode
        print e.output
        result = ''
    return result

def get_field_val(hsf, field, wc_str):
    """Get the value of a field if it is not wildcarded or 'z' in the given
    wildcard string.

    :rtype: `None` if value is fully wildcarded or has 'z', or value formatted
    specific to the field if it is set.
    """
    def ensure_no_partial_wildcard(val, desc_str):
        ind = val.find('x')
        if ind == -1:
            return False
        elif ind == 0 and not ('0' in val or '1' in val):
            return True
        else:
            raise RuntimeError("Pyretic doesn't support arbitrary wildcards on "
                               "%s: value %s" % (desc_str, val))

    def ensure_prefix_wildcard(val, desc_str):
        ind = val.find('x')
        if ind != -1:
            ensure_no_partial_wildcard(val[0:ind], desc_str)
            ensure_no_partial_wildcard(val[ind:], desc_str)
            return ind
        else:
            return len(val) + 1

    def convert_mac(field_bytes, field_str):
        ''' Take bytes representing a MAC address and return a MAC value, or
        None if wildcarded.'''
        full_wc = ensure_no_partial_wildcard(field_str, "MAC address")
        if full_wc:
            ''' fully wildcarded. '''
            return None
        else:
            ''' MAC value completely specified. '''
            macdigits = []
            for digitpair in field_bytes:
                first_digit = hex(int(digitpair[0:4],2))[2:]
                second_digit = hex(int(digitpair[4:8],2))[2:]
                macdigits.append(first_digit + second_digit)
            return MAC(':'.join(macdigits))

    def convert_ip(field_bytes, field_str):
        ''' Take bytes representing an IP address and return an IP value, or
        None if completely wildcarded. '''
        ind = ensure_prefix_wildcard(field_str, "IP address")
        if ind == 0:
            ''' fully wildcarded. '''
            return None
        else:
            full_octets = ind / 9
            assert full_octets >= 0 and full_octets <= 4
            dotted_quad = []
            # fully specified octets
            for octet in range(0, full_octets):
                dotted_quad.append(int(field_bytes[octet], 2))
            # partially wildcarded octet
            if full_octets < 4:
                dotted_quad.append(int(field_bytes[octet].replace('x', '0'), 2))
            # fully wildcarded octets
            for octet in range(full_octets+1, 4):
                dotted_quad.append(0)
            prefixlen = ((ind/9) * 8) + (ind % 9)
            ipaddr_dq = '.'.join(map(str, dotted_quad))
            if prefixlen < 32:
                return IPPrefix('%s/%d' % (ipaddr_dq, prefixlen))
            else:
                return IPAddr('%s' % ipaddr_dq)

    def convert_to_integer(field_bytes, field_str):
        ''' Take bytes and convert to integer. '''
        return int(field_str.replace(',',''), 2)

    wc_bytes = wc_str.split(',')[::-1]
    assert '%s_pos' % field in hsf.keys()
    assert '%s_len' % field in hsf.keys()
    field_start = hsf['%s_pos' % field]
    field_len   = hsf['%s_len' % field]
    field_bytes = wc_bytes[field_start:field_start+field_len][::-1]
    field_str = ','.join(field_bytes)
    assert not 'z' in field_str # we don't support "null" matches.
    ''' Process field bytes based on the field. '''
    if field in ['srcmac', 'dstmac']:
        return convert_mac(field_bytes, field_str)
    elif field in ['srcip', 'dstip']:
        return convert_ip(field_bytes, field_str)
    else:
        full_wc = ensure_no_partial_wildcard(field_str, field)
        if full_wc:
            return None
        else:
            return convert_to_integer(field_bytes, field_str)

def match_from_single_elem(hsf, wc_str):
    """ Convert a single wildcard string to a pyretic match """
    fields = set(map(lambda x: x[:-4], filter(lambda x: x != "length",
                                              hsf.keys())))
    mat_map = {}
    for field in fields:
        val = get_field_val(hsf, field, wc_str)
        if val:
            mat_map[field] = val
    if mat_map:
        return match(**mat_map)
    else:
        return identity

def print_hs(hsf, hsres, indent=''):
    for hs in hsres:
        print indent, match_from_single_elem(hsf, hs['elem'])
        if 'diff' in hs:
            print indent, '\\'
            print_hs(hsf, hs['diff'], indent+'  ')

def get_filter_hs(hsf, hsres):
    res_filter = drop
    for hs in hsres:
        curr_filter = match_from_single_elem(hsf, hs['elem'])
        if 'diff' in hs:
            diff_filter = get_filter_hs(hsf, hs['diff'])
            curr_filter = curr_filter - diff_filter
        if res_filter == drop:
            res_filter = curr_filter
        else:
            res_filter = res_filter | curr_filter
    return res_filter

def extract_inversion_results():
    f = open(INVERTED_OUTFILE, 'r')
    hslines = []
    for line in f:
        hslines += json.loads(line.strip())
    f.close()
    return hslines

def get_reachable_inheaders(hsf, portids, sw_ports, insw, inport, outmatch,
                            no_vlan=False):
    """ Given a switch and inport to start from, pick out the headers at this
    switch and inport which eventually reach a specified output headerspace.

    :param hsf: a headerspace format.
    :type hsf: dict
    :param portids: port ID mapping from (sw,port) -> port number
    :type portids: dict
    :param sw_ports: mapping from switches to list of port numbers
    :type sw_ports: dict
    :param insw: the input switch from which packets logically enter the network
    :type insw: int
    :param inport: the input port from which packets logically enter the network
    :type inport: int
    :param outmatch: output header space
    :type outmatch: match
    :rtype: Filter
    """
    reachability_inport_outheader(hsf, portids, sw_ports, insw, inport,
                                  outmatch, no_vlan)
    hslines = extract_inversion_results()
    return get_filter_hs(hsf, hslines)
