from pyretic.core.language import *
from pyretic.vendor.hsa.utils.wildcard import wildcard_create_bit_repeat, wildcard_to_str
from pyretic.vendor.hsa.utils.wildcard_utils import set_header_field
from ipaddr import IPv4Network
from pyretic.vendor.hsa.headerspace.tf import TF
import copy, logging
import subprocess, shlex
import json

HSL_C_FOLDER = '/home/mininet/pyretic/pyretic/lib/hassel-c'
TFS_FOLDER = '%s/tfs/pyretic' % HSL_C_FOLDER
INVERTED_OUTFILE = "%s/out-inverted.json" % HSL_C_FOLDER
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

''' Temporary helper to get network switches and ports. '''
def get_switch_port_ids():
    return {k: v for (k,v) in
            [(1, [1,2]), (2, [1,2,3]), (3, [1,2])]}

def get_network_links():
    '''Temporary helper to get network links.

    Return a list where the format of each entry is (switch_i, switch_j, {i:
    port_on_i, j: port_on_j}) for each link in the network.
    '''
    return [(1, 2, {1:1, 2:1}),
            (2, 3, {2:2, 3:1})]

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
                              (match(switch=3) >> fwd(2)))) +
        (~match(srcmac='00:00:00:00:00:01')) +
        (match(ethtype=IP_TYPE))
    )

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
    elif not field in ['switch', 'port']:
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
        """
        new_acts = filter(lambda x: isinstance(x, modify), acts)
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
        out_ports = []
        for p in acts_ports:
            if p in sw_ports[sw]:
                out_ports.append(portids[(sw,p)])
            else:
                hsalib_log.warn("Non-existent port specified: "
                                "(sw %d, p %d) in %s" % (
                                    sw, p, str(rule)))
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

def write_port_map(sw_ports, portids):
    f = open('%s/port_map.txt' % TFS_FOLDER, 'w')
    for (sw, ports) in sw_ports.iteritems():
        f.write('$s%d\n' % sw)
        for p in ports:
            f.write('s%d-eth%d:%d\n' % (sw, p, portids[(sw,p)]))
    f.close()

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

def reachability_inport_outheader(hsf, portids, sw_ports, insw, inport, outmatch):
    """Function that runs reachability from a given inport to a given output header
    space, represented by the `match` in outmatch.
    """
    from pyretic.core.language import _match
    in_port = portids[(insw,inport)]
    mat_map = dict(_match(**outmatch.map).map)
    mat_wc = get_match_wc(hsf, mat_map)
    outports = []
    if 'switch' in mat_map:
        outports = get_ports(hsf, portids, sw_ports, mat_map, mat_map['switch'])
    else:
        outports = reduce(lambda acc, sw: acc + get_ports(hsf, portids, sw_ports,
                                                         mat_map, sw),
                          sw_ports.keys(), [])
    out_ports = reduce(lambda acc, x: acc + ' ' + str(x), outports, '')
    reachability_cmd = "%s -oh %s %d %s" % (PYRETIC_BINARY,
                                            wildcard_to_str(mat_wc),
                                            in_port,
                                            out_ports)
    try:
        result = subprocess.check_output(shlex.split(reachability_cmd),
                                         cwd=HSL_C_FOLDER)
    except subprocess.CalledProcessError as e:
        print "Could not run pyretic reachability on the inputs!"
        print e.returncode
        print e.output
        result = ''
    return result

def extract_inversion_results():
    f = open(INVERTED_OUTFILE, 'r')
    hslines = []
    for line in f:
        hslines.append(json.loads(line.strip()))
    f.close()
    return hslines

def test_reachability_inport_outheader(hsf, portids, sw_ports):
    res = reachability_inport_outheader(hsf, portids, sw_ports, 3, 2,
                                        match(switch=1,port=2))
    hslines = extract_inversion_results()
    print "test 1:"
    print hslines
    res = reachability_inport_outheader(hsf, portids, sw_ports, 3, 2,
                                        match(switch=1,port=2,dstip=IPAddr('10.0.0.2')))
    hslines = extract_inversion_results()
    print "test 2:"
    print hslines

if __name__ == "__main__":
    hs_format = pyr_hs_format()
    logging.basicConfig()

    # get a classifier
    c = static_fwding_chain_3_3().compile()

    # test a classifier
    sw_ports = get_switch_port_ids()
    portids = get_portid_map(sw_ports)
    convert_classifier(c, hs_format, portids, sw_ports)

    # test a topology transfer function
    edge_list = get_edge_list(get_network_links())
    convert_topology(edge_list, hs_format, portids)

    # write out a port map
    write_port_map(sw_ports, portids)

    # Run reachability
    gen_hassel_datafile()
    test_reachability_inport_outheader(hs_format, portids, sw_ports)

# a rough TODO(ngsrinivas):
# run tf -> ./gen -> dat -> ./reachability -> outputs. check for sane outputs

