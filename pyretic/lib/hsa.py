from pyretic.core.language import *
from pyretic.vendor.hsa.utils.wildcard import wildcard_create_bit_repeat
from pyretic.vendor.hsa.utils.wildcard_utils import set_header_field
from ipaddr import IPv4Network
from pyretic.vendor.hsa.headerspace.tf import TF
import copy

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
                              (match(switch=2) >> fwd(1)) +
                              (match(switch=3) >> fwd(1)))) +
        (match(dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(3)) +
                              (match(switch=3) >> fwd(1)))) +
        (match(dstip=ip3) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(2)))) +
        (~match(srcmac='00:00:00:00:00:01')) +
        (match(ethtype=IP_TYPE)) +
        (match(dstip=ip4) >> (modify(dstport=80) >> modify(port=4)))
        )

def convert_classifier(classifier, hsf, portids, sw_ports):
    """Function to convert a classifier `classifier` into a header space given by a
    header space format dictionary `hsf`.
    """
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

    def set_field_val(wc_obj, field, val, process_field=True):
        if field in ['srcmac', 'dstmac']:
            int_val = mac2int(val) if process_field else val
            set_header_field(hsf, wc_obj, field, int_val, 0)
        elif field in ['srcip', 'dstip']:
            int_val = ip2int(val) if process_field else val
            if process_field:
                int_val = ip2int(val)
                right_pfx = 32 - val.prefixlen
            else:
                int_val = val
                right_pfx = 0
            set_header_field(hsf, wc_obj, field, int_val, right_pfx)
        elif not field in ['switch', 'port']:
            set_header_field(hsf, wc_obj, field, val, 0)
        else:
            ''' do nothing '''
            return wc_obj

    def get_match_wc(mat_map):
        mat = wildcard_create_bit_repeat(hsf["length"], 3)
        for (field, val) in mat_map.iteritems():
            set_field_val(mat, field, val)
        return mat

    def get_inports(mat_map):
        ''' Return network-wide unique identifiers from match information in
        classifiers. '''
        inports = []
        if 'switch' in mat_map:
            sw = mat_map['switch']
            if 'port' in mat_map:
                inports.append(portids[(sw, mat_map['port'])])
            else:
                for p in sw_ports[sw]:
                    inports.append(portids[(sw,p)])
        else:
            if 'port' in mat_map:
                p = mat_map['port']
                for sw in sw_ports.keys():
                    if p in sw_ports[sw]:
                        inports.append(portids[(sw,p)])
            else:
                inports = portids.values()
        return inports

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
                    set_field_val(mask, field, 0, process_field=False)
                    set_field_val(rewrite, field, val)
                return (mask, rewrite, outports, True)
            else:
                return (None, None, outports, False)
        else:
            ''' No modify actions '''
            return (None, None, [], False)

    def process_outports(mat_map, acts_ports):
        ''' Return network-wide unique port identifiers from the port values
        present in classifier actions. '''
        out_ports = []
        if 'switch' in mat_map:
            sw = mat_map['switch']
            for p in acts_ports:
                out_ports.append(portids[(sw, p)])
        else:
            for sw in sw_ports.keys():
                for p in acts_ports:
                    if p in sw_ports[sw]:
                        out_ports.append(portids[(sw,p)])
        return out_ports

    ''' Classifier conversion core logic begins here. '''
    tf = TF(hsf["length"])
    for rule in classifier.rules:
        try:
            mat_map = {} if rule.match == identity else rule.match.map
        except:
            raise RuntimeError("unexpected rule match in classifier!")
        mat_wc = get_match_wc(mat_map)
        in_ports = get_inports(mat_map)
        (mask, rewrite, outports, rw) = get_action_wc(rule.actions)
        out_ports = process_outports(mat_map, outports)
        print '*********************'
        print 'inports:', in_ports
        print rule.match
        print '--->', mat_wc
        print rule.actions
        print '--->', mask, rewrite
        print 'outports:', out_ports
        print '*********************'
        rule = TF.create_standard_rule(in_ports, mat_wc,
                                       out_ports, mask, rewrite)
        if rw:
            tf.add_rewrite_rule(rule)
        else:
            tf.add_fwd_rule(rule)
    tf.save_object_to_file('/tmp/tf-test.txt')

def get_portid_map(sw_ports):
    max_port = reduce(lambda acc, (x,y): max(acc, max(y)),
                      sw_ports.iteritems(), 0)
    portid_map = {}
    for (sw, ports) in sw_ports.iteritems():
        for port in ports:
            portid_map[(sw, port)] = (sw * max_port) + port
    return portid_map

def get_edge_list(edges):
    edge_list = []
    for (s1, s2, ports) in edges:
        edge_list.append((s1, ports[s1], s2, ports[s2]))
    return edge_list

if __name__ == "__main__":
    hs_format = pyr_hs_format()

    # get a classifier
    c = static_fwding_chain_3_3().compile()

    # test a classifier
    sw_ports = get_switch_port_ids()
    portids = get_portid_map(sw_ports)
    convert_classifier(c, hs_format, portids, sw_ports)

# a rough TODO(ngsrinivas):
# run tf -> ./gen -> dat -> ./reachability -> outputs. check for sane outputs

