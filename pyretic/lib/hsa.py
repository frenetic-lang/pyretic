from pyretic.core.language import *
from pyretic.vendor.hsa.utils.wildcard import wildcard_create_bit_repeat
from pyretic.vendor.hsa.utils.wildcard_utils import set_header_field
from ipaddr import IPv4Network
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

def convert_classifier(classifier, hsf):
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
                return (None, None, outports)
            else:
                raise RuntimeError("actions not HSA-compilable! %s" % acts)
        elif len(new_acts) == 1:
            mod_dict = copy.copy(new_acts[0].map)
            if 'port' in mod_dict:
                outports = [mod_dict['port']]
                del mod_dict['port']
            else:
                return (None, None, [])
            if len(mod_dict.keys()) > 0:
                ''' There are rewritten packet header fields. '''
                mask = wildcard_create_bit_repeat(hsf["length"], 0x2)
                rewrite = wildcard_create_bit_repeat(hsf["length"], 0x1)
                for (field, val) in mod_dict.iteritems():
                    set_field_val(mask, field, 0, process_field=False)
                    set_field_val(rewrite, field, val)
                return (mask, rewrite, outports)
            else:
                return (None, None, outports)
        else:
            ''' No modify actions '''
            return (None, None, [])

    for rule in classifier.rules:
        if isinstance(rule.match, match):
            mat = get_match_wc(rule.match.map)
        elif rule.match == identity:
            mat = get_match_wc({})
        else:
            raise RuntimeError("unexpected rule match in classifier!")
        (mask, rewrite, outports) = get_action_wc(rule.actions)
        print rule.actions
        print '--->', mask, rewrite, outports

def get_portid_map(sw_ports):
    max_port = reduce(lambda acc, (x,y): max(acc, max(y)), sw_ports, 0)
    portid_map = {}
    for (sw, ports) in sw_ports.iteritems():
        for port in ports:
            portid_map[(sw, port)] = (sw * max_port) + port
    return portid_map

if __name__ == "__main__":
    hs_format = pyr_hs_format()

    # get a classifier
    c = static_fwding_chain_3_3().compile()
    print c

    # test a classifier
    convert_classifier(c, hs_format)

    # TODO: fields to set in a TF rule
    # in_port
    # out_port
    # mask and rewrite for modification rules such that:
    # new_hs = (old_hs & mask) | rewrite

# a rough TODO(ngsrinivas):
# try match, mask and modify from various rule combinations
# call create_standard_rule with a tf object
# save the tf object to a .tf file
# run tf -> ./gen -> dat -> ./reachability -> outputs. check for sane outputs

