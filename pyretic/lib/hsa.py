from pyretic.core.language import *
from pyretic.vendor.hsa.utils.wildcard import wildcard_create_bit_repeat
from pyretic.vendor.hsa.utils.wildcard_utils import set_header_field
from ipaddr import IPv4Network

def pyr_hs_format():
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
    format["vlan_pcp_len"] = 30 # allocate full byte for 3 bits

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

if __name__ == "__main__":
    hs_format = pyr_hs_format()
    match = wildcard_create_bit_repeat(hs_format["length"], 3)
    set_header_field(hs_format, match, "dstport", 80, 0)
    print match

# a rough TODO(ngsrinivas):
# try match, mask and modify from various rule combinations
# call create_standard_rule with a tf object
# save the tf object to a .tf file
# run tf -> ./gen -> dat -> ./reachability -> outputs. check for sane outputs

