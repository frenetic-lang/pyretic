'''
Created on Jul 10, 2012

@author: Peyman Kazemian
'''

from pyretic.vendor.hsa.utils.wildcard import \
    wildcard_is_subset,wildcard_create_from_int,\
    wildcard_create_bit_repeat

'''
 Non-C helper functions
'''

def compress_wildcard_list(l):
    pop_index = []
    for i in range(len(l)):
        for j in range(i + 1, len(l)):
            if wildcard_is_subset(l[i], l[j]):
                pop_index.append(i)
            elif wildcard_is_subset(l[j], l[i]):
                pop_index.append(j)
    result = []
    for k in range(len(l)):
        if k not in pop_index:
            result.append(l[k])
    return result

def extract_wildcard_mask_match_string(w):
    if w == None:
        raise Exception("Wildcard is empty")
    str_mask = ""
    str_match = ""
    for i in range(len(w)):
        for j in range(8):
            next_bit = w[(i,j)]
            if (next_bit == 0x01):
                str_mask = "1" + str_mask
                str_match = "0" + str_match
            elif (next_bit == 0x02):
                str_mask = "1" + str_mask
                str_match = "1" + str_match
            elif (next_bit == 0x03):
                str_mask = "0" + str_mask
                str_match = "0" + str_match
            else:
                str_mask = "0" + str_mask
                str_match = "1" + str_match
    return [str_mask,str_match]
  
def wc_byte_to_int(b):
    val = 0
    for i in range(4):
        b_shift = b >> (i * 2)
        next_bit = b_shift & 0x03
        if (next_bit == 0x02):
            val = val + 2**i
        elif (next_bit != 0x01):
            return None
    return val
  
def wc_header_to_parsed_string(hs_format, fields, i_wc):
    out_string = ""
    for field in fields:
        offset = hs_format["%s_pos"%field]
        len = hs_format["%s_len"%field]
        w = wildcard_create_bit_repeat(len,0x1)
        for i in range(0,len):
            w[i] = i_wc[offset+i]
        out_string = "%s%s:%s, "%(out_string, field, w)
    return out_string
  
def set_header_field(hs_format, arr, field, value, right_mask):
    '''
    Sets the @field in wildcard @arr to @value.
    @hs_format: field names, such as 'vlan', 'ip_src', 'ip_dst', 
    'ip_proto', 'transport_src', 'transport_dst', 'transport_ctrl', etc
    each feild should have _len (length) and _pos (position). look at 
    cisco_router_parser for an example. 
    @arr: the wildcard to set the field bits to value.
    @field: a field name
    @value: an integer number, of the width equal to field's width
    @right_mask: number of bits, from right that should be ignored when 
    written to field. e.g. to have a /24 ip address, set mask to 8.
    '''
    wc_array = wildcard_create_from_int(value, \
                                            hs_format["%s_len" % field])
    start_pos = hs_format["%s_pos" % field]
    for i in range(hs_format["%s_len" % field]):
        if right_mask <= 8 * i:
            arr[start_pos + i] = wc_array[i]
        elif (right_mask > 8 * i and right_mask < 8 * i + 8):
            shft = right_mask % 8;
            rm = (0xffff << 2 * shft) & 0xffff
            lm = ~rm & 0xffff
            arr[start_pos + i] = \
            (wc_array[i] & rm) | (arr[start_pos + i] & lm) 
