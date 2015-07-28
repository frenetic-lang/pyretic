'''
    <Helper functions used in Cisco IOS parser -- Part of HSA Library>
    
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Jun 1, 2011

@author: Peyman Kazemian
'''

import re
from math import pow
# from headerspace.hs import *
# from headerspace.tf import TF
    
def is_ip_address(str):
    ips = re.match('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', str)
    if ips == None:
        return False
    else:
        return True
    
def is_ip_subnet(str):
    ips = re.match('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})/(?:[\d]{1,2})', str)
    if ips == None:
        return False
    else:
        return True
    
def int_to_dotted_ip( intip ):
        octet = ''
        for exp in [3,2,1,0]:
            octet = octet + str(intip / ( 256 ** exp )) + "."
            intip = intip % ( 256 ** exp )
        return(octet.rstrip('.'))
 
def dotted_ip_to_int( dotted_ip ):
        exp = 3
        intip = 0
        for quad in dotted_ip.split('.'):
            intip = intip + (int(quad) * (256 ** exp))
            exp = exp - 1
        return(intip)
    
def dotted_subnet_to_int( dotted_subnet ):
        exp = 3
        intip = 0
        subnet = 32
        parts = dotted_subnet.split('/')
        if len(parts) > 1:
            try:
                subnet = int(parts[1])
            except Exception:
                pass
        dotted_ip = parts[0]
        for quad in dotted_ip.split('.'):
            intip = intip + (int(quad) * (256 ** exp))
            exp = exp - 1
        return([intip,subnet])
    
def mac_to_int(mac):
  return int(mac.replace(':', ''),16)
    
def l2_proto_to_int(proto):
  if proto == "ip":
    return 0x0800
  elif proto == "arp":
    return 0x0806
  elif proto == "mpls":
    return 0x8847
    
def range_to_wildcard(r_s,r_e,length):
    vals = r_s
    vale = r_e
    match = []
    while (vals <= vale):
        for i in range(1,length+2):
            if not ((vals | (2**i - 1 )) <= vale and (vals % 2**i)==0) :
                match.append((vals,i-1))
                vals = (vals| (2**(i-1) - 1 )) + 1
                break
    return match
    
def find_num_mask_bits_right_mak(mask):
    count = 0
    while (True):
        if (mask & 1 == 1):
            mask = mask >> 1
            count += 1
        else:
            break
    return count

def find_num_mask_bits_left_mak(mask):
    count = 0
    while (True):
        if (mask & 1 == 0):
            mask = mask >> 1
            count += 1
        else:
            break
    return 32-count
    
class node(object):
    def __init__(self):
        self.zero = None;
        self.one = None;
        self.ips = []
        self.action = None;
        
    def printSelf(self, indent):
        ind = ""
        for i in range(indent):
            ind = ind + "\t";
        str_ip = "%sIPs: "%ind
        for i in self.ips:
            str_ip = str_ip + int_to_dotted_ip(i[0]) + "/%d"%i[1] + ", "
        print str_ip
        print "%sAction: %s"%(ind,self.action)
        if self.zero != None:
            print "%sZero:"%(ind)
            self.zero.printSelf(indent+1)
        if self.one != None:
            print "%sOne:"%(ind)
            self.one.printSelf(indent+1)
    
    def is_leaf(self):
        return (self.zero == None and self.one == None)
    
    def optimize(self,action):
        propagate_action = action
        if (self.action != None):
            propagate_action = self.action
            
        if (self.zero != None):
            self.zero.optimize(propagate_action)
            if (self.zero.action == propagate_action and self.zero.action != None):
                self.ips.extend(self.zero.ips)
                self.action = propagate_action
                self.zero.ips = []
                self.zero.action = None
                if self.zero.is_leaf():
                    self.zero = None
        if (self.one != None):
            self.one.optimize(propagate_action)
            if (self.one.action == propagate_action and self.one.action != None):
                self.ips.extend(self.one.ips)
                self.action = propagate_action
                self.one.ips = []
                self.one.action = None
                if self.one.is_leaf():
                    self.one = None
        if (self.zero != None and self.one != None and \
            self.zero.action == self.one.action and self.zero.action != None):
            self.action = self.zero.action
            self.ips.extend(self.zero.ips)
            self.ips.extend(self.one.ips)
            self.zero.ips = []
            self.zero.action = None
            self.one.ips = []
            self.one.action = None
            if self.zero.is_leaf():
                self.zero = None
            if self.one.is_leaf():
                self.one = None
              
    def output_compressed(self, power, cip, result):
        if (self.zero != None):
            self.zero.output_compressed(power-1, cip, result)
        if (self.one != None):
            self.one.output_compressed(power-1, int(cip + pow(2,power-1)), result)
        if len(self.ips) > 0:
            result.append((cip,32-power,self.action,self.ips))
          
    
def compress_ip_list(ip_list):
    '''
    ip_list is a list of ip address, subnet, next_hop,... of type 
    (int,int,string,...)
    this function compresses the list, and returns a list of 
    (int ip address,int subnet,next_hop,[ip_list_elem]) where list of
    ip_list_elem shows which input ipl_list elem is compressed to create the 
    output entry and next_hop is a string indicating the next hop.
    '''
    root = node()
    # create the tri
    for elem in ip_list:
        cur = root
        for i in range(31,31-elem[1],-1):
            next_bit = (elem[0] >> i) & 0x1
            if (next_bit == 0):
                if (cur.zero == None):
                    cur.zero = node()
                cur = cur.zero
            elif (next_bit == 1):
                if (cur.one == None):
                    cur.one = node()
                cur = cur.one
        if (len(cur.ips) == 0):
            cur.ips.append(elem)
            cur.action = elem[2]

    # optimize the tri
    #root.printSelf(0)
    root.optimize(None)
    #root.printSelf(0)
    result = []
    root.output_compressed(32, 0, result)
    return result
        
        
def compose_standard_rules(rule1,rule2):

    mid_ports = [val for val in rule2["in_ports"] if val in rule1["out_ports"]]
    if len(mid_ports) == 0:
        return None
    
    ### finding match
    #rule 2 is a link rule
    if rule2["match"] == None:
        match = wildcard_copy(rule1["match"])
    else:
        # if rule 1 is a fwd or link rule
        if rule1["mask"] == None:
            # if rule 1 is a link rule
            if rule1["match"] == None:
                match = wildcard_copy(rule2["match"])
            else:
                match = wildcard_intersect(rule2["match"],rule1["match"])
        # if rule 1 is a rewrite rule
        else:
            match_inv = wildcard_or(\
                wildcard_and(rule2["match"],rule1['mask']),\
                rule1['inverse_rewrite'])
            match = wildcard_intersect(match_inv,rule1["match"])
    if len(match) == 0:
        return None
    
    ### finding mask and rewrite
    mask = None
    rewrite = None
    if rule2["mask"] == None:
        mask = rule1["mask"]
        rewrite = rule1["rewrite"]
    elif rule1["mask"] == None:
        mask = rule2["mask"]
        rewrite = rule2["rewrite"]
    else:
        # mask = mask1 & mask2
        # rewrite = (rewrite1 & mask2) | (rewrite2 & !mask2)
        mask = wildcard_and(rule1["mask"],rule2["mask"])
        rewrite = wildcard_or(wildcard_and(rule1["rewrite"],rule2["mask"]),wildcard_and(rule2["rewrite"],wildcard_not(rule2["mask"])))
    in_ports = rule1["in_ports"]
    out_ports = rule2["out_ports"]
    
    if rule1["file"] == rule2["file"]:
        file_name = rule1["file"]
    else:
        file_name = "%s , %s"%(rule1["file"],rule2["file"])
    
    lines = rule1["line"]
    lines.extend(rule2["line"])
    result_rule = TF.create_standard_rule(in_ports, match, out_ports, mask, rewrite, file_name, lines)
    return result_rule
