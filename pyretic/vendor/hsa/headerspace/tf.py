'''
    <Transfer function class -- Part of HSA Library>
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Jan 24, 2011
Major clean up on Jul 10, 2012

@author: Peyman Kazemian
'''

from pyretic.vendor.hsa.headerspace.hs import *
from pyretic.vendor.hsa.utils.wildcard import *
from array import array
from pyretic.vendor.hsa.utils.wildcard_dictionary import *
from pyretic.vendor.hsa.utils.hs_hash_table import hs_hash_table
import json

class TF(object):
    '''
    models a box transfer function, a network transfer function or a 
    topology transfer function.
    '''

    def __init__(self, length):
        '''
        Constructor
        length is the length of packet headers in bytes. 
        '''
        # L for all headerspace and bytearray objects in this TF
        self.length = length
        
        # List of rules in this TF
        self.rules = []
        
        # List of custom rules
        # IMPORTANT: either use custom_rules or rules at a time. don't mix 
        # and match.
        self.custom_rules = []
        
        # lazy_eval_bytes:index of bytes in HS that may be lazily evaluated.
        # If a rule is only affecting these bytes, don't apply it.
        # lazy_eval_active: whether lazy evaluation of rules is activated.
        self.lazy_eval_bytes = []
        self.lazy_eval_active = False
        
        # Two fast lookup dictionary from input port to rules affecting on them
        # and from output port to rules outputting on them.
        self.inport_to_rule = {}
        self.outport_to_rule = {}
        
        # Fast access to rules by rule id.
        self.id_to_rule = {}
        
        # Used to generate next rule id.
        self.next_id = 0
        self.prefix_id = ""
        
        # If the rules send out results on the port the input hs is received on
        self.send_on_receiving_port = False
        
        # To help improving speed of look up, can use a hash table for this 
        # tf class.
        self.hash_table_object = None
        self.hash_table_active = False
        
    def set_prefix_id(self,str_prefix):
        self.prefix_id = str_prefix
        
    def set_send_on_receiving_port(self, val):
        self.send_on_receiving_port = val
       
    def _generate_next_id(self):
        self.next_id = self.next_id + 1
        return "%s_%d"%(self.prefix_id,self.next_id)
          
    def set_lazy_evaluate(self,list_of_byte_positions):
        '''
        set the index of bytes for lazy evaluation
        '''
        self.lazy_eval_bytes = list_of_byte_positions
        
    def activate_lazy_eval(self):
        self.lazy_eval_active = True
        
    def deactivate_lazy_eval(self):
        self.lazy_eval_active = False
        
    def activate_hash_table(self,h_table):
        self.hash_table_active = True
        self.hash_table_object = h_table
        # start puting objects into hash table
        if not issubclass(h_table,hs_hash_table):
            raise Exception("hash table should be a subclass of hs_hash_table")
        
        for rule in self.rules:
            self.hash_table_object.add_entry(rule["match"],rule["in_ports"],\
                                             rule)
                 
    def deactivate_hash_table(self):
        self.hash_table_active = False
        self.hash_table_object = None
        
    def print_influences(self):
        '''
        For each rule, shows the list of higher priority rules that has an 
        intersection with the rule, and also the lower priority rules that has 
        an intersection with the rule, in two separate lists.
        '''
        for rule in self.rules:
            print "%s Rule Match: %s,%s"%(rule["action"],rule["match"],\
                                          rule["in_ports"])
            print "Affected by:"
            for aff in rule["affected_by"]:
                print "\t%s: On Ports %s, Intersect= %s"%\
                        (aff[0]["match"],aff[2],aff[1])
            print "Influence on:"
            for aff in rule["influence_on"]:
                print "\t%s"%aff["match"]
            print "-"*20
            
    def to_string(self):
        strings = []
        for rule in self.rules:
            if (rule['action'] == 'rw'):
                string = "in_ports: %s, match: %s => ((h & %s) | %s, %s)" % \
                    (rule['in_ports'], rule['match'], rule['mask'], \
                     rule['rewrite'], rule['out_ports'])
                strings.append(string)
                
            if (rule['action'] == 'fwd'):
                string = "in_ports: %s, match: %s => (h , %s)" % \
                    (rule['in_ports'], rule['match'], rule['out_ports'])
                strings.append(string)
                
            if (rule['action'] == 'link'):
                string = "in_ports: %s => out_ports: %s" % \
                    (rule['in_ports'], rule['out_ports'])
                strings.append(string)
                
            if (rule['action'] == 'custom'):
                string = "match: %s , transform: %s" % \
                    (rule['match'].__name__, rule['transform'].__name__)
                strings.append(string)
                
        return strings
    
    def inv_to_string(self):
        strings = []
        for rule in self.rules:
            if (rule['action'] == 'rw'):
                string = "out_ports: %s match: %s => ((h & %s) | %s, %s)" % \
                    (rule['out_ports'], rule['inverse_match'], rule['mask'],\
                  rule['inverse_rewrite'], rule['in_ports'])
                strings.append(string)
                
            if (rule['action'] == 'fwd'):
                string = "out_ports: %s match: %s => (h , %s)" % \
                    (rule['out_ports'], rule['match'], rule['in_ports'])
                strings.append(string)
                
            if (rule['action'] == 'link'):
                string = "out_ports: %s => in_ports: %s)" % \
                    (rule['out_ports'], rule['in_ports'])
                
            if (rule['action'] == 'custom'):
                string = "match: %s , transform: %s" % \
                    (rule['inv_match'].__name__, rule['inv_transform'].__name__)
                strings.append(string)
                
        return strings
            
    @staticmethod
    def create_custom_rule(match, transform, inv_match, inv_transform, \
                           file_name = None, lines = []):
        '''
        Creates a custom rule. You need to provide a function for finding match
        and a function for creating output header.
        @match: a pointer to the function for finding if a packet match this 
        rule. the function should accept (headerspace,in_port) as input and 
        returns a list of headerspace objects that match this rule.
        @transform: a pointer to a function that accepts a (headerspace,port) 
        as input and outputs a list of (headerspace, list of out_ports) pairs
        as the output of the rule.
        @inv_match': a pointer to the function for finding if an output packet
        can be generated by this rule. The function format is like "match'. 
        @inv_transform': a pointer to a function which outputs a list of 
        (headerspace, list of in_ports) pairs as the output of the inverse rule.
        format is similar to @transform.
        '''
        rule = {}
        rule["match"] = match
        rule["inv_match"] = inv_match
        rule["transform"] = transform
        rule["inv_transform"] = inv_transform
        if file_name != None:
            rule["file"] = file_name
        else:
            rule["file"] = ""
        rule["line"] = []
        rule["line"].extend(lines)
        rule["id"] = None
        return rule
            
    @staticmethod
    def create_standard_rule(in_ports, match, out_ports, mask, rewrite, \
                             file_name = None, lines = []):
        '''
        Create a rule using input arguments. 
        @in_ports: list of input ports
        @match: wildcard or str for matching pattern. None for link rules.
        @out_ports: lis ot output ports to send packets to.
        @mask: wildcard or str for masking pattern. should have 0 in bit 
        positions to be rewritten.
        @rewrite: wildcard or str for rewrite pattern. should have 0 in all 
        positions not affected by rewrite.
        @file_name: (optional) name of file this rule comes from.
        @lines: (optional) list of line numbers in the file.
        '''
        rule = {}
        rule["in_ports"] = list(in_ports)
        rule["out_ports"] = list(out_ports)
        #match
        if  match.__class__ == str:
            rule["match"] = wildcard_create_from_string(match)
        elif match.__class__ == wildcard:
            rule["match"] = wildcard_copy(match)
        elif match == None:
            rule["match"] = None
        else:
            raise Exception("Expecting str, wildcard or None for match. found \
            %s"%match.__class__)
        #mask
        if  mask.__class__ == str:
            rule["mask"] = wildcard_create_from_string(mask)
        elif mask.__class__ == wildcard:
            rule["mask"] = wildcard_copy(mask)
        elif mask == None:
            rule["mask"] = None
        else:
            raise Exception("Expecting str, wildcard or None for mask. found \
            %s"%mask.__class__)
        #rewrite
        if  rewrite.__class__ == str:
            rule["rewrite"] = wildcard_create_from_string(rewrite)
        elif rewrite.__class__ == wildcard:
            rule["rewrite"] = wildcard_copy(rewrite)
        elif rewrite == None:
            rule["rewrite"] = None
        else:
            raise Exception("Expecting str, wildcard or None for rewrite. \
            found %s"%rewrite.__class__)
            
        rule['inverse_match'] = None
        rule['inverse_rewrite'] = None
        #influences 
        rule["influence_on"] = []
        rule["affected_by"] = []
        #file refs and id
        if file_name != None:
            rule["file"] = file_name
        else:
            rule["file"] = ""
        rule["line"] = []
        rule["line"].extend(lines)
        rule["id"] = None
        
        return rule
        
    def _find_influences(self, position):
        '''
        After inserting the new_rule, into self.rules, call this method to update the 
        rule dependencies.
        @position: position of the new rule in the rule table
        '''
        new_rule = self.rules[position]
        #higher position rules
        for i in range(0,position):
            if (self.rules[i]["action"] == "rw" or \
                self.rules[i]["action"] == "fwd"):
                common_ports = [val for val in new_rule["in_ports"] \
                                if val in self.rules[i]["in_ports"]]
                intersect = wildcard_intersect(self.rules[i]["match"],\
                                               new_rule["match"])
                if not intersect.is_empty() and len(common_ports) > 0:
                    new_rule["affected_by"].append(\
                                (self.rules[i],intersect,common_ports))
                    self.rules[i]["influence_on"].append(self.rules[position])
        # lower position rules
        for i in range(position+1,len(self.rules)):
            if (self.rules[i]["action"] == "rw" or \
                self.rules[i]["action"] == "fwd"):
                common_ports = [val for val in new_rule["in_ports"] \
                                if val in self.rules[i]["in_ports"]]
                intersect = wildcard_intersect(self.rules[i]["match"],\
                                               new_rule["match"])
                if not intersect.is_empty() and len(common_ports) > 0:
                    new_rule["influence_on"].append(self.rules[i])
                    self.rules[i]["affected_by"].append(\
                                (self.rules[position],intersect,common_ports))
        
    def _set_fast_lookup_pointers(self, position):
        '''
        sets up port-based look up pointer and rule_id based look up entry.
        If hash table is active, add rule to hash table as well.
        @position: position of the new rule in the rule table 
        '''
        new_rule = self.rules[position]
        in_ports = self.rules[position]["in_ports"]
        out_ports = self.rules[position]["out_ports"]
        #input port based lookup table
        for p in in_ports:
            port = "%d"%p
            if port not in self.inport_to_rule.keys():
                self.inport_to_rule[port] = []
            self.inport_to_rule[port].append(new_rule)
        #output port based lookup table
        for p in out_ports:
            port = "%d"%p
            if port not in self.outport_to_rule.keys():
                self.outport_to_rule[port] = []
            self.outport_to_rule[port].append(new_rule)
        #rule-id based lookup table
        self.id_to_rule[new_rule["id"]] = new_rule
        #hash table set up.
        if (self.hash_table_active and new_rule["action"] != "link"):
            self.hash_table_object.add_entry(new_rule["match"],\
                                             new_rule["in_ports"],\
                                             new_rule)
        
    def _get_rules_for_inport(self,inport):
        if (str(inport) in self.inport_to_rule.keys()):
            return self.inport_to_rule[str(inport)]
        else:
            return []
        
    def _get_rules_for_outport(self,outport):
        if (str(outport) in self.outport_to_rule.keys()):
            return self.outport_to_rule[str(outport)]
        else:
            return []
        
    def add_rewrite_rule(self, rule, position= -1):
        '''
        @rule: rule as generated by TF.create_standard_rule.
        @position: position of rule in the table
        Note: Once rule added to TF, TF will own the rule. avoid reusing rule.
        '''
        # Mask rewrite
        rule['rewrite'] = wildcard_and(\
                                                wildcard_not(rule['mask']),\
                                                rule['rewrite'])
        rule['action'] = "rw"
        #finding inverse
        rule['inverse_match'] = wildcard_or(rule["rewrite"],\
                                            wildcard_and(rule["match"],\
                                                         rule["mask"])
                                            )
        rule['inverse_rewrite'] = wildcard_and(rule['match'],\
                                               wildcard_not(rule['mask'])
                                               )
        #setting up id
        rule["id"] = self._generate_next_id()
        #inserting rule at correct position
        if (position == -1 or position >= len(self.rules)):
            self.rules.append(rule)
            position = len(self.rules) - 1
        else:
            self.rules.insert(position, rule)
        #setting up fast lookups and influences
        self._find_influences(position)
        self._set_fast_lookup_pointers(position)
        
        
    def add_fwd_rule(self, rule, position=-1):
        '''
        @rule: rule as generated by TF.create_standard_rule. mask and rewrite
        @position: position of rule in the table
        will be ignored.
        Note: Once rule added to TF, TF will own the rule. avoid reusing rule.
        '''
        #action
        rule['action'] = "fwd"
        #set up rule id
        rule["id"] = self._generate_next_id()
        #insert rule
        if (position == -1 or position >= len(self.rules)):
            self.rules.append(rule)
            priority = len(self.rules) - 1
        else:
            self.rules.insert(priority, rule)
        #set up influence and lookup tables
        self._find_influences(priority)
        self._set_fast_lookup_pointers(priority)
        
    def add_link_rule(self, rule, position = -1):
        '''
        This is useful for topology transfer functions.
        only in_ports and out_ports in the rule is important.
        Note: Once rule added to TF, TF will own the rule. avoid reusing rule.
        '''
        rule['action'] = "link"
        rule["id"] = self._generate_next_id()
        if (position == -1):
            self.rules.append(rule)
            position = len(self.rules) - 1
        else:
            self.rules.insert(position, rule)
        self._set_fast_lookup_pointers(position)
        
    def add_custom_rule(self, rule, position=-1):
        '''
        @rule: rule as generated by TF.create_custom_rule.
        @position: position of rule in the table
        WARNING: use custom rules in a transfer function with only custom rules. 
        Interaction between custom rules and standard rules is not defined.
        '''
        rule['action'] = "custom"
        rule["id"] = self._generate_next_id()
        if (position == -1):
            self.rules.append(rule)
            position = len(self.rules) - 1
        else:
            self.rules.insert(position, rule)
        self.id_to_rule[rule["id"]] = rule
        self.custom_rules.append(self.rules[position])
        
    def apply_rewrite_rule(self,rule,hs,port,applied_rules=None):
        '''
        Applies @rule to (@hs,@port).
        @applied_rules is for internal use only.
        @return: a list of (hs,port) generated by this rule.
        '''
        mod_outports = list(rule["out_ports"])
        # if not sedning on receiving port, remove it from outports.
        if (not self.send_on_receiving_port) and (port in mod_outports):
            mod_outports.remove(port)
        # If no outport, don't do anything.
        if len(mod_outports) == 0:
            applied_rules.append(rule["id"])
            return []
        
        # check if match pattern matches and port is in in_ports. 
        new_hs = hs.copy_intersect(rule['match'])
        if new_hs.count() > 0 and port in rule["in_ports"]:
            
            # subtract off all the higher priority rule's match patterns
            for (r, h, in_ports) in rule["affected_by"]:
                if port in in_ports and \
                (applied_rules == None or r["id"] in applied_rules):
                    new_hs.diff_hs(h)
            # apply mask,rewrite to all elements in hs_list and hs_diff, 
            # considering the cardinality.
            for i in range(0,len(new_hs.hs_list)):
                (rew,card) = wildcard_rewrite(new_hs.hs_list[i],\
                                              rule['mask'],\
                                              rule['rewrite'])

                new_hs.hs_list[i] = rew
                new_diff_list = []
                for diff_hs in new_hs.hs_diff[i]:
                    (diff_rew,diff_card) = \
                    wildcard_rewrite(diff_hs,rule['mask'],rule['rewrite'])
                    if diff_card == card:
                        new_diff_list.append(diff_rew)
                new_hs.hs_diff[i] = new_diff_list
            new_hs.clean_up()
            if (new_hs.count() == 0):
                applied_rules.append(rule["id"])
                return []
            new_hs.push_applied_tf_rule(self,rule["id"],port)
            applied_rules.append(rule["id"])
            return [(new_hs,mod_outports)]
        else:
            return []
        
    def apply_fwd_rule(self,rule,hs,port,applied_rules=None):
        '''
        Applies @rule to (@hs,@port).
        @applied_rules is for internal use only.
        @return: a list of (hs,port) generated by this rule.
        '''
        mod_outports = list(rule["out_ports"])
        # if not sedning on receiving port, remove it from outports.
        if (not self.send_on_receiving_port) and (port in mod_outports):
            mod_outports.remove(port)
        # If no outport, don't do anything.
        if len(mod_outports) == 0:
            applied_rules.append(rule["id"])
            return []
        
        # check if match pattern matches and port is in in_ports.
        new_hs = hs.copy_intersect(rule['match'])
        if new_hs.count() > 0 and port in rule["in_ports"]:
            
            for (r, h, in_ports) in rule["affected_by"]:
                if port in in_ports and \
                (applied_rules == None or r["id"] in applied_rules):
                    new_hs.diff_hs(h)
            new_hs.clean_up()
            if (new_hs.count() == 0):
                applied_rules.append(rule["id"])
                return []
            new_hs.push_applied_tf_rule(self,rule["id"],port)
            applied_rules.append(rule["id"])
            return [(new_hs,mod_outports)]
        else:
            return []
        
    def apply_link_rule(self,rule,hs,port):
        '''
        sends hs to the other end(s) of the link.
        '''
        if port in rule["in_ports"]:
            ohs = hs.copy()
            ohs.push_applied_tf_rule(self,rule["id"],port)
            return [(ohs,list(rule['out_ports']))]
        else:
            return []
      
    def apply_custom_rule(self,rule,hs,port):
        '''
        rule(hs,port) where rule is a custom rule
        '''
        result = []
        matches = rule["match"](hs,port)
        if len(matches) > 0:
            for match in matches:
                tmp_hp = rule["transform"](match,port)
                for (out_hs,out_ports) in tmp_hp:
                    if out_hs.count() > 0:
                        out_hs.push_applied_tf_rule(self,rule["id"],port)
                        result.append((out_hs,out_ports))
        return result
                        
    def T(self,hs,port):
        '''
        returns a list of (hs, list of output ports) as a result of applying 
        transfer function.
        '''
        result = []
        applied_rules = []
        rule_set = []

        if (self.hash_table_active):
            for w in hs.hs_list:
                rs = self.hash_table_object.find_entries(w,port)
                if rs:
                    rule_set.extend(rs)
                else:
                    rule_set = self._get_rules_for_inport(port)
                    break
        else:
            rule_set = self._get_rules_for_inport(port)

        lazy_tf_rule_ids = {}
        for rule in rule_set:
            #check if this rule qualifies for lazy evaluation
            if self.lazy_eval_active and self._is_qualified_for_lazy_eval(rule):
                for p in rule["out_ports"]:
                    if str(p) not in lazy_tf_rule_ids.keys():
                        lazy_tf_rule_ids[str(p)] = []
                    lazy_tf_rule_ids[str(p)].append(rule)
                    
                lazy_tf_rule_ids.append(rule["id"])
                lazy_hs = hs.copy()
                lazy_hs.add_lazy_tf_rule(self,rule["id"],port)
                result.append(lazy_hs,rule["out_ports"])
            # link rule
            elif rule['action'] == "link":
                result.extend(self.apply_link_rule(rule, hs, port))
            # rewrite rule
            elif rule['action'] == "rw":
                result.extend(self.apply_rewrite_rule(rule, hs, port,\
                                                      applied_rules))
            # forward rule
            elif rule['action'] == "fwd":
                result.extend(self.apply_fwd_rule(rule, hs, port,applied_rules))
    
        #lazy tf rules:
        if (self.lazy_eval_active):
            for p in lazy_tf_rule_ids.keys():
                lazy_outport = int(p)
                lazy_hs = hs.copy()
                lazy_hs.add_lazy_tf_rule(self,lazy_tf_rule_ids[p],port)
                result.append(lazy_hs,[lazy_outport])
                
        # custom rules
        for rule in self.custom_rules:
            result.extend(self.apply_custom_rule(rule, hs, port))
       
        return result
                
    def T_rule(self,rule_id,hs,port):
        '''
        Apply rule with id = rule_id to (hs,port)
        Output is a list of [hs,list_of_out_ports].
        '''
        result = []
        if self.id_to_rule.has_key(rule_id):
            rule = self.id_to_rule[rule_id]
            if rule['action'] == "link":
                result = self.apply_link_rule(rule, hs, port)
            elif rule['action'] == "rw":
                result = self.apply_rewrite_rule(rule, hs, port)
            elif rule['action'] == "fwd":
                result = self.apply_fwd_rule(rule, hs, port)
            elif rule['action'] == "custom":
                result = self.apply_custom_rule(rule, hs, port)
                
        return result
        
    def apply_inv_link_rule(self,rule,hs,port):
        if (port in rule["out_ports"]):
            ihs = hs.copy()
            ihs.push_applied_tf_rule(self,rule["id"],port)
            return [(ihs,list(rule['in_ports']))]
        else:
            return []        
        
    def apply_inv_rewrite_rule(self,rule,hs,port):
        
        result = []
        new_hs = hs.copy_intersect(rule['inverse_match'])
        if new_hs.count() > 0 and port in rule["out_ports"]:
            for i in range(0,len(new_hs.hs_list)):
                (rew,card) = wildcard_rewrite(new_hs.hs_list[i],\
                                                rule['mask'],\
                                                rule['inverse_rewrite'])
                new_hs.hs_list[i] = rew
                new_diff_list = []
                for diff_hs in new_hs.hs_diff[i]:
                    (diff_rew,diff_card) = \
                    wildcard_rewrite(diff_hs,rule['mask'],\
                                       rule['inverse_rewrite'])
                    if diff_card == card:
                        new_diff_list.append(diff_rew)
                new_hs.hs_diff[i] = new_diff_list
                
            for p in rule["in_ports"]:
                next_hs = new_hs.copy()
                for (r, h, in_ports) in rule["affected_by"]:
                    if p in in_ports:
                        next_hs.diff_hs(h)
                next_hs.clean_up()
                if (next_hs.count() != 0):
                    next_hs.push_applied_tf_rule(self,rule["id"],port)
                    result.append((next_hs,[p]))
        return result
    
    def apply_inv_fwd_rule(self,rule,hs,port):
        result = []
        new_hs = hs.copy_intersect(rule['match'])
        if new_hs.count() > 0:
            for p in rule["in_ports"]:
                next_hs = new_hs.copy()
                for (r, h, in_ports) in rule["affected_by"]:
                    if p in in_ports:
                        next_hs.diff_hs(h)
                next_hs.clean_up()
                if (next_hs.count() != 0):
                    next_hs.push_applied_tf_rule(self,rule["id"],port)
                    result.append((next_hs,[p]))
        return result
                
    def apply_inv_custom_rule(self,rule,hs,port):
        result = []
        matches = rule["inv_match"](hs,port)
        for match in matches:
            tmp_hp = rule["inv_transform"](match,port)
            for (in_hs,in_ports) in tmp_hp:
                if in_hs.count() > 0:
                    in_hs.push_applied_tf_rule(self,rule["id"],port)
                    result.append((in_hs,in_ports))
        return result            
        
    def T_inv(self,hs,port):
        '''
        returns a list of (hs, list of in_ports) as possible inputs that can cause this (hs,port).
        The format of hs and returned headerspace object, is like T() method above. 
        '''
        result = []
        
        for rule in self._get_rules_for_outport(port):
            #check if rule qualifies for lazy eval
            if (self.lazy_eval_active and self._is_qualified_for_lazy_eval(rule)):
                lazy_hs = hs.copy()
                lazy_hs.add_lazy_tf_rule(self,rule["id"],port)
                result.append(lazy_hs,rule["in_ports"])
            # link rule
            elif rule['action'] == "link":
                result.extend(self.apply_inv_link_rule(rule, hs, port))
            # rewrite rule
            elif rule['action'] == "rw":
                result.extend(self.apply_inv_rewrite_rule(rule, hs, port))
            # forward rules
            elif rule['action'] == "fwd":
                result.extend(self.apply_inv_fwd_rule(rule, hs, port))
            
        # custom rules                
        for rule in self.custom_rules:
            result.extend(self.apply_inv_custom_rule(rule, hs, port))
                        
        return result
        
    def T_inv_rule(self,rule_id,hs,port):
        '''
        Apply rule with id = rule_id to (hs,port)
        Output is a list of [hs,list_of_out_ports].
        '''
        result = []
        if self.id_to_rule.has_key(rule_id):
            rule = self.id_to_rule[rule_id]
            if rule['action'] == "link":
                result = self.apply_inv_link_rule(rule, hs, port)
            elif rule['action'] == "rw":
                result = self.apply_inv_rewrite_rule(rule, hs, port)
            elif rule['action'] == "fwd":
                result = self.apply_inv_fwd_rule(rule, hs, port)
            elif rule['action'] == "custom":
                result = self.apply_inv_custom_rule(rule, hs, port)
                
        return result
        
    def _is_qualified_for_lazy_eval(self,rule):
        '''
        checks if all rewrites happen inside lazy eval bytes or not.
        '''
        if rule["action"] == "rw":
            no_rewrite_outside_lazy = True
            one_rewrite_inside_lazy = False
            for i in range(len(rule["mask"])):
                if i in self.lazy_eval_bytes:
                    if rule["mask"][i] != 0xaaaa:
                        one_rewrite_inside_lazy = True
                else:
                    if rule["mask"][i] != 0xaaaa:
                        no_rewrite_outside_lazy = False
            return (no_rewrite_outside_lazy and one_rewrite_inside_lazy)
        else:
            return False

        
    def save_as_json(self, file):
        '''
        saves all the non-custom transfer function rules to a json file
        '''
        # print "=== Saving transfer function to json file %s ==="%file
        func = {}
        func["length"] = self.length
        func["prefix_id"] = self.prefix_id
        func["next_id"] = self.next_id
        func["lazy_eval_active"] = self.lazy_eval_active
        func["send_on_receiving_port"] = self.send_on_receiving_port
        func["lazy_eval_bytes"] = self.lazy_eval_bytes
        func["rules"] = []
        for rule in self.rules:
            r = {}
            r["action"] = rule["action"]
            r["in_ports"] = rule["in_ports"]
            r["out_ports"] = rule["out_ports"]
            r["match"] = wildcard_to_str(rule["match"])
            r["mask"] = wildcard_to_str(rule["mask"])
            r["rewrite"] = wildcard_to_str(rule["rewrite"])
            r["inverse_match"] = wildcard_to_str(rule["inverse_match"])
            r["inverse_rewrite"] = wildcard_to_str(rule["inverse_rewrite"])
            r["affected_by"] = []
            r["id"] = rule["id"]
            r["file"] = rule["file"]
            r["line"] = rule["line"]
            for ra in rule["affected_by"]:
                r["affected_by"].append([self.rules.index(ra[0]),
                                         wildcard_to_str(ra[1]),
                                         ra[2]])
            r["influence_on"] = []
            for io in rule["influence_on"]:
                r["influence_on"].append(self.rules.index(io))
            func["rules"].append(r)
            
        f = open(file, 'w')
        f.write(json.dumps(func, indent=1))
        f.close()
        # print "=== Transfer function saved to json file %s ==="%file
        
    def save_object_to_file(self, file):
        '''
        Depreciated
        saves all the non-custom transfer function rules to a file
        '''
        # print "=== Saving transfer function to file %s ==="%file
        f = open(file, 'w')
        f.write("%d$%s$%d$%d$%d$\n"%(2*self.length,\
                                     self.prefix_id,\
                                     self.next_id,\
                                     self.lazy_eval_active,\
                                     self.send_on_receiving_port)
                )
        for b in self.lazy_eval_bytes:
            f.write("%d$"%b)
        f.write("#\n")
        for rule in self.rules:
            f.write("%s$"%rule["action"])
            f.write("%s$"%rule["in_ports"])
            f.write("%s$"%wildcard_to_str(rule["match"]))
            f.write("%s$"%wildcard_to_str(rule["mask"]))
            f.write("%s$"%wildcard_to_str(rule["rewrite"]))
            f.write("%s$"%wildcard_to_str(rule["inverse_match"]))
            f.write("%s$"%wildcard_to_str(rule["inverse_rewrite"]))
            f.write("%s$"%rule["out_ports"])
            f.write("#")
            for ra in rule["affected_by"]:
                f.write("%d;%s;%s#"%(self.rules.index(ra[0]),\
                                     wildcard_to_str(ra[1]),\
                                     ra[2]))
            f.write("$")
            f.write("#")
            for io in rule["influence_on"]:
                f.write("%d#"%self.rules.index(io))
            f.write("$%s$"%rule["file"])
            for ln in rule["line"]:
                f.write("%d,"%ln)
            f.write("$%s$\n"%rule["id"])
        f.close()
        # print "=== Transfer function saved to file %s ==="%file
        
    def load_from_json(self, file):
        print "=== Loading transfer function from file %s ==="%file
        f = open(file,'r')
        func = json.load(f)
        self.rules = []
        self.length = func["length"]
        self.prefix_id = func["prefix_id"]
        self.next_id = func["next_id"]
        self.lazy_eval_active = func["lazy_eval_active"]
        self.send_on_receiving_port = func["send_on_receiving_port"]
        self.lazy_eval_bytes = func["lazy_eval_bytes"]
        for rule in func["rules"]:
          rule["match"] = wildcard_create_from_string(rule["match"])
          rule["mask"] = wildcard_create_from_string(rule["mask"])
          rule["rewrite"] = wildcard_create_from_string(rule["rewrite"])
          rule["inverse_match"] = wildcard_create_from_string(rule["inverse_match"])
          rule["inverse_rewrite"] = wildcard_create_from_string(rule["inverse_rewrite"])
          for i in range(len(rule["affected_by"])):
            rule["affected_by"][i][1] = wildcard_create_from_string(rule["affected_by"][i][1])
          self.rules.append(rule)
        f.close()
        for indx in range(len(self.rules)):
          rule = self.rules[indx]
          for i in range(len(rule["influence_on"])):
            rule["influence_on"][i] = self.rules[i]
          for j in range(len(rule["affected_by"])):
            rule["affected_by"][j][0] = self.rules[rule["affected_by"][j][0]]
    
          self._set_fast_lookup_pointers(indx)
        
        
    def load_object_from_file(self, file):
        '''
        Depreciated
        load object from file, and replace the current object.
        '''
        print "=== Loading transfer function from file %s ==="%file
        f = open(file,'r')
        self.rules = []
        first_line = f.readline()
        tokens = first_line.split('$')
        self.length = int(tokens[0])
        self.prefix_id = tokens[1]
        self.next_id = int(tokens[2])
        if (int(tokens[3]) == 1):
            self.lazy_eval_active = True
        else:
            self.lazy_eval_active = False
        if (int(tokens[4]) == 1):
            self.send_on_receiving_port = True
        else:
            self.send_on_receiving_port = False
        second_line = f.readline()
        tokens = second_line.split('#')[0].split('$')
        for n in tokens:
            if n != "":
                self.lazy_eval_bytes.append(int(n))
        for line in f:
            tokens = line.split('$')
            new_rule = {}
            # action
            new_rule["action"] = tokens[0]
            # in_ports
            in_p = tokens[1].strip('[]').split(', ')
            new_rule["in_ports"] = []
            for p in in_p:
                if p != "":
                    new_rule["in_ports"].append(int(p)) 
            # match
            match = wildcard_create_from_string(tokens[2])
            new_rule["match"] = match
            # mask
            mask = wildcard_create_from_string(tokens[3])
            new_rule["mask"] = mask
            # rewrite
            rewrite = wildcard_create_from_string(tokens[4])
            new_rule["rewrite"] = rewrite
            # inverse_match
            inverse_match = wildcard_create_from_string(tokens[5])
            new_rule["inverse_match"] = inverse_match
            # inverse_rewrite
            inverse_rewrite = wildcard_create_from_string(tokens[6])
            new_rule["inverse_rewrite"] = inverse_rewrite
            # out_ports
            out_p = tokens[7].strip('[]').split(', ')
            new_rule["out_ports"] = []
            for p in out_p:
                if p != "":
                    new_rule["out_ports"].append(int(p)) 
            # affected by
            new_rule["affected_by"] = []
            affect_list = tokens[8].split('#')
            for affect in affect_list:
                if affect != "":
                    elems = affect.split(';')
                    aff_p = elems[2].strip('[]').split(', ')
                    prts = []
                    for p in aff_p:
                        if p != "":
                            prts.append(int(p)) 
                    new_affect = (int(elems[0]),wildcard_create_from_string(elems[1]),prts)
                    new_rule["affected_by"].append(new_affect)
            # influence on
            new_rule["influence_on"] = []
            influence_list = tokens[9].split('#')
            for influence in influence_list:
                if influence != "":
                    new_rule["influence_on"].append(int(influence))
            new_rule["file"] = tokens[10]
            lns = tokens[11].split(',')
            new_rule["line"] = []
            for ln in lns:
                if ln != "":
                    new_rule["line"].append(int(ln))
            new_rule["id"] = tokens[12]
            # Save new rule
            self.rules.append(new_rule)

        f.close()
        # now replace index in affected_by and influence_on fields to the pointer to rules.
        for indx in range(len(self.rules)):
            rule = self.rules[indx]
            influences = []
            for idex in rule["influence_on"]:
                influences.append(self.rules[idex])
            rule["influence_on"] = influences
            affects = []
            for r in rule["affected_by"]:
                new_affect = (self.rules[r[0]],r[1],r[2])
                affects.append(new_affect)
            rule["affected_by"] = affects
            self._set_fast_lookup_pointers(indx)
            
        print "=== Transfer function loaded from file %s ==="%file
            
    def __str__(self):
        strs = self.to_string()
        result = ""
        for s in strs:
            result += "%s\n"%s
        return result
        
    '''
    def add_fwd_rule_no_influence(self, rule, priority=-1):
        extended_rule = rule.copy()
        extended_rule['match'] = bytearray(rule['match'])
        extended_rule['action'] = "fwd"
        extended_rule['inverse_match'] = None
        extended_rule['inverse_rewrite'] = None
        extended_rule["id"] = self._generate_next_id()
        if (priority == -1 or priority >= len(self.rules)):
            self.rules.append(extended_rule)
            priority = len(self.rules) - 1
        else:
            self.rules.insert(priority, extended_rule)
            
        #self._find_influences(priority)
        self._set_fast_lookup_pointers(priority)
        
    def add_rewrite_rule_no_influence(self, rule, priority= -1):
        extended_rule = rule.copy()
        extended_rule['match'] = bytearray(rule['match'])
        extended_rule['mask'] = bytearray(rule['mask'])
        # Mask rewrite
        extended_rule['rewrite'] = byte_array_and(byte_array_not(rule['mask']), rule['rewrite'])
        extended_rule['action'] = "rw"
        
        masked = byte_array_and(rule['match'], rule['mask'])
        rng = byte_array_or(masked, rule['rewrite'])
        extended_rule['inverse_match'] = rng
        extended_rule['inverse_rewrite'] = byte_array_and(byte_array_not(rule['mask']), rule['match'])
        extended_rule["id"] = self._generate_next_id()
        if (priority == -1 or priority >= len(self.rules)):
            self.rules.append(extended_rule)
            priority = len(self.rules) - 1
        else:
            self.rules.insert(priority, extended_rule)
            
        #self._find_influences(priority)
        self._set_fast_lookup_pointers(priority)
    '''
