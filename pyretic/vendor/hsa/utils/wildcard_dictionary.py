'''
    <A table for searching matching wildcarded entries -- Part of HSA Library>
    Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
    a special exception, as described in included LICENSE_EXCEPTION.txt.
    
Created on Sep 13, 2011

@author: Peyman Kazemian
'''

class wildcard_dictionary(object):
    '''
    classdocs
    '''

    def __init__(self,num_key_bits,threshold):
        '''
        Constructor
        '''
        self.num_key_bits = num_key_bits
        self.threshold = threshold
        self.table = {}
        self.table["value"] = []
        self.table["info"] = []
        for i in range(4**num_key_bits):
            self.table["value"].append([])
            self.table["info"].append((True,[]))
        
    def add_entry_to_table(self,table,key,value,next_keys):
        indices = [0]
        for i in range(self.num_key_bits):
            next_bit = (key >> 2*i) & 0x3
            tmp = []
            for index in indices:
                if next_bit == 0x1:
                    tmp.append(index + 2**(2*i))
                    tmp.append(index + 3*2**(2*i))
                elif next_bit == 0x2:
                    tmp.append(index + 2*2**(2*i))
                    tmp.append(index + 3*2**(2*i))
                else:
                    tmp.append(index + 1*2**(2*i))
                    tmp.append(index + 2*2**(2*i))
                    tmp.append(index + 3*2**(2*i))
            indices = tmp
        for index in indices:
            if table["info"][index][0] == True and (len(table["value"][index]) < self.threshold or len(next_keys) == 0):
                table["value"][index].append(value)
                table["info"][index][1].append(next_keys)
            elif table["info"][index][0] == True:
                new_table = {}
                new_table["value"] = []
                new_table["info"] = []
                for i in range(4**self.num_key_bits):
                    new_table["value"].append([])
                    new_table["info"].append((True,[]))
                for i in range(len(table["value"][index])):
                    new_val = table["value"][index][i]
                    new_keys = table["info"][index][1][i]
                    self.add_entry_to_table(new_table, new_keys[0], new_val, new_keys[1:])
                self.add_entry_to_table(new_table, next_keys[0], value, next_keys[1:])
                table["value"][index] = new_table
                table["info"][index] = (False,[])
            else:
                new_table = table["value"][index]
                self.add_entry_to_table(new_table, next_keys[0], value, next_keys[1:])
            
    def find_entry_in_table(self,table,keys):
        if table["info"][keys[0]][0] == True:
            return table["value"][keys[0]]
        else:
            return self.find_entry_in_table(table["value"][keys[0]], keys[1:])
            
    def add_entry(self,keys,value):
        self.add_entry_to_table(self.table,keys[0],value,keys[1:])
            
    def find_entry(self,keys):
        return self.find_entry_in_table(self.table, keys)

    def self_print_table(self,table,indent):
        idn = ""
        for j in range(indent):
            idn = "%s\t"%idn
        for i in range(len(table["value"])):
            if table["info"][i][0] == False:
                print "%sIndex %x: Table is"%(idn,i)
                self.self_print_table(table["value"][i], indent+1)
            elif len(table["value"][i]) > 0:
                print "%sIndex %x has value %s"%(idn,i,table["value"][i])

    def self_print(self):
        self.self_print_table(self.table, 0)