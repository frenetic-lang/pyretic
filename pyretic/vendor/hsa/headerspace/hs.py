'''
  <Headerspace Class -- Part of HSA Library>
  
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.
  
Created on Jan 24, 2011
Major changes on Jul 2, 2012
Replaced bytearray with wildcard on Jul 9,2012

@author: Peyman Kazemian
'''
from operator import xor
from pyretic.vendor.hsa.utils.wildcard import *
from pyretic.vendor.hsa.utils.wildcard_utils import *
from copy import deepcopy

class headerspace(object):
  '''
  A headerspace object keeps a set of header space regions. it can be union of
  [0,1,x,z] expressions. It can also keep a list of headerspaces to be subtracted
  from this object. The subtraction can be done lazily.
  It also enables normal set operations on header space.
  '''
  
  def __init__(self, length):
    '''
    Constructor
    length is the length of packet headers in bytes.
    '''
    # hs_list: list of all wildcards included.
    # hs_diff: for each wildcard in hs diff, a list of wildcard not
    # included in the headerspace. hs_diff elements should all be a subset 
    # of corresponding element in hs_list.
    self.hs_list = []
    self.hs_diff = []
    # list of (tf,rule_id,port) that has been lazy evaluated
    self.lazy_rules = []
    # list of (tf,rule_id,port) that has been evaluated on this headerspace
    self.applied_rules = []
    self._length = length
    
  @property
  def length(self):
    return self._length
    
  def add_hs(self, value):
    '''
    adds value to the list of headerspaces, hs_list
    @value: wildcard of lenght self.length or another headerspace objects
    '''
    if value.__class__ == wildcard:
      if len(value) != self.length:
        raise Exception("Wildcard length mismatch")
      else:
        self.hs_list.append(wildcard_copy(value))
        self.hs_diff.append([])
    elif value.__class__ == headerspace:
      if value.length != self.length:
        raise Exception("Wildcard length mismatch")
      else:
        self.hs_list.extend(deepcopy(value.hs_list))
        self.hs_diff.append(deepcopy(value.hs_diff))
      
  def add_hs_list(self, values):
    '''
    adds values to the list of headerspaces, hs_list
    @values: list of wildcard of lenght self.length or other headerspace 
    objects of the same length
    '''
    for value in values:
      self.add_hs(value)
    
  def diff_hs(self, value):
    '''
    lazily subtract value from this headerspace
    @value: wildcard of lenght self.length
    '''
    if value.__class__ == wildcard:
      if len(value) != self.length:
        raise Exception("Wildcard length mismatch")
      else:
        for i in range(len(self.hs_list)):
          insect = wildcard_intersect(self.hs_list[i],value)
          if (not insect.is_empty()):
            self.hs_diff[i].append(insect)
    else:
      raise TypeError("Expecting wildcard as input")

  
  def diff_hs_list(self, values):
    '''
    lazily subtract values from this headerspace
    @values: list of wildcard of lenght self.length
    '''
    for value in values:
      if value.__class__ == wildcard:
        if len(value) == self.length:
          self.diff_hs(value)
      
  def count(self):
    '''
    returns count of number of elements in hs_list
    '''
    return len(self.hs_list)
  
  def count_diff(self):
    total = 0
    for diff_list in self.hs_diff:
      total += len(diff_list)
    return total
    
  def copy(self):
    return self.__deepcopy__(None)
  
  def __deepcopy__(self,memo):
    '''
    create a deep copy of itself
    '''
    deep_copy = type(self)(self.length)
    deep_copy.__dict__.update(self.__dict__)
    deep_copy.hs_list = deepcopy(self.hs_list,memo)
    deep_copy.hs_diff = deepcopy(self.hs_diff,memo)
    deep_copy.applied_rules = []
    deep_copy.applied_rules = list(self.applied_rules)
    deep_copy.lazy_rules = deepcopy(self.lazy_rules,memo)
    return deep_copy
  
  def to_string(self):
    '''
    represent a [0,1,x,z] string showing the header space.
    ''' 
    strings = []

    for i in range(len(self.hs_list)):
      hs = self.hs_list[i]
      if len(self.hs_diff[i]) == 1:
        expression = "%s - %s"%(hs,self.hs_diff[i][0])
      elif (len(self.hs_diff[i]) > 1):
        expression = "%s - (\n"%hs
        for d in self.hs_diff[i]:
          expression = "%s  %s U\n"%(expression,d)
        expression = expression[0:-3]
        expression += "\n  )"
      else:
        expression = hs.__str__()
      strings.append(expression)
    
    if len(strings) == 0:
      return "empty"
    else:
      result = ""
      for string in strings:
        result += string
        result += "\nU\n"
      result = result[0:-3]
      return result
    
  def intersect(self, other_hs):
    '''
    intersect itself with other_hs if the header lengths are equal.
    The result will be saved in the caller instance itself.
    @other_fs: @type wildcard or headerspace: the other headerspace to intersect with
    '''
    if other_hs.__class__ == headerspace:
      new_hs_list = []
      new_hs_diff = []
      if self.length != other_hs.length:
        raise Exception("Wildcard length mismatch")
      for i in range(len(self.hs_list)):
        for j in range(len(other_hs.hs_list)):
          isect = wildcard_intersect(self.hs_list[i],other_hs.hs_list[j])
          if not isect.is_empty():
            new_hs_list.append(isect)
            diffs = []
            for diff_hs in self.hs_diff[i]:
              diff_isect = wildcard_intersect(isect,diff_hs)
              if not diff_isect.is_empty():
                diffs.append(diff_isect)
            for diff_hs in other_hs.hs_diff[j]:
              diff_isect = wildcard_intersect(isect,diff_hs)
              if not diff_isect.is_empty():
                diffs.append(diff_isect)
            new_hs_diff.append(diffs)        
      self.hs_list = new_hs_list
      self.hs_diff = new_hs_diff
    
    elif other_hs.__class__ == wildcard:
      new_hs_list = []
      new_hs_diff = []
      if self.length != len(other_hs):
        raise Exception("Wildcard length mismatch")
      for i in range(len(self.hs_list)):
        isect = wildcard_intersect(self.hs_list[i], other_hs)
        if not isect.is_empty() > 0:
          new_hs_list.append(isect)
          new_hs_diff.append([])
          for diff_hs in self.hs_diff[i]:
            diff_isect = wildcard_intersect(diff_hs,isect)
            if not diff_isect.is_empty():
              new_hs_diff[i].append(diff_isect)
      self.hs_list = new_hs_list
      self.hs_diff = new_hs_diff
      
  def copy_intersect(self, other_hs):
    cpy = self.copy()
    cpy.intersect(other_hs)
    return cpy
  
  def complement(self):
    '''
    find the complement of header space pieces saved in hs_list
    and saves it back to itself
    '''
    # if empty, make it all x
    if len(self.hs_list) == 0:
      self.hs_list.append(wildcard_create_bit_repeat(self.length,3))
      self.hs_diff = [[]]
    else:
      c_hs_list = []
      # create one hs object per union element in self.hs_list
      for i in range(len(self.hs_list)):
        tmp = headerspace(self.length)
        c_set = wildcard_complement(self.hs_list[i])
        tmp.add_hs_list(c_set)
        tmp.add_hs_list(self.hs_diff[i])
        c_hs_list.append(tmp)

      result = c_hs_list[0]
      for i in range(1, len(c_hs_list)):
        result.intersect(c_hs_list[i])
      
      self.hs_list = list(result.hs_list)
      self.hs_diff = list(result.hs_diff)
        
  def copy_complement(self):
    cpy = self.copy()
    cpy.complement()
    return cpy
  
  def minus(self, other_fs):
    '''
    computes self - other_fs. note that the hs_diff will be intact
    '''
    cpy = other_fs.copy_complement()
    self.intersect(cpy)
    self.clean_up()
    
  def copy_minus(self, other_fs):
    cpy = self.copy()
    cpy.minus(other_fs)
    return cpy
    
  def self_diff(self):
    '''
    computes hs_list - hs_diff and saves all the result in hs_list.
    '''
    if len(self.hs_diff) == 0:
      return
    new_hs_list = []
    for i in range(len(self.hs_list)):
      incs = headerspace(self.length)
      incs.add_hs(self.hs_list[i])
      difs = headerspace(self.length)
      difs.add_hs_list(self.hs_diff[i])
      incs.minus(difs)
      new_hs_list.extend(incs.hs_list)  

    self.hs_diff = []
    self.hs_list = []
    self.add_hs_list(new_hs_list)
    
  def is_empty(self):
    return (len(self.hs_list) == 0)
    
  def is_subset_of(self, other_fs):
    '''
    checks if self is a subset of other_hs
    '''
    cpy = self.copy()
    cpy.minus(other_fs)
    cpy.self_diff()
    if len(cpy.hs_list) > 0:
      return False
    else:
      return True
    
  def is_contained_in(self,other):
    '''
    checks if self is completely contained in other.
    this is a 'literal' check, rather than actual mathematical check,
    (it may return False when self is a subset of other, but not literally
    has the same fomrat)
    '''
    for i in range(len(self.hs_list)):
      h1 = self.hs_list[i]
      found_hs_eq = False 
      for j in range(len(other.hs_list)):
        h2 = other.hs_list[j]
        if h1 == h2:
          found_diff_eq = False
          for d1 in other.hs_diff[j]:
            for d2 in self.hs_diff[i]:
              if d1 == d2:
                found_diff_eq = True
                break
          if found_diff_eq:
            found_hs_eq = True
            break
      if not found_hs_eq:
        return False
    return True
      
  def clean_up(self):
    '''
    This function cleans up the headerspace partially, by removing all 
    elements un hs_list that subtract out to empty
    '''
    new_hs_list = []
    new_hs_diff = []
    # removes all objects in hs_list that will subtract out to empty
    for i in range(len(self.hs_list)):
      flag = False
      for dh in self.hs_diff[i]:
        if wildcard_is_subset(self.hs_list[i], dh):
          flag = True
      if not flag:
        new_hs_list.append(self.hs_list[i])
        new_hs_diff.append(compress_wildcard_list(self.hs_diff[i]))
    
    self.hs_list = new_hs_list
    self.hs_diff = new_hs_diff
        
          
  def add_lazy_tf_rules(self, ntf, rule_ids, port):
    '''
    a lazy tf rule that should have applied to this rule but has been 
    postponed to next stages.
    '''
    self.lazy_rules.append((ntf, rule_ids, port))
    
  def apply_lazy_tf_rule(self):
    '''
    WARNING: not well-tested
    '''
    result = [self.copy()]
    result[0].lazy_rule = []
    for (ntf, rule_ids, port) in self.lazy_rules:
      temp = []
      for rule_id in rule_ids:
        for elemHS in result:
          temp.extend(ntf.T_rule(rule_id, elemHS, port))
      result = temp;
    return result
         
  def push_applied_tf_rule(self, ntf, rule_id, in_port):
    self.applied_rules.append((ntf, rule_id, in_port))
    
  def pop_applied_tf_rule(self):
    '''
    @return (transfer function, rule_id in the transfer function, 
    input port from whcih the hs is received)
    '''
    return self.applied_rules.pop()
    
  def __str__(self):
    return self.to_string()
    
  
