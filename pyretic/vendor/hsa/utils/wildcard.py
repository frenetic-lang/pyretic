'''
Created on Jul 3, 2012

@author: Peyman Kazemian
'''
from c_wildcard import _wildcard_create,_wildcard_copy,\
            _wildcard_to_string,_wildcard_from_string,\
            _wildcard_from_int,\
            _wildcard_logical_and,_wildcard_logical_or,\
            _wildcard_logical_not,_wildcard_isect,\
            _wildcard_compl,_wildcard_diff,_wildcard_rewrite,\
            _wildcard_is_subset,_wildcard_is_equal,\
            _wildcard_set_byte,_wildcard_set_bit,\
            _wildcard_get_byte,_wildcard_get_bit,\
            _wildcard_pickle,_wildcard_unpickle
            

class wildcard(object):
  '''
  A class implementing wildcard expression.
  '''

  def __init__(self,length,pointer):
    '''
    Constructor.
    Don't directly construct it. use provided create methods.
    length: number of 32-bit words in header.
    '''
    self._length = length
    self.pointer = pointer
    
  @property
  def length(self):
    if (self.pointer != None):
      return self._length
    else:
      return 0
      
  def __copy__(self):
    newone = type(self)(self.length,self.pointer)
    newone.__dict__.update(self.__dict__)
    return newone
  
  def __deepcopy__(self,memo):
    newone = type(self)(self.length,self.pointer)
    newone.__dict__.update(self.__dict__)
    if self.pointer != None:
      newone.pointer = _wildcard_copy(self.pointer,self.length) 
    return newone
      
  def __str__(self,pretty=1):
    if self.pointer != None:
      return _wildcard_to_string(self.pointer,self.length,pretty)
    return "empty"
  
  def __len__(self):
    return self.length

  def is_empty(self):
    return self.length == 0
    
  def __getitem__(self,key):
    if key.__class__ == tuple:
      if len(key) == 2:
        if key[0] < self.length and key[1] < 8:
          return _wildcard_get_bit(self.pointer,key[0],key[1],self._length)
        else:
          raise Exception("%s points to an invalid bit"%key)
      else:
        raise Exception("Tuple length should be 2. found %d"%len(key))
    else:
      if key < self.length:
        return _wildcard_get_byte(self.pointer,key,self._length)  
      else:
        raise Exception("Index out of range")
    
  def __setitem__(self,key,value):
    if key.__class__ == tuple:
      if len(key) == 2:
        if key[0] < self.length and key[1] < 8:
          _wildcard_set_bit(self.pointer,value&0x3,key[0],key[1],self._length)
        else:
          raise Exception("%s points to an invalid bit"%key)
      else:
        raise Exception("Tuple length should be 2. found %d"%len(key))
    else:
      if key < self.length:
        _wildcard_set_byte(self.pointer,value & 0xffff,key,self._length)  
      else:
        raise Exception("Index out of range")

  def __setstate__(self,state):
    self._length = state[0]
    if state[1] == None:
      self.pointer = None
    else:
      self.pointer = _wildcard_unpickle(state[1])
  
  def __getstate__(self):
    if self.pointer != None:
      state = [self._length,_wildcard_pickle(self.pointer,self._length)]
    else:
      state = [self._length,None]
    return state

def wildcard_to_str(w):
  if (w):
    return w.__str__(0)
  else:
    return None

def wildcard_create_bit_repeat(length,bit):
  '''
  0: all z
  1: all 0
  2: all 1
  3: all x
  '''
  if bit == 0:
    return wildcard(length,None)
  return wildcard(length,_wildcard_create(length,bit))

def wildcard_create_from_string(string):
  if string == None:
    return None
  if string == "empty":
    return wildcard(0,None)
  if string == "None":
    return None 
  l1 = 8
  l2 = len(string)
  if ',' in string:
    l1 += 1
    l2 += 1
  d = l2/l1
  r = l2%l1
  if r != 0:
    string = "0"*(l2-r) + string
    d += 1
  return wildcard(d,_wildcard_from_string(string))

def wildcard_create_from_int(int_val,length):
  '''
  reads length byte from int_val and converts it to a wildcard object
  '''
  if length <= 0 or length > 8:
    raise Exception("invalid length")
  return wildcard(length,_wildcard_from_int(int_val,length))

def wildcard_copy(w):
  if w.pointer != None:
    return wildcard(w.length,_wildcard_copy(w.pointer,w.length))
  else:
    return wildcard(w.length,None)

def wildcard_and(w1,w2):
  if w1.length != w2.length:
    raise Exception("length mismatch")
  elif w1.length == 0:
    raise Exception("trying to do logical AND with an empty wildcard")
  return wildcard(w1.length,\
        _wildcard_logical_and(w1.pointer,w2.pointer,w1.length))
  
def wildcard_or(w1,w2):
  if w1.length != w2.length:
    raise Exception("length mismatch")
  elif w1.length == 0:
    raise Exception("trying to do logical OR with an empty wildcard")
  return wildcard(w1.length,\
        _wildcard_logical_or(w1.pointer,w2.pointer,w1.length))
  
def wildcard_not(w):
  if w.length == 0:
    raise Exception("trying to do logical NOT on an empty wildcard")
  return wildcard(w.length,\
        _wildcard_logical_not(w.pointer,w.length))
  
def wildcard_intersect(w1,w2):
  if w1._length != w2._length:
    raise Exception("length mismatch")
  elif w1.pointer == None or w2.pointer == None:
    return wildcard(w1._length,None)
  ptr = _wildcard_isect(w1.pointer,w2.pointer,w1.length)
  return wildcard(w1.length,ptr)
  
def wildcard_complement(w):
  if w.length == 0:
    return [wildcard_create_bit_repeat(w._length,3)]
  arr = _wildcard_compl(w.pointer,w.length)
  result = []
  for elem in arr:
    result.append(wildcard(w.length,elem))
  return result

def wildcard_diff(w1,w2):
  '''
  w1-w2
  '''
  if w1._length != w2._length:
    raise Exception("length mismatch")
  elif w1.pointer == None:
    return []
  elif w2.pointer == None:
    return [wildcard_copy(w1)]
  arr = _wildcard_diff(w1.pointer,w2.pointer,w1.length)
  result = []
  for elem in arr:
    result.append(wildcard(w1.length,elem))
  return result

def wildcard_is_equal(w1,w2):
  if w1.length != w2.length:
    return False
  elif w1.pointer == None:
    return True
  elif (_wildcard_is_equal(w1.pointer,w2.pointer,w1.length)):
    return True
  else:
    return False
  
def wildcard_is_subset(w1,w2):
  if w1.length != w2.length:
    return False
  elif w1.pointer == None:
    return True
  elif (_wildcard_is_subset(w1.pointer,w2.pointer,w1.length)):
    return True
  else:
    return False
    
def wildcard_rewrite(w,mask,rewrite):
  if (w.length==mask.length and mask.length==rewrite.length and w.length > 0):
    (p,card) = _wildcard_rewrite(w.pointer,mask.pointer,rewrite.pointer,\
                   w.length)
    return (wildcard(w.length,p), card)
  else:
    raise Exception("length mismatch")
  

