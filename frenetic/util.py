################################################################################
# The Frenetic Project                                                         #
# frenetic@frenetic-lang.org                                                   #
################################################################################
# Licensed to the Frenetic Project by one or more contributors. See the        #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Frenetic Project licenses this        #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################
# /src/frenetic_util.py                                                        #
# Utility functions                                                            #
################################################################################


from collections import namedtuple
from functools import wraps


# Adapted from http://code.activestate.com/recipes/577629-namedtupleabc-abstract-base-class-mix-in-for-named/
class RecordMeta(type):
    '''The metaclass for the abstract base class + mix-in for named tuples.'''
    def __new__(mcls, name, bases, namespace):
        fields = namespace.get('_fields')

        if isinstance(fields, basestring):
            fields = tuple(fields.split())
            
        for base in bases:
            next_fields = getattr(base, '_fields', None)
            if fields is None:
                fields = next_fields
            elif isinstance(next_fields, tuple):
                fields += next_fields
        
        basetuple = namedtuple("Record_" + name, fields)
        basetuple.__is_namedtuple__ = True
        bases = (basetuple,) + bases 
        namespace.pop('_fields', None)
        namespace["__real_base__"] = basetuple
        namespace["__is_namedtuple__"] = False
        namespace.setdefault('__doc__', basetuple.__doc__)
        namespace.setdefault('__slots__', ())
        
        return type.__new__(mcls, name, bases, namespace)

    def mro(cls):
        oldmro = type.mro(cls)
        found_nt = None
        newmro = []
        for cls in oldmro:
            if getattr(cls, "__is_namedtuple__", False):
                if found_nt is None:
                    found_nt = cls
            else:
                if cls == tuple:
                    newmro.append(found_nt)
                newmro.append(cls)
        return newmro
            

class Record(object):
    '''The abstract base class + mix-in for named tuples.'''
    __metaclass__ = RecordMeta
    _fields = ""

    def __new__(cls, *args, **kwargs):
        return cls.__real_base__.__new__(cls, *args, **kwargs)

        
def Data(fields):
    class _Record(Record):
        _fields = fields
    return _Record

        
def cached(f):
    @wraps(f)
    def wrapper(*args):
        try:
            return wrapper.cache[args]
        except KeyError:
            wrapper.cache[args] = v = f(*args)
            return v
    wrapper.cache = {}
    return wrapper
        
# TODO optimize this
class frozendict(object):
    __slots__ = ["_dict", "_cached_hash"]

    def __init__(self, new_dict=None, **kwargs):
        self._dict = dict()
        if new_dict is not None:
            self._dict.update(new_dict)
        self._dict.update(kwargs)

    def update(self, new_dict=None, **kwargs):
        d = self._dict.copy()
        
        if new_dict is not None:
            d.update(new_dict)    
        d.update(kwargs)
        
        return self.__class__(d)

    def remove(self, *ks):
        d = self._dict.copy()
        for k in ks:
            del d[k]
        return self.__class__(d)
        
    def pop(self, *ks):
        result = []
        for k in ks:
            result.append(self[k])
        result.append(self.remove(*ks))
        return result
      
    def __repr__(self):
        return repr(self._dict)

    def __iter__(self):
        return iter(self._dict)

    def __contains__(self, key):
        return key in self._dict

    def keys(self):
        return self._dict.keys()

    def values(self):
        return self._dict.values()
        
    def items(self):
        return self._dict.items()

    def iterkeys(self):
        return self._dict.iterkeys()

    def itervalues(self):
        return self._dict.itervalues()
        
    def iteritems(self):
        return self._dict.iteritems()

    def get(self, key, default=None):
        return self._dict.get(key, default)

    def __getitem__(self, item):
        return self._dict[item]

    def __hash__(self):
        try:
            return self._cached_hash
        except AttributeError:
            h = self._cached_hash = hash(frozenset(self._dict.items()))
            return h
        
    def __eq__(self, other):
        return self._dict == other._dict

    def __ne__(self, other):
        return self._dict != other._dict
        
    def __len__(self):
        return len(self._dict)

def indent_str(s, indent=4):
    return "\n".join(indent * " " + i for i in s.splitlines())

def repr_plus(ss, indent=4, sep="\n", prefix=""):
    if isinstance(ss, basestring):
        ss = [ss]
    return indent_str(sep.join(prefix + repr(s) for s in ss), indent)
    
class ReprPlusMixin(object):
    """must be used w/ data objects"""

    _mes_attrs = None
    _mes_drop = None
    _repr_plus_args = ()
    
    def __repr__(self):
        mes = self.__squash_mes__()
        
        if self._mes_attrs is None and len(mes) == 1:
            return "%s" % repr(mes[0])
        else:
            return "%s:\n%s" % (self.__class__.__name__, repr_plus(mes, *self._repr_plus_args))
        
    def __squash_mes__(self):
        mes = []
        
        for k, v in self._asdict().iteritems():
            if self._mes_attrs is None:
                cls = self.__class__
            else:
                cls = self._mes_attrs.get(k)
                if cls == 0:
                    cls = self.__class__
            if cls is not None and issubclass(v.__class__, cls):
                mes += v.__squash_mes__()
            elif self._mes_drop is None or not issubclass(v.__class__, self._mes_drop):
                mes.append(v)

        return mes
        
            
def singleton(f):
    return f()
    
