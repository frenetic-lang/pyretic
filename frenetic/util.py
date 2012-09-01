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

from time import time
import sys as sys
from abc import ABCMeta, abstractproperty
from collections import namedtuple

# XXX why this over TypeError or ValueError?
class IllegalArgument(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


def current_time():
    """current_time in seconds"""
    return int(time())


# XXX hacky? at least move to lib or something.
class FRef:
    """Reference cells"""
    def __init__(self):
        self.x = None
    def get(self):
        return self.x
    def set(self, x):
        self.x = x


def add_pair(p1, p2):
    """Addition lifted to pairs"""
    (x1, y1) = p1 
    (x2, y2) = p2
    return (x1 + x2, y1 + y2)

def sub_pair(p1, p2):
    """Subtraction lifted to pairs"""
    (x1, y1) = p1 
    (x2, y2) = p2
    return (x1 - x2, y1 - y2)


# Adapted from http://peter-hoffmann.com/2010/extrinsic-visitor-pattern-python-inheritance.html
class Case(object):
    def __call__(self, node, *args, **kwargs):
        meth = None
        for cls in node.__class__.__mro__:
            meth_name = 'case_'+cls.__name__
            meth = getattr(self, meth_name, None)
            if meth:
                break

        if not meth:
            meth = self.generic_case
        return meth(node, *args, **kwargs)

    def generic_case(self, *args, **kwargs):
        raise ValueError

# Adapted from http://code.activestate.com/recipes/577629-namedtupleabc-abstract-base-class-mix-in-for-named/
class RecordMeta(ABCMeta):
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
            
        if not isinstance(fields, abstractproperty):
            basetuple = namedtuple("Record", fields)
            bases = (basetuple,) + bases
            namespace.pop('_fields', None)
            namespace["__real_base__"] = basetuple
            namespace.setdefault('__doc__', basetuple.__doc__)
            namespace.setdefault('__slots__', ())
        return ABCMeta.__new__(mcls, name, bases, namespace)


class Record(object):
    '''The abstract base class + mix-in for named tuples.'''
    __metaclass__ = RecordMeta
    _fields = abstractproperty()

    def __new__(cls, *args, **kwargs):
        return cls.__real_base__.__new__(cls, *args, **kwargs)

    def asdict(self):
        return self._asdict()
        
    def replace(self, **kwargs):
        return self._replace(**kwargs)

    def make(self, iterable):
        return self._make(iterable)

    

def Data(fields):
    class _Record(Record):
        _fields = fields
    return _Record


# TODO optimize this
class frozendict(object):
    __slots__ = ["_dict"]

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
        
        return frozendict(d)

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

    def __len__(self):
        return len(self._dict)
        
