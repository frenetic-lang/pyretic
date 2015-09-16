################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
# author: Cole Schlesinger (cschlesi@cs.princeton.edu)                         #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
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

from functools import wraps

from multiprocessing import Lock
from logging import StreamHandler
import sys
from ipaddr import IPv4Network, AddressValueError, IPv4Address


def singleton(f):
    return f()

class SingletonMetaclass(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonMetaclass, cls).__call__(
                *args, **kwargs)
        return cls._instances[cls]

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

    def remove(self, ks):
        d = self._dict.copy()
        for k in ks:
            if k in d:
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

class LockStreamHandler(StreamHandler):
    '''Relies on a multiprocessing.Lock to serialize multiprocess writes to a
    stream.'''
    
    def __init__(self, lock, stream=sys.stderr):
        self.lock = lock
        super(MultiprocessStreamHandler, self).__init__(stream)

    def emit(self, record):
        '''Acquire the lock before emitting the record.'''
        self.lock.acquire()
        super(LockStreamHandler, self).emit(record)
        self.lock.release()

class QueueStreamHandler(StreamHandler):
    '''Relies on a multiprocessing.Lock to serialize multiprocess writes to a
    stream.'''
    
    def __init__(self, queue, stream=sys.stderr):
        self.queue = queue
        super(QueueStreamHandler, self).__init__(stream)

    def emit(self, record):
        '''Acquire the lock before emitting the record.'''
        self.queue.put(record)

def string_to_network(ip_str):
    """ Return an IPv4Network object from a dotted quad IP address/subnet. """
    try:
        return IPv4Network(ip_str)
    except AddressValueError:
        raise TypeError('Input not a valid IP address!')

def string_to_IP(ip_str):
    try:
        return IPv4Address(ip_str)
    except AddressValueError:
        raise TypeError('Input not a valid IP address!')

def network_to_string(ip_net):
    """ Return a dotted quad IP address/subnet from an IPv4Network object. """
    assert isinstance(ip_net, IPv4Network)
    if ip_net.prefixlen < 32:
        return str(ip_net.network) + '/' + str(ip_net.prefixlen)
    else:
        return str(ip_net.ip)
