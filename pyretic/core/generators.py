
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
# author: Christopher Monsanto (chris@monsan.to)                               #
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


"""Generator magic"""

from Queue import Queue
import threading
import weakref
import itertools


# This was using weakrefs, but for simplicity let us just use lists for now.
class Event(object):
    def __init__(self):
        self.listeners = []

    def notify(self, listener):
        self.listeners.append(listener)
        return listener # for decorators
        
    def signal(self, item=None):
        for listener in self.listeners:
            listener(item)
    
    def __iter__(self):
        queue = Queue()
        
        self.notify(queue.put)
        
        def gen():
            while True: yield queue.get()

        return gen()

_property = property
class Behavior(Event):
    def __init__(self, value=None):
        self.value = value
        super(Behavior, self).__init__()

    def get(self):
        return self.value

    def notify(self, listener):
        # Always let the listener know the current value.
        listener(self.value)
        return super(Behavior, self).notify(listener)
        
    def signal(self, value):
        self.value = value
        super(Behavior, self).signal(value)

    set = signal

    def signal_mutation(self):
        super(Behavior, self).signal(self.value)

    @classmethod
    def property(cls, name):
        def get(self):
            return getattr(self, name).get()
        def set(self, value):
            return getattr(self, name).set(value)
        return _property(get, set)

        
# The ever famous generator multiplexer, courtesy of 
# http://www.dabeaz.com/generators/genmulti.py
def merge(*genlist):
    """Merge a list of generators."""
    
    item_q = Queue()
    
    def run_one(source):
        for item in source: item_q.put(item)

    def run_all():
        thrlist = []
        for source in genlist:
            t = threading.Thread(target=run_one, args=(source,))
            t.setDaemon(True)
            t.start()
            thrlist.append(t)
        for t in thrlist: t.join()
        item_q.put(StopIteration)

    t = threading.Thread(target=run_all)
    t.setDaemon(True)
    t.start()
    
    while True:
        item = item_q.get()
        if item is StopIteration: return
        yield item


def tag(gen, value):
    for v in gen:
        yield (value, v)
        
def merge_hold(*genlist):
    iters = map(iter, genlist)
    values = []
    
    for i in iters:
        try:
            values.append(i.next())
        except StopIteration:
            pass
    yield tuple(values)
    
    gens = map(tag, iters, xrange(len(iters)))
    for (i, v) in merge(*gens):
        values[i] = v
        yield tuple(values)

def run_non_daemon(func, *args, **kwargs):
    t = threading.Thread(target=func, args=args, kwargs=kwargs)
    t.start()
    return func
        
def run(func, *args, **kwargs):
    t = threading.Thread(target=func, args=args, kwargs=kwargs)
    t.setDaemon(True)
    t.start()
    return func



