
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


class DelayedEvent(Event):
    def __init__(self, delayed_items):
        self.delayed_items = delayed_items
        super(DelayedEvent, self).__init__()

    def notify(self, listener):
        for item in self.delayed_items:
            listener(item)
        return super(DelayedEvent, self).notify(listener)

        
class Behavior(Event):
    def __init__(self, value=None):
        self.value = value
        super(Behavior, self).__init__()

    def get(self):
        return self.value

    def signal(self, value):
        self.value = value
        super(Behavior, self).signal(value)

    set = signal


        
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
        values.append(i.next())
    yield tuple(values)
    
    gens = map(tag, iters, xrange(len(genlist)))
    for (i, v) in merge(*gens):
        values[i] = v
        yield tuple(values)

def run_non_daemon(func, *args, **kwargs):
    t = threading.Thread(target=func, args=args, kwargs=kwargs)
    t.start()
        
def run(func, *args, **kwargs):
    t = threading.Thread(target=func, args=args, kwargs=kwargs)
    t.setDaemon(True)
    t.start()



