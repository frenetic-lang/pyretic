
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


class Event(object):
    def __init__(self):
        self.waiting_queue = Queue()
        self.queues = weakref.WeakSet()

    def signal(self, item):
        for queue in self.queues:
            queue.put(item)
        
    def __iter__(self):
        queue = Queue()
        self.queues.add(queue)
        
        def event_iter():
            while True: yield queue.get()
            
        return event_iter()        
            
        
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
            t.start()
            thrlist.append(t)
        for t in thrlist: t.join()
        item_q.put(StopIteration)

    threading.Thread(target=run_all).start()
    while True:
        item = item_q.get()
        if item is StopIteration: return
        yield item

def run(func, *args, **kwargs):
    t = threading.Thread(target=func, args=args, kwargs=kwargs)
    t.start()

