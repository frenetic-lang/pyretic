################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #
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

from pyretic.core.language import identity, match, union, DerivedPolicy, DynamicFilter, FwdBucket, Query, LocalDynamicFilter, LocalDynamicPolicy
import time
import re
import marshal, types
from threading import Thread

class LimitFilter(DynamicFilter):
    """A DynamicFilter that matches the first limit packets in a specified grouping.

    :param limit: the number of packets to be matched in each grouping.
    :type limit: int
    :param group_by: the fields by which to group packets.
    :type group_by: list string
    """
    def __init__(self,limit=None,group_by=[]):
        self.limit = limit
        self.group_by = group_by
        self.seen = {}
        self.done = []
        super(LimitFilter,self).__init__(identity)

    def update_policy(self,pkt):
        if self.group_by:    # MATCH ON PROVIDED GROUP_BY
            pred = match([(field,pkt[field]) for field in self.group_by])
        else:              # OTHERWISE, MATCH ON ALL AVAILABLE GROUP_BY
            pred = match([(field,pkt[field]) 
                              for field in pkt.available_group_by()])
        # INCREMENT THE NUMBER OF TIMES MATCHING PKT SEEN
        try:
            self.seen[pred] += 1
        except KeyError:
            self.seen[pred] = 1

        if self.seen[pred] == self.limit:
            val = {h : pkt[h] for h in self.group_by}
            self.done.append(match(val))
            self.policy = ~union(self.done)

    def __repr__(self):
        return "LimitFilter\n%s" % repr(self.policy)


class LocalLimitFilter(LocalDynamicFilter):
    """A LocalDynamicFilter that matches the first limit packets in a specified grouping.

    :param limit: the number of packets to be matched in each grouping.
    :type limit: int
    :param group_by: the fields by which to group packets.
    :type group_by: list string
    """
    def __init__(self,limit=None,group_by=[]):
        self.limit = limit
        self.group_by = group_by
        self.seen = {}
        self.done = []
        super(LocalLimitFilter,self).__init__(identity)

    def update_policy(self,pkt):
        if self.group_by:    # MATCH ON PROVIDED GROUP_BY
            pred = match([(field,pkt[field]) for field in self.group_by])
        else:              # OTHERWISE, MATCH ON ALL AVAILABLE GROUP_BY
            pred = match([(field,pkt[field]) 
                              for field in pkt.available_group_by()])
        # INCREMENT THE NUMBER OF TIMES MATCHING PKT SEEN
        try:
            self.seen[pred] += 1
        except KeyError:
            self.seen[pred] = 1

        if self.seen[pred] == self.limit:
            val = {h : pkt[h] for h in self.group_by}
            self.done.append(match(val))
            self.policy = ~union(self.done)

    def __repr__(self):
        return "LocalLimitFilter\n%s" % repr(self.policy)


class packets(DerivedPolicy):
    """A FwdBucket preceeded by a LimitFilter.

    :param limit: the number of packets to be matched in each grouping.
    :type limit: int
    :param group_by: the fields by which to group packets.
    :type group_by: list string
    """
    def __init__(self,limit=None,group_by=[]):
        self.group_by = group_by
        self.limit    = limit
        self.callbacks = []
        self.initialize()

    def register_callback(self, func):
        self.callbacks.append(func)

    def notify(self, pkt):
        for callback in self.callbacks:
            callback(pkt)

    def initialize(self):
        limit    = self.limit
        group_by = self.group_by 
        self.fb = FwdBucket()

        if limit is None:
            super(packets,self).__init__(self.fb)
        else:
            self.limit_filter = LimitFilter(limit,group_by)
            self.fb.register_callback(self.limit_filter.update_policy)
            self.fb.register_callback(self.notify)
            super(packets,self).__init__(self.limit_filter >> self.fb)
        
    def __repr__(self):
        return "packets\n%s" % repr(self.policy)

    def __getstate__(self):
        state = self.__dict__.copy()
        def codify_func(c):
            assert(len(c.func_code.co_freevars) == 0)
            return marshal.dumps(c.func_code)

        callbacks = map(codify_func, state['callbacks'])
        state['callbacks'] = callbacks

        del state['fb']
        del state['limit_filter']
        del state['policy']
        return state
    
    def __setstate__(self, state):
        state['callbacks'] = \
            map(
                lambda f: types.FunctionType(marshal.loads(f), globals()), 
                state['callbacks'])

        self.__dict__.update(state)
        self.initialize()


class local_packets(LocalDynamicPolicy, DerivedPolicy):
    """A FwdBucket preceeded by a LimitFilter.

    :param limit: the number of packets to be matched in each grouping.
    :type limit: int
    :param group_by: the fields by which to group packets.
    :type group_by: list string
    """
    def __init__(self,limit=None,group_by=[]):
        self.group_by = group_by
        self.limit    = limit
        self.callbacks = []
        self.initialize()

    def register_callback(self, func):
        self.callbacks.append(func)

    def notify(self, pkt):
        for callback in self.callbacks:
            callback(pkt)

    def initialize(self):
        limit    = self.limit
        group_by = self.group_by 
        self.fb = FwdBucket()

        if limit is None:
            super(local_packets,self).__init__(self.fb)
        else:
            self.limit_filter = LocalLimitFilter(limit,group_by)
            self.fb.register_callback(self.limit_filter.update_policy)
            self.fb.register_callback(self.notify)
            super(packets,self).__init__(self.limit_filter >> self.fb)
        
    def __repr__(self):
        return "packets\n%s" % repr(self.policy)

    def __getstate__(self):
        state = self.__dict__.copy()
        def codify_func(c):
            assert(len(c.func_code.co_freevars) == 0)
            return marshal.dumps(c.func_code)

        callbacks = map(codify_func, state['callbacks'])
        state['callbacks'] = callbacks

        del state['fb']
        del state['limit_filter']
        del state['policy']
        return state
    
    def __setstate__(self, state):
        state['callbacks'] = \
            map(
                lambda f: types.FunctionType(marshal.loads(f), globals()), 
                state['callbacks'])

        self.__dict__.update(state)
        self.initialize()


class AggregateFwdBucket(FwdBucket):
    """An abstract FwdBucket which calls back all registered routines every interval
    seconds (can take positive fractional values) with an aggregate value/dict.
    If group_by is empty, registered routines are called back with a single aggregate
    value.  Otherwise, group_by defines the set of headers used to group counts which
    are then returned as a dictionary."""
    ### init : int -> List String
    def __init__(self, interval, group_by=[]):
        FwdBucket.__init__(self)
        self.interval = interval
        self.group_by = group_by
        if group_by:
            self.aggregate = {}
        else:
            self.aggregate = 0
        
        def report_count(callbacks,aggregate,interval):
            while(True):
                for callback in callbacks:
                    callback(aggregate)
                time.sleep(interval)

        self.query_thread = Thread(target=report_count,args=(self.callbacks,self.aggregate,self.interval))
        self.query_thread.daemon = True
        self.query_thread.start()

    def aggregator(self,aggregate,pkt):
        raise NotImplementedError

    ### update : Packet -> unit
    def update_aggregate(self,pkt):
        if self.group_by:
            from pyretic.core.language import match
            groups = set(self.group_by) & set(pkt.available_fields())
            pred = match([(field,pkt[field]) for field in groups])
            try:
                self.aggregate[pred] = self.aggregator(self.aggregate[pred],pkt)
            except KeyError:
                self.aggregate[pred] = self.aggregator(0,pkt)
        else:
            self.aggregate = self.aggregator(self.aggregate,pkt)

    def eval(self, pkt):
        self.update_aggregate(pkt)
        return set()


class count_packets(AggregateFwdBucket):
    """AggregateFwdBucket that calls back with aggregate count of packets."""
    def aggregator(self,aggregate,pkt):
        return aggregate + 1


class count_bytes(AggregateFwdBucket):
    """AggregateFwdBucket that calls back with aggregate bytesize of packets."""
    def aggregator(self,aggregate,pkt):
        return aggregate + pkt['header_len'] + pkt['payload_len']

class RegexpQuery(Query):
    """
    Class for registering callbacks on matching string in packet data?
    """
    def __init__(self, pattern=""):
        super(RegexpQuery, self).__init__()
        self.re = pattern

    def compile(self):
        """Produce a Classifier for this policy

        :rtype: Classifier
        """
        r = Rule(identity,[Controller])
        return Classifier([r])

    @property
    def re(self):
        return self._re

    @re.setter
    def re(self, pattern):
        if not isinstance(pattern, re._pattern_type):
            pattern = re.compile(pattern, re.S)

        self._re = pattern

    def apply(self):
        with self.bucket_lock:
            for pkt in self.bucket:
                #XXX Should we go with raw data or payload?
                #XXX Logic for iteration here? first match or all of them?
                for m in self.re.finditer(pkt['raw']):
                    for callback in self.callbacks:
                        callback(pkt, m)

            self.bucket.clear()

    def __repr__(self):
        return "RegexpQuery"

    def __eq__(self, other):
        # TODO: if buckets eventually have names, equality should
        # be on names.
        return isinstance(other, RegexpQuery) and (other.re == self.re)




