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

from pyretic.core.language import identity, match, union, DerivedPolicy, DynamicFilter, FwdBucket, Query
import time
import re
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


class packets(DerivedPolicy):
    """A FwdBucket preceeded by a LimitFilter.

    :param limit: the number of packets to be matched in each grouping.
    :type limit: int
    :param group_by: the fields by which to group packets.
    :type group_by: list string
    """
    def __init__(self,limit=None,group_by=[]):
        self.fb = FwdBucket()
        self.register_callback = self.fb.register_callback
        if limit is None:
            super(packets,self).__init__(self.fb)
        else:
            self.limit_filter = LimitFilter(limit,group_by)
            self.fb.register_callback(self.limit_filter.update_policy)
            super(packets,self).__init__(self.limit_filter >> self.fb)
        
    def __repr__(self):
        return "packets\n%s" % repr(self.policy)


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




