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

"""Pyretic Query Library"""
from pyretic.core.language import Policy, DynamicPolicy, FwdBucket, DerivedPolicy, match, all_packets, EvalTrace
import time
from threading import Thread

class packets(DynamicPolicy):
    """Effectively a FwdBucket which calls back all registered routines on each 
    packet evaluated.
    A positive integer limit will cause callback to cease after limit packets of
    a given group have been seen.  group_by defines the set of headers used for 
    grouping - two packets are in the same group if they match on all headers in the
    group_by.  If no group_by is specified, the default is to match on all available
    headers."""
    class FilterWrappedFwdBucket(Policy):
        def __init__(self,limit=None,group_by=[]):
            self.limit = limit
            self.group_by = group_by
            self.seen = {}
            self.fwd_bucket = FwdBucket()
            self.register_callback = self.fwd_bucket.register_callback
            super(packets.FilterWrappedFwdBucket,self).__init__()

        def eval(self,pkt):
            if not self.limit is None:
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

                if self.seen[pred] > self.limit:
                    return set()
            self.fwd_bucket.eval(pkt)
            return {pkt}
        
    def __init__(self,limit=None,group_by=[]):
        self.limit = limit
        self.seen = {}
        self.group_by = group_by
        self.pwfb = self.FilterWrappedFwdBucket(limit,group_by)
        self.register_callback = self.pwfb.register_callback
        super(packets,self).__init__(all_packets)

    def eval(self,pkt):
        """Don't look any more such packets"""
        if self.policy.eval(pkt) and not self.pwfb.eval(pkt):
            val = {h : pkt[h] for h in self.group_by}
            self.policy = ~match(val) & self.policy
        return set()

    def track_eval(self,pkt,dry):
        """Don't look any more such packets"""
        eval_trace = EvalTrace(self)
        (results,trace) = self.policy.track_eval(pkt,dry)
        eval_trace.add_trace(trace)
        if results: 
            if not dry:
                (results,trace) = self.pwfb.track_eval(pkt,dry)
                eval_trace.add_trace(trace)
                if not results:
                    val = {h : pkt[h] for h in self.group_by}
                    self.policy = ~match(val) & self.policy
            else:
                eval_trace.add_trace(EvalTrace(self.pwfb))
        return (set(),eval_trace)

    def compile(self):
        classifier = ((self.policy >> self.pwfb.fwd_bucket) + ~self.policy).compile()
        return classifier

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

    def track_eval(self, pkt, dry):
        if dry:
            return (set(), EvalTrace(self))
        else:
            return (self.eval(pkt), EvalTrace(self))


class count_packets(AggregateFwdBucket):
    """AggregateFwdBucket that calls back with aggregate count of packets."""
    def aggregator(self,aggregate,pkt):
        return aggregate + 1


class count_bytes(AggregateFwdBucket):
    """AggregateFwdBucket that calls back with aggregate bytesize of packets."""
    def aggregator(self,aggregate,pkt):
        return aggregate + pkt['header_len'] + pkt['payload_len']
