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

"""Pyretic Standard Library"""
from pyretic.core.language import match, union, DerivedPredicate, Policy, DerivedPolicy, passthrough, all_packets, no_packets
import pyretic.core.util as util
from datetime import datetime

### DEFINITIONS
ARP_TYPE = 2054

### CONVENIENCE PREDICATES

class _in(DerivedPredicate):
    def __init__(self,field,group):
        self.group = group
        self.field = field
        super(_in,self).__init__(union([match({field : i}) 
                                for i in group]))
    def __repr__(self):
        return "_in: %s" % self.group


class switch_in(_in):
    def __init__(self,switches):
        super(switch_in,self).__init__('switch',switches)

    def __repr__(self):
        return "switch%s" % super(switch_in,self).__repr__()


class dstip_in(_in):
    def __init__(self,dstips):
        super(dstip_in,self).__init__('dstip',dstips)

    def __repr__(self):
        return "dstip%s" % super(dstip_in,self).__repr__()


### PRINTING POLICIES

class _print(DerivedPolicy):
    def __init__(self,s='',condition=all_packets, policy=passthrough):
        self.s = s
        self.condition = condition
        super(_print,self).__init__(policy)

    def print_fn(self,packet):
        raise NotImplementedError        

    def eval(self, packet):
        if self.condition.eval(packet):
            self.print_fn(packet)
        return super(_print,self).eval(packet)

    def track_eval(self, packet):
        if self.condition.eval(packet):
            self.print_fn(packet)
        return super(_print,self).track_eval(packet)

    def __repr__(self):
        if self.condition == no_packets:
            return ''
        else:
            return "[%s %s %s]" % (self.name(),self.condition,self.s)


class str_print(_print):
    def print_fn(self, packet):
        print str(datetime.now()),
        print " | ",
        print self.s


class pkt_print(_print):
    def print_fn(self, packet):
        if self.s != '':
            print "---- %s -------" % self.s
        print str(datetime.now())
        print packet
        if self.s != '':
            print "-------------------------------"


class topo_print(_print):
    def print_fn(self, packet):
        if self.s != '':
            print "---- %s -------" % self.s
        print str(datetime.now())
        print self.network.topology
        if self.s != '':
            print "-------------------------------"


class pol_print(_print):
    def __init__(self,policy,s='',condition=all_packets):
        super(pol_print,self).__init__(s,condition,policy)

    def print_fn(self,packet):
        if self.s != '':
            print "---- %s -------" % self.s
        print str(datetime.now())
        print self.policy
        if self.s != '':
            print "-------------------------------"

    def __repr__(self):
        if self.condition == no_packets:
            return ''
        else:
            return "[pol_print %s %s]\n%s" % (self.condition,self.s,self.policy)


### TRACING POLICIES


class breakpoint(DerivedPolicy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, condition=all_packets, policy=passthrough):
        self.condition = condition
        super(breakpoint,self).__init__(policy)

    def set_network(self, network):
        super(breakpoint,self).set_network(network)
        self.condition.set_network(network)
                    
    def eval(self, packet):
        if self.condition.eval(packet):
            try:
                import ipdb as debugger
            except:
                import pdb as debugger
            debugger.set_trace()
        return self.policy.eval(packet)

    def track_eval(self, packet):
        if self.condition.eval(packet):
            try:
                import ipdb as debugger
            except:
                import pdb as debugger
            debugger.set_trace()
        (result,traversed) = self.policy.track_eval(packet)
        return (result,[self,traversed])        

    def __repr__(self):
        return "***breakpoint on %s***\n%s" % (self.condition,util.repr_plus([self.policy]))


class trace(DerivedPolicy):
    def __init__(self,policy,trace_name='trace'):
        self.trace_name = trace_name
        self.highest_trace_value = {}
        super(trace,self).__init__(policy)

    def eval(self, packet):
        v = packet.get_stack(self.trace_name)
        try:
            i = self.highest_trace_value[v]
        except:
            i = 0
        output = super(trace,self).eval(packet)
        if len(output) > 1:
            tagged_output = set()
            for packet in output:
                tagged_output.add(packet.pushmany({self.trace_name : i}))
                i = i + 1
                self.highest_trace_value[v] = i
            return tagged_output
        else:
            return output

    def track_eval(self, packet):
        v = packet.get_stack(self.trace_name)
        try:
            i = self.highest_trace_value[v]
        except:
            i = 0
        (output,traversed) = super(trace,self).track_eval(packet)
        if len(output) > 1:
            tagged_output = set()
            for packet in output:
                tagged_output.add(packet.pushmany({self.trace_name : i}))
                i = i + 1
                self.highest_trace_value[v] = i
            return (tagged_output,[self,traversed])
        else:
            return (output,[self,traversed])

    def __repr__(self):
        return "[%s]\n%s" % (self.trace_name,self.policy)


class clear_trace(Policy):
    def __init__(self,trace_name='trace'):
        self.trace_name=trace_name
        super(clear_trace,self).__init__()

    def eval(self, packet):
        return {packet.clear(self.trace_name)}
