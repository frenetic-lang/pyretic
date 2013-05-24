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
from pyretic.core.language import match, union, DerivedPredicate, Policy, DerivedPolicy, passthrough

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

class _print(Policy):
    def __init__(self,s='',on=True):
        super(_print,self).__init__()
        self.s = s
        self.on = on


class str_print(_print):
    def eval(self, packet):
        if self.on:
            print self.s
        return {packet}

    def __repr__(self):
        if self.on:
            return "str_print %s" % self.s
        else:
            return ''


class pkt_print(_print):
    def eval(self, packet):
        if self.on:
            print "---- %s -------" % self.s
            print packet
            print "-------------------------------"
        return {packet}

    def __repr__(self):
        if self.on:
            return "pkt_print %s" % self.s
        else:
            return ''


class net_print(_print):
    def eval(self, packet):
        if self.on:
            print "---- net_print %s -------" % self.s
            print self.network
            print "-------------------------------"
        return {packet}

    def __repr__(self):
        if self.on:
            return "net_print %s" % self.s
        else:
            return ''


class pol_print(DerivedPolicy):
    def __init__(self,policy,s='',on=True):
        self.s = s    
        self.on = on
        super(pol_print,self).__init__(policy)

    def eval(self, packet):
        if self.on:
            print self.s 
            print self.policy
        return super(pol_print,self).eval(packet)

    def track_eval(self, packet):
        if self.on:
            print self.s 
            print self.policy
        (result,traversed) = super(pol_print,self).track_eval(packet)
        return (result,[self,traversed])

    def __repr__(self):
        if self.on:
            return "[pol_print %s]\n%s" % (self.s,self.policy)
        else:
            return ''


### TRACING POLICIES

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


class breakpoint(DerivedPolicy):
    ### init : Policy -> Predicate -> unit
    def __init__(self, policy=passthrough, condition=lambda ps: True):
        self.condition = condition
        super(breakpoint,self).__init__(policy)

    def set_network(self, network):
        super(breakpoint,self).set_network(network)
        self.condition.set_network(network)
                    
    def eval(self, packet):
        if self.condition(packet):
            try:
                import ipdb as debugger
            except:
                import pdb as debugger
            debugger.set_trace()
        return DerivedPolicy.eval(self, packet)

    def track_eval(self, packet):
        if self.condition(packet):
            try:
                import ipdb as debugger
            except:
                import pdb as debugger
            debugger.set_trace()
        (result,traversed) = DerivedPolicy.track_eval(self, packet)
        return (result,[self,traversed])        

    def __repr__(self):
        return "***debug***\n%s" % util.repr_plus([self.policy])
