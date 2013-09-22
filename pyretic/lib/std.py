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
from pyretic.core.language import Policy, Filter, DerivedPolicy, identity, all_packets, passthrough, no_packets, match, union
import pyretic.core.util as util
from datetime import datetime

### BREAKPOINT policy
class breakpoint(DerivedPolicy):
    def eval(self, pkt):
        if self.policy.eval(pkt):
            try:
                import ipdb as debugger
            except:
                import pdb as debugger
            debugger.set_trace()
        return {pkt}

    def __repr__(self):
        return "***breakpoint on %s***" % util.repr_plus([self.policy])


### CONVENIENCE policies

class _in(DerivedPolicy,Filter):
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


### PRINTING policies

class _print(Policy):
    def __init__(self,s=''):
        self.s = s
        super(_print,self).__init__()

    def print_str(self,pkt):
        raise NotImplementedError

    def eval(self,pkt):
        print self.print_str(pkt)
        return {pkt}

    def __repr__(self):
        return "[%s %s]" % (self.name(),self.s)

class str_print(_print):
    def print_str(self, pkt):
        return str(datetime.now()) + " | " + self.s

class pkt_print(_print):
    def print_str(self, pkt):
        output_str = ""
        if self.s != '':
            output_str = "---- " + self.s + " -------\n" 
        output_str += str(datetime.now()) + "\n"
        output_str += str(pkt)
        if self.s != '':
            output_str += "\n-------------------------------"
        return output_str

class topo_print(_print):
    def print_str(self, pkt):
        output_str = ""
        if self.s != '':
            output_str = "---- " + self.s + " -------\n" 
        output_str += str(datetime.now()) + "\n"
        output_str += str(self.network.topology)
        if self.s != '':
            output_str += "\n-------------------------------"
        return output_str
