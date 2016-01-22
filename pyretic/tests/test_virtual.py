################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
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

""" Fresh tests for the overhauled virtual header implementation. """
from pyretic.core.language import *
from pyretic.core.runtime import virtual_field
from pyretic.lib.corelib import *
from pyretic.lib.std import *
import inspect

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')

def start_new_test():
    print "**** Test %s" % inspect.stack()[1][3]
    virtual_field.clear()

def test_single_field_1():
    start_new_test()
    virtual_field("test1", range(0, 10), type="integer")
    m = match(test1=4, srcip=ip1)
    print m.compile()

def test_single_field_2():
    start_new_test()
    virtual_field("test2", range(0,15), type="integer")
    m = match(test2=4, srcip=ip1)
    print m.compile()

def test_single_field_3():
    start_new_test()
    virtual_field("test3", range(0,16), type="integer")
    m = match(test3=4, srcip=ip1)
    print m.compile()

def test_single_stage_1():
    start_new_test()
    virtual_field("field11", range(0, 10), type="integer")
    virtual_field("field12", range(1, 5), type="integer")
    m1 = match(field11=4, field12=3, srcip=ip2)
    print m1.compile()
    m2 = match(field11=4, srcip=ip2)
    print m2.compile()
    m3 = match(srcip=ip3)
    print m3.compile()

if __name__ == "__main__":
    test_single_field_1()
    test_single_field_2()
    test_single_field_3()
    test_single_stage_1()
