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
    print "**** Test %s" % inspect.stack()[1][3],
    virtual_field.clear()

def vdict(**kw):
    """ Get the compiled field=value dictionary from a match specification. """
    return match(**kw).compile().rules[0].match.map

def success():
    print "PASS"

def test_single_field_1():
    start_new_test()
    virtual_field("test1", range(0, 10), type="integer")
    m = vdict(test1=4, srcip=ip1)
    assert m['vlan_id'] == 4
    assert m['vlan_total_stages'] == 1
    assert m['vlan_nbits'] == 4
    success()

def test_single_field_2():
    start_new_test()
    virtual_field("test2", range(0,15), type="integer")
    m = vdict(test2=14, srcip=ip1)
    assert (m['vlan_id'] == 14 and m['vlan_total_stages'] == 1 and
            m['vlan_nbits'] == 4)
    success()

def test_single_field_3():
    start_new_test()
    virtual_field("test3", range(0,16), type="integer")
    m = vdict(test3=4, srcip=ip1)
    assert m['vlan_id'] == 4 and m['vlan_nbits'] == 5
    success()

def test_single_stage_1():
    start_new_test()
    virtual_field("field11", range(0, 10), type="integer")
    virtual_field("field12", range(0, 5), type="integer")
    m1 = vdict(field11=0, field12=0, srcip=ip2)
    assert m1['vlan_id'] == 0 and m1['vlan_nbits'] == 7
    m2 = vdict(field11=4, field12=3, srcip=ip2)
    assert m2['vlan_id'] == 27
    m3 = vdict(field11=4, srcip=ip2)
    assert m3['vlan_id'] == 29
    m4 = vdict(srcip=ip3)
    assert not 'vlan_id' in m4
    success()

def test_single_stage_2():
    start_new_test()
    virtual_field("field11", range(0, 10), type="integer", stage=4)
    virtual_field("field12", range(0, 5), type="integer", stage=4)
    m1 = vdict(field11=0, field12=0, srcip=ip2)
    assert m1['vlan_id'] == 0 and m1['vlan_nbits'] == 7
    m2 = vdict(field11=4, field12=3, srcip=ip2)
    assert m2['vlan_id'] == 27
    m3 = vdict(field11=4, srcip=ip2)
    assert m3['vlan_id'] == 29
    m4 = vdict(srcip=ip3)
    assert not 'vlan_id' in m4
    success()

def test_multi_stage_1():
    start_new_test()
    virtual_field("field11", range(0,10), type="integer", stage=0)
    virtual_field("field12", range(0, 5), type="integer", stage=0)
    virtual_field("field2", range(0, 15), type="integer", stage=1)
    m1 = vdict(field11=4, field12=3, srcip=ip1)
    assert (m1['vlan_total_stages'] == 2 and m1['vlan_id'] == 27 and
            m1['vlan_offset'] == 0 and m1['vlan_nbits'] == 7)
    m2 = vdict(field2=2, dstip=ip3)
    assert m2['vlan_total_stages'] == 2
    assert m2['vlan_offset'] == 7
    assert m2['vlan_nbits'] == 4
    assert m2['vlan_id'] == 2 << 7
    success()

def test_multi_stage_2():
    start_new_test()
    virtual_field("field11", range(0,10), type="integer", stage=0)
    virtual_field("field21", range(0,10), type="integer", stage=1)
    virtual_field("field12", range(0, 5), type="integer", stage=0)
    virtual_field("field22", range(0, 5), type="integer", stage=1)
    m1 = vdict(field11=0, field12=0, srcip=ip1)
    assert m1['vlan_total_stages'] == 2
    assert m1['vlan_id'] == 0
    assert m1['vlan_offset'] == 0
    assert m1['vlan_nbits'] == 7
    m2 = vdict(field21=4, field22=3, dstip=ip3)
    assert m2['vlan_total_stages'] == 2
    assert m2['vlan_offset'] == 7
    assert m2['vlan_nbits'] == 7
    assert m2['vlan_id'] == (27 << 7) & ((1<<12)-1) # least 12 bits
    assert m2['vlan_pcp'] == ((27 << 7) >> 12) & ((1<<3)-1) # highest 3 bits
    success()

def test_decode():
    start_new_test()
    virtual_field("field11", range(0,10), type="integer", stage=0)
    virtual_field("field21", range(0,10), type="integer", stage=1)
    virtual_field("field12", range(0, 5), type="integer", stage=0)
    virtual_field("field22", range(0, 5), type="integer", stage=1)
    vlan_16bit = 2 + (27 << 7)
    vals = {'vlan_id': vlan_16bit & ((1<<12)-1),
            'vlan_pcp': (vlan_16bit >> 12) & ((1<<3)-1)}
    m = virtual_field.expand(vals)
    assert 'field11' in m and m['field11'] == 0
    assert 'field12' in m and m['field12'] == 2
    assert 'field21' in m and m['field21'] == 4
    assert 'field22' in m and m['field22'] == 3
    vlan_16bit = 2 + (29 << 7)
    vals = {'vlan_id': vlan_16bit & ((1<<12)-1),
            'vlan_pcp': (vlan_16bit >> 12) & ((1<<3)-1)}
    m = virtual_field.expand(vals)
    assert 'field11' in m and m['field11'] == 0
    assert 'field12' in m and m['field12'] == 2
    assert 'field21' in m and m['field21'] == 4
    assert 'field22' in m and m['field22'] == None
    success()

def test_multi_stage_3():
    start_new_test()
    virtual_field("field1",  range(0,10), type="integer", stage=0)
    virtual_field("field21", range(0,10), type="integer", stage=1)
    virtual_field("field22", range(0, 4), type="integer", stage=1)
    virtual_field("field3",  range(0, 5), type="integer", stage=2)
    m1 = vdict(field21=5, field22=3, srcip=ip1)
    assert m1['vlan_id'] == 28 << 4
    assert m1['vlan_offset'] == 4
    assert m1['vlan_nbits'] == 6
    assert m1['vlan_total_stages'] == 3
    m2 = vdict(field3=4, dstip=ip3)
    vlan_16bit = 4 << 10
    assert m2['vlan_id'] == vlan_16bit & ((1<<12)-1)
    assert m2['vlan_pcp'] == vlan_16bit >> 12
    assert m2['vlan_offset'] == 10
    assert m2['vlan_nbits'] == 3
    success()

if __name__ == "__main__":
    test_single_field_1()
    test_single_field_2()
    test_single_field_3()
    test_single_stage_1()
    test_single_stage_2()
    test_multi_stage_1()
    test_multi_stage_2()
    test_decode()
    test_multi_stage_3()
