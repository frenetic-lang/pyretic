
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

import asynchat
import asyncore
import socket

import json

BACKEND_PORT=41414
TERM_CHAR='\n'

def serialize(msg):
    jsonable_msg = to_jsonable_format(msg)
    jsoned_msg = json.dumps(jsonable_msg)
    serialized_msg = jsoned_msg + TERM_CHAR
    return serialized_msg

def deserialize(serialized_msgs):
    def json2python(item):
        if isinstance(item, unicode):
            return item.encode('ascii')
        elif isinstance(item, dict):
            return bytelist2ascii({ 
                    json2python(k) : json2python(v) 
                    for (k,v) in item.items() })
        elif isinstance(item, list):
            return [ json2python(l)
                     for l in item ]
        else:
            return item
    serialized_msg = serialized_msgs.pop(0)
    jsoned_msg = serialized_msg.rstrip(TERM_CHAR)
    msg = None
    while True:
        try:
            msg = json.loads(jsoned_msg)  
            msg = json2python(msg)
            break
        except:
            if len(serialized_msgs) == 0:
                break
            next_part = serialized_msgs.pop(0).rstrip(TERM_CHAR)
            jsoned_msg += next_part
    return msg


def dict_to_ascii(d):
    def convert(h,v):
        if (isinstance(v,str) or
            isinstance(v,int)):
            return v
        elif isinstance(v, unicode):
            return str(v)
        else:
            return repr(v)
    return { h : convert(h,v) for (h,v) in d.items() }


def bytelist2ascii(packet_dict):
    def convert(h,val):
        if h in ['srcmac','dstmac','srcip','dstip','raw']:
            return ''.join([chr(d) for d in val])
        else:
            return val
    return { h : convert(h,val) for (h, val) in packet_dict.items()}


def ascii2bytelist(packet_dict):
    def convert(h,val):
        if h in ['srcmac','dstmac','srcip','dstip','raw']:
            return [ord(c) for c in val]
        else:
            return val
    return { h : convert(h,val) for (h, val) in packet_dict.items()}


def to_jsonable_format(item):
    if isinstance(item, dict):
        ascii_item = dict_to_ascii(item)
        bytelist_item = ascii2bytelist(ascii_item)
        return bytelist_item
    elif isinstance(item, list):
        return map(to_jsonable_format,item)
    else:
        return item
