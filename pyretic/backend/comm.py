################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Joshua Reich (jreich@cs.princeton.edu)                               #

################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Core Project licenses this        #
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
    jsoned_msg = json.dumps(msg)
    serialized_msg = jsoned_msg + TERM_CHAR
    return serialized_msg

def deserialize(serialized_msgs):
    def json2python(item):
        if isinstance(item, unicode):
            return item.encode('ascii')
        elif isinstance(item, dict):
            return { json2python(k) : json2python(v) 
                     for (k,v) in item.items() }
        elif isinstance(item, list):
            return [ json2python(l)
                     for l in item ]
        else:
            return item
    serialized_msg = serialized_msgs.pop(0)
    jsoned_msg = serialized_msg.rstrip(TERM_CHAR)
    try:
        msg = json.loads(jsoned_msg)  
    except:
        p2 = serialized_msgs.pop(0).rstrip(TERM_CHAR)
        try:
            msg = json.loads(jsoned_msg+p2)
        except:
            raise RuntimeError("BAD MSG IN!!!!")
    msg = json2python(msg)
    return msg


def bytelist2ascii(packet_dict):
    def convert(h,val):
        if h in ['srcmac','dstmac','srcip','dstip','payload']:
            return ''.join([chr(d) for d in val])
        else:
            return val
    return { h : convert(h,val) for (h, val) in packet_dict.items()}


def ascii2bytelist(packet_dict):
    def convert(h,val):
        if h in ['srcmac','dstmac','srcip','dstip','payload']:
            return [ord(c) for c in val]
        else:
            return val
    return { h : convert(h,val) for (h, val) in packet_dict.items()}
