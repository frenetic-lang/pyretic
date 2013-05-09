#!/usr/bin/python

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

from pyretic.core.runtime import Runtime
from pyretic.backend.backend import Backend
import sys
import threading
import signal
import subprocess
from importlib import import_module


def signal_handler(signal, frame):
    for thread in threading.enumerate():
        print (thread,thread.isAlive())
    sys.exit(0)

FRONTEND_ONLY = False
if sys.argv[1] == '-f':
    FRONTEND_ONLY = True
    sys.argv.pop(1)
module_name = sys.argv[1]
kwargs = sys.argv[2:]
module = import_module(module_name)
main = module.main
kwargs = { k : v for [k,v] in [ i.lstrip('--').split('=') for i in kwargs ]}

runtime = Runtime(Backend(),main,False,False,kwargs)
if not FRONTEND_ONLY:
    of_client = subprocess.Popen([sys.executable, 
                                  '/home/mininet/pox/pox.py', 
                                  'of_client.pox_client' ],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

signal.signal(signal.SIGINT, signal_handler)
signal.pause()








