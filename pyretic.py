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
from optparse import OptionParser
import re


def signal_handler(signal, frame):
    for thread in threading.enumerate():
        print (thread,thread.isAlive())
    sys.exit(0)


def parseArgs():
    """Parse command-line args and return options object.
    returns: opts parse options dict"""
    desc = ( 'Pyretic runtime' )
    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    
    end_args = 0
    for arg in sys.argv[1:]:
        if not re.match('-',arg):
            end_args = sys.argv.index(arg)
    kwargs_to_pass = sys.argv[end_args+1:]
    sys.argv = sys.argv[:end_args+1]

    op = OptionParser( description=desc, usage=usage )
    op.add_option( '--frontend-only', '-f', action="store_true", 
                     dest="frontend_only", help = 'only start the frontend'  )
    op.add_option( '--mode', '-m', type='choice',
                     choices=['interpreter','microflow'], 
                     help = '|'.join( ['quiet','verbose'] )  )
    op.add_option( '--verbosity', '-v', type='choice',
                     choices=['quiet','verbose'], default = 'quiet',
                     help = '|'.join( ['quiet','verbose'] )  )

    op.set_defaults(frontend_only=False,mode='interpreter')
    options, args = op.parse_args()
    return (options, args, kwargs_to_pass)


def main():
    (options, args, kwargs_to_pass) = parseArgs()

    module_name = args[0]
    module = import_module(module_name)
    main = module.main
    kwargs = { k : v for [k,v] in [ i.lstrip('--').split('=') for i in kwargs_to_pass ]}

    sys.setrecursionlimit(1500) #INCREASE THIS IF "maximum recursion depth exceeded"
    
    runtime = Runtime(Backend(),main,kwargs,options.mode,False,False)
    if not options.frontend_only:
        of_client = subprocess.Popen([sys.executable, 
                                      '/home/mininet/pox/pox.py', 
                                      'of_client.pox_client' ],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()


if __name__ == '__main__':
    main()





