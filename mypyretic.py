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


import sys
import threading
import signal
import subprocess
from importlib import import_module
from optparse import OptionParser
import re
import os
import datetime

of_client = None

def signal_handler(signal, frame):
    print '\n----starting pyretic shutdown------'
#    for thread in threading.enumerate():
#        print (thread,thread.isAlive())
    if of_client != None:
      print "attempting to kill of_client"
      of_client.kill()
      print "attempting get output of of_client:"
      output = of_client.communicate()[0]
      print output
      
    print "pyretic.py done"
    sys.exit(0)

def buildOptions():
    desc = ( 'Pyretic runtime' )
    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    op = OptionParser( description=desc, usage=usage )
    op.add_option( '--frontend-only', '-f', action="store_true", 
                     dest="frontend_only", help = 'only start the frontend'  )
    op.add_option( '--mode', '-m', type='choice',
                     choices=['interpreted','i','reactive0','r0'], 
                     help = '|'.join( ['interpreted/i','reactive0/r0'] )  )
    op.add_option( '--verbosity', '-v', type='choice',
                     choices=['low','normal','high'], default = 'low',
                     help = '|'.join( ['quiet','high'] )  )
    op.add_option('--port', '-p', action = 'store', type   = 'int',
                   dest   = "listenPort", default= 6633,
                   help   = 'set listenPort')
    
    from tools.comm import BACKEND_PORT
                   
    op.add_option('--backendPort', '-P', action = 'store', type   = 'int',
                   dest   = "backendPort", default= BACKEND_PORT,
                   help   = 'set backendPort')
                   
    localHost = '127.0.0.1'
    
    op.add_option('--listenIP', '-i', action = 'store', type   = 'string',
                   dest   = "listenIP", default= '0.0.0.0',
                   help   = 'set listenIP')
    op.add_option('--backendIP', '-I', action = 'store', type   = 'string',
                   dest   = "backendIP", default= localHost,
                   help   = 'set backendIP')

    op.add_option('--client', '-c', action = 'store', type   = 'string',
                   dest   = "client", default= 'pox_client',
                   help   = 'use this OF client')

    op.add_option('--logDirName', '-d', action = 'store', type   = 'string',
                   dest   = "logDirName", default= 'pyretic',
                   help   = 'set log dir name')

    op.add_option('--logLevel', '-l', action = 'store', type   = 'int',
                   dest   = "logLevel", default= 100,
                   help   = 'set log level')

    op.add_option( '--ofclient-only', '-o', action="store_true", 
                     dest="ofclient_only", help = 'only start the OF client'  )

    op.add_option( '--echoServer', '-e', action="store_true", 
                     dest="useEchoServer", help = 'use EchoServer for testing'  )

    op.set_defaults(frontend_only=False,mode='reactive0')
    options, args = op.parse_args()

    return op, options, args
    
def parseArgs():
    """Parse command-line args and return options object.
    returns: opts parse options dict"""
    
    end_args = 0
    for arg in sys.argv[1:]:
        if not re.match('-',arg):
            end_args = sys.argv.index(arg)
    kwargs_to_pass = None
    if end_args > 0:
        kwargs_to_pass = sys.argv[end_args+1:]
        sys.argv = sys.argv[:end_args+1]

    op, options, args = buildOptions()

    if options.mode == 'i':
        options.mode = 'interpreted'
    elif options.mode == 'r0':
        options.mode = 'reactive0'
        
    
    return (op, options, args, kwargs_to_pass)

def getPaths():
  try:
    output = subprocess.check_output('echo $PYTHONPATH',shell=True).strip()
    
  except:
    print 'Error: Unable to obtain PYTHONPATH'
    sys.exit(1)

  poxpath = None
  pyreticpath = None
  mininetpath = None
  
  for p in output.split(':'):
     if re.match('.*pox/?$',p):
       poxpath = os.path.abspath(p)
       
     elif re.match('.*pyretic/?$',p):
       pyreticpath = os.path.abspath(p)

     elif re.match('.*mininet/?$',p):
       mininetpath = os.path.abspath(p)

  # print("poxpath=%s pyreticpath=%s mininetpath=%s" %(poxpath, pyreticpath, mininetpath))
  
  return (poxpath, pyreticpath, mininetpath)
  
def emptyLogDir(logDir):  
  for the_file in os.listdir(logDir):
    file_path = os.path.join(logDir, the_file)
    
    try:
      if os.path.isfile(file_path):
        os.unlink(file_path)
            
    except Exception, e:
      print e

def setPyreticEnv(pyreticpath, options):

  datetimeNow = datetime.datetime.now()
  dateNow     = datetimeNow.strftime("%Y-%m-%d")
  timeNow     = datetimeNow.strftime("%H:%M:%S.%f")
  
  pyreticLogsDir = "%s/%s" % (pyreticpath, "logs")
  logDirPathName = "%s/%s/%s" % (pyreticLogsDir, dateNow, options.logDirName)
      
  # print("logDirPathName=%s logLevel=%s" % (logDirPathName, options.logLevel))
  
  if not os.path.isdir(logDirPathName):
    os.makedirs(logDirPathName)

  else:
    emptyLogDir(logDirPathName)  
    
  os.environ["PYRETICLOGDIR"]   = logDirPathName
  os.environ["PYRETICLOGLEVEL"] = str(options.logLevel)

def getModuleName(op, args):
    try:
        return(args[0])
        
    except IndexError:
        print 'Module must be specified'
        print ''
        op.print_usage()
        sys.exit(1)
        
def getMainModule(op, args):
    module_name = getModuleName(op, args)

    try:
        module = import_module(module_name)
        return module.main
        
    except ImportError:
        print 'Must be a valid python module'
        print 'e.g, full module name,'
        print '     no .py suffix,'
        print '     located on the system PYTHONPATH'
        print ''
        op.print_usage()
        sys.exit(1)

def startRuntime(op, options, args, kwargs_to_pass):
    main = getMainModule(op, args)
    kwargs = { k : v for [k,v] in [ i.lstrip('--').split('=') for i in kwargs_to_pass ]}

    sys.setrecursionlimit(1500) #INCREASE THIS IF "maximum recursion depth exceeded"
    
    from pyretic.backend.backend import Backend
    from pyretic.backend.BackendServer import BackendServer
    
    if options.useEchoServer:
      backEnd = BackendServer(port=options.backendPort)
      options.frontend_only = True
      
    else:
      backEnd = Backend(port=options.backendPort)
    
    from pyretic.core.runtime import Runtime
    runtime = Runtime(backEnd, main,kwargs, options.mode, options.verbosity, False, False)

def startOFClient(poxpath, options):

    if poxpath is None:
        print 'Error: pox not found in PYTHONPATH'
        sys.exit(1)

    pox_exec = os.path.join(poxpath,'pox.py')
    python=sys.executable

    poxClient   = 'of_client.%s' % options.client
    backendIP   = '--ip=%s'   % options.backendIP 
    backendPort = '--port=%d' % options.backendPort

    OF          = 'openflow.of_01'
    listenIP    = '--address=%s' % options.listenIP 
    listenPort  = '--port=%d'    % options.listenPort 

    procCmd = [python, pox_exec, poxClient, backendIP, backendPort, OF, listenIP, listenPort]

    global of_client
    
    of_client = subprocess.Popen(procCmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def main():
    global of_client
    (op, options, args, kwargs_to_pass) = parseArgs()

    (poxpath, pyreticpath, mininetpath) = getPaths()
    
    setPyreticEnv(pyreticpath, options)
    
    if not options.ofclient_only:
        startRuntime(op=op, options=options, args=args, kwargs_to_pass=kwargs_to_pass)
    
    if not options.frontend_only:
        startOFClient(poxpath, options)
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()

if __name__ == '__main__':
    main()
