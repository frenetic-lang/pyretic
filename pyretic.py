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
import os
import logging
from multiprocessing import Queue, Process
import pyretic.core.util as util
import yappi
from pyretic.evaluations.stat import Stat
import shlex

of_client = None
enable_profile = False
eval_profile_enabled = False


def signal_handler(signal, frame):
    print '\n----starting pyretic shutdown------'
    # for thread in threading.enumerate():
    #     print (thread,thread.isAlive())
    if of_client:
        print "attempting to kill of_client"
        of_client.kill()
    # print "attempting get output of of_client:"
    # output = of_client.communicate()[0]
    # print output
    print "pyretic.py done"
    # Print profile information if enabled
    if enable_profile:
        funcstats = yappi.get_func_stats()
        funcstats.sort("tsub")
        funcstats.print_all(columns={0:("name",38), 1:("ncall",8), 2:("tsub",8),
                                     3:("ttot",8), 4:("tavg", 8)})
    
    global eval_profile_enabled
    if eval_profile_enabled:
        Stat.stop()

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
    kwargs_to_pass = None
    if end_args > 0:
        kwargs_to_pass = sys.argv[end_args+1:]
        sys.argv = sys.argv[:end_args+1]

    op = OptionParser( description=desc, usage=usage )
    op.add_option( '--frontend-only', '-f', action="store_true", 
                     dest="frontend_only", help = 'only start the frontend'  )
    op.add_option( '--mode', '-m', type='choice',
                     choices=['interpreted','i','reactive0','r0','proactive0','p0','proactive1','p1'], 
                     help = '|'.join( ['interpreted/i','reactive0/r0','proactiveN/pN for N={0,1}'] )  )
    op.add_option( '--nx', action="store_true",
                   dest="nx", help="use nicira extensions in pox" )
    op.add_option( '--pipeline', dest="pipeline",
                   help="pipeline configuration (if --nx enabled)",
                   default="default_pipeline")
    op.add_option( '--verbosity', '-v', type='choice',
                   choices=['low','normal','high','please-make-it-stop'],
                   default = 'low',
                   help = '|'.join( ['low','normal','high','please-make-it-stop'] )  )
    op.add_option( '--enable_profile', '-p', action="store_true",
                   dest="enable_profile",
                   help = 'enable yappi multithreaded profiler' )

    op.add_option('--eval_result_path', '-e', action='store', 
                    type='string', dest='eval_result_path')
    op.add_option( '--enable_disjoint', '-d', action="store_true",
                    dest="disjoint_enabled",
                    help = 'enable disjoint optimization')
    op.add_option('--enable_default_link', '-l', action="store_true",
                    dest='default_enabled',
                    help = 'enable adding default link optimization, only woks with disjoint on')
    op.add_option('--enable_integration', '-i', action="store_true",
                    dest='integrate_enabled',
                    help = 'enable integration of tag and capture optimization, only works with multitable on')
    op.add_option('--enable_multitable', '-u', action="store_true",
                    dest = 'multitable_enabled',
                    help = 'enable multitable optimization. This option is'
                    ' strictly necessary *only* if you do control plane'
                    ' evaluations; it is set from the pipeline configuration'
                    ' automatically.')
    op.add_option('--enable_ragel', '-r', action="store_true",
                    dest = 'ragel_enabled',
                    help = 'enable ragel optimization')
    op.add_option('--enable_partition', '-a', action = "store_true",
                    dest = 'partition_enabled',
                    help = 'enable partition optimization')
    op.add_option('--switch_count', '-s', type = int,
                    dest = 'switch_cnt',
                    help = 'The expected number of switches, used for offline analysis')
    op.add_option('--enable_cache', '-c', action = "store_true",
                    dest = 'cache_enabled',
                    help = 'enable cache optimization')
    op.add_option('--enable_edge_contraction', '-g', action = "store_true",
                    dest = 'edge_contraction_enabled',
                    help = 'enable edge contraction optimization, only works with cache enabled')
    op.add_option('--enable_preddecomp', '-b', action="store_true",
                  dest = "preddecomp_enabled",
                  help = "enable predicate decomposition into several stages")
    op.add_option('--use_pyretic', action="store_true",
                  dest = 'use_pyretic',
                  help = "Use the pyretic compiler (uses netkat by default)")
    op.add_option('--write_log', dest="write_log",
                  help = ("Location of the runtime's write log for post-run"
                          "debugging"))
    op.add_option('--use_fdd', action="store_true",
                  dest = 'use_fdd',
                  help = "Use FDD for predicate decomposition")
    op.set_defaults(frontend_only=False, mode='proactive0', enable_profile=False,
                    disjoint_enabled=False, default_enabled=False,
                    integrate_enabled=False, multitable_enabled=False,
                    ragel_enabled=False, partition_enabled=False, 
                    switch_cnt=None, cache_enabled=False, 
                    edge_contraction_enabled=False,
                    preddecomp_enabled=False,
                    nx=False, use_pyretic=False, use_fdd=False,
                    write_log="rt_log.txt")

    options, args = op.parse_args()

    return (op, options, args, kwargs_to_pass)


def main():
    global of_client, enable_profile
    (op, options, args, kwargs_to_pass) = parseArgs()
    if options.mode == 'i':
        options.mode = 'interpreted'
    elif options.mode == 'r0':
        options.mode = 'reactive0'
    elif options.mode == 'p0':
        options.mode = 'proactive0'
    elif options.mode == 'p1':
        options.mode = 'proactive1'
    try:
        module_name = args[0]
    except IndexError:
        print 'Module must be specified'
        print ''
        op.print_usage()
        sys.exit(1)
    try:
        module = import_module(module_name)
    except ImportError, e:
        print 'Must be a valid python module'
        print 'e.g, full module name,'
        print '     no .py suffix,'
        print '     located on the system PYTHONPATH'
        print ''
        print 'Exception message for ImportError was:'
        print e
        sys.exit(1)

    main = module.main
    try:
        path_main = module.path_main
    except:
        path_main = None
    kwargs = { k : v for [k,v] in [ i.lstrip('--').split('=') for i in kwargs_to_pass ]}

    sys.setrecursionlimit(1500) #INCREASE THIS IF "maximum recursion depth exceeded"

    # Set up multiprocess logging.
    verbosity_map = { 'low' : logging.ERROR,
                      'normal' : logging.WARNING,
                      'high' : logging.INFO,
                      'please-make-it-stop' : logging.DEBUG }
    logging_queue = Queue()

    # Make a logging process.
    def log_writer(queue, log_level):
        formatter = logging.Formatter('%(levelname)s:%(name)s:%(asctime)s: %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        handler.setLevel(log_level)
        logger = logging.getLogger()
        logger.addHandler(handler)
        logger.setLevel(log_level)
        while(True):
            try:
                to_log = queue.get()
            except KeyboardInterrupt, e:
                print "\nkilling log"
                import sys
                sys.exit(0)
            logger.handle(to_log)
    log_level = verbosity_map.get(options.verbosity, logging.DEBUG)
    log_process = Process(target=log_writer,args=(logging_queue, log_level,))
    log_process.daemon = True
    log_process.start()

    # Set default handler.
    logger = logging.getLogger()
    handler = util.QueueStreamHandler(logging_queue)
    logger.addHandler(handler)
    logger.setLevel(log_level)

    if options.eval_result_path:
        global eval_profile_enabled
        eval_profile_enabled = True
        Stat.start(options.eval_result_path)

    """ Start the frenetic compiler-server """
    if not options.use_pyretic and options.mode == 'proactive0':
        netkat_cmd = "bash start-frenetic.sh"
        try:
            output = subprocess.Popen(netkat_cmd, shell=True,
                                      stderr=subprocess.STDOUT)
        except Exception as e:
            print "Could not start frenetic server successfully."
            print e
            sys.exit(1)

    """ Start the runtime. """
    opt_flags_arg = (options.disjoint_enabled, options.default_enabled,
                     options.integrate_enabled, options.multitable_enabled,
                     options.ragel_enabled, options.partition_enabled,
                     options.switch_cnt, options.cache_enabled, 
                     options.edge_contraction_enabled,
                     options.preddecomp_enabled)
    runtime = Runtime(Backend(),main,path_main,kwargs,
                      mode=options.mode, verbosity=options.verbosity,
                      opt_flags=opt_flags_arg, use_nx=options.nx,
                      pipeline=options.pipeline,
                      use_pyretic=options.use_pyretic,
                      use_fdd=options.use_fdd,
                      write_log=options.write_log)

    """ Start pox backend. """
    if not options.frontend_only:
        try:
            output = subprocess.check_output('echo $PYTHONPATH',shell=True).strip()
        except:
            print 'Error: Unable to obtain PYTHONPATH'
            sys.exit(1)
        poxpath = None
        for p in output.split(':'):
             if re.match('.*pox/?$',p):
                 poxpath = os.path.abspath(p)
                 break
        if poxpath is None:
            print 'Error: pox not found in PYTHONPATH'
            sys.exit(1)
        pox_exec = os.path.join(poxpath,'pox.py')
        python=sys.executable
        # TODO(josh): pipe pox_client stdout to subprocess.PIPE or
        # other log file descriptor if necessary
        pox_cmd = "python %s %s of_client.pox_client %s %s" % (
            pox_exec,
            'openflow.nicira --convert-packet-in' if options.nx else '',
            '--use_nx' if options.nx else '',
            "--pipeline=%s" % options.pipeline if options.nx else '')
        of_client = subprocess.Popen(shlex.split(pox_cmd),
                                     stdout=sys.stdout,
                                     stderr=subprocess.STDOUT)

    """ Profiling. """
    if options.enable_profile:
        enable_profile = True
        yappi.start()
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()

if __name__ == '__main__':
    main()
