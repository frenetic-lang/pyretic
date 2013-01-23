#!/usr/bin/python

from time import time, sleep
from subprocess import call, check_output, Popen, PIPE, STDOUT, CalledProcessError
import sys as sys
import os as os
from optparse import OptionParser
from signal import SIGINT

from threading import Thread

class subprocess_output(Thread):
    
    def __init__(self,proc):
        self.proc = proc
        Thread.__init__(self)

    def run(self):
        while self.proc.poll() is None:
            line = self.proc.stdout.readline()
            print line,
            sleep(0.1)

def parseArgs():
    """Parse command-line args and return options object.
    returns: opts parse options dict"""

    desc = ( "The %prog utility creates Mininet network from the\n"
             "command line. It can create parametrized topologies,\n"
             "invoke the Mininet CLI, and run tests." )

    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    
    opts = OptionParser( description=desc, usage=usage )
    opts.add_option( '--verbosity', '-v', type='choice',
                     choices=['quiet','verbose'], default = 'quiet',
                     help = '|'.join( ['quiet','verbose'] )  )

    options, args = opts.parse_args()
    return (options, args)

def main():
    
    (options, args) = parseArgs()
    if options.verbosity == 'verbose':
        verbose = ['-v','verbose']
    else:
        verbose = []

    # GET PATHS
    controller_src_path = os.path.expanduser('~/pyretic/examples/static_load_balancer.py')
    unit_test_path = os.path.expanduser('~/pyretic/tests/lb_connectivity_test.py')
    pox_path = os.path.expanduser('~/pox/pox.py')

    # MAKE SURE WE CAN SEE ALL OUTPUT IF VERBOSE
    env = os.environ.copy()
    if verbose:
        env['PYTHONUNBUFFERED'] = 'True'

    # STARTUP CONTROLLER
    controller = Popen([sys.executable, pox_path,'--no-cli', controller_src_path, '--clients=5', '--servers=3'], 
                       env=env,
                       stdout=PIPE, 
                       stderr=STDOUT)
    if verbose:
        controller_out = subprocess_output(controller)
        controller_out.start()
    sleep(1)

    # TEST EACH TOPO
    topos = ['bump_clique,1,5,3']

    for topo in topos:
        test = ['sudo', unit_test_path, '--topo', topo] + verbose
        testproc = call(test)
        if testproc == 0:
            print "%s\tCONNECTIVITY PASSED" % topo
        else:
            print "%s\tCONNECTIVITY FAILED" % topo
        
    # KILL CONTROLLER
    controller.send_signal( SIGINT )

if __name__ == '__main__':
    main()
