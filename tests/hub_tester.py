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
            sleep(0.001)

def parseArgs():
    """Parse command-line args and return options object.
    returns: opts parse options dict"""

    desc = ( "The %prog utility creates Mininet network from the\n"
             "command line. It can create parametrized topologies,\n"
             "invoke the Mininet CLI, and run tests." )

    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    
    opts = OptionParser( description=desc, usage=usage )
    opts.add_option( '--verbose', '-v', action="store_true", dest="verbose")
    opts.add_option( '--quiet', '-q', action="store_true", dest="quiet")
    opts.add_option( '--ping-pattern', '-P', type='choice',
                     choices=['sequential','intermediate','parallel'], default = 'intermediate' ,
                     help = '|'.join( ['sequential','intermediate','parallel'] )  )
    opts.add_option( '--switch', '-s', action="store", type="string", 
                     dest="switch", default='ovsk', help = 'ovsk|user'  )
    options, args = opts.parse_args()
    if options.quiet and options.verbose:
        opts.error("options -q and -v are mutually exclusive")
    return (options, args)

def main():
    
    (options, args) = parseArgs()
    flags = ['-P',options.ping_pattern,'--switch',options.switch]
    if options.verbose:
        flags.append('-v')

    # GET PATHS
    controller_src_path = os.path.expanduser('~/pyretic/examples/hub.py')
    unit_test_path = os.path.expanduser('~/pyretic/tests/hub_unit_test.py')
    pox_path = os.path.expanduser('~/pox/pox.py')

    # MAKE SURE WE CAN SEE ALL OUTPUT IF VERBOSE
    env = os.environ.copy()
    if options.verbose:
        env['PYTHONUNBUFFERED'] = 'True'

    # STARTUP CONTROLLER
    controller = Popen([sys.executable, pox_path,'--no-cli', controller_src_path], 
                       env=env,
                       stdout=PIPE, 
                       stderr=STDOUT)
    if options.verbose:
        controller_out = subprocess_output(controller)
        controller_out.start()
    sleep(1)

    # TEST EACH TOPO
    topos = ['single,2','single,16','linear,2','linear,8','tree,2,2','tree,3,2','cycle,8,8','clique,8,8']

    print "=============== HUB TESTER ===================="
    print "-TOPO---------CONNS----PKTS----------TIME------"
    count = 0
    for topo in topos:
        test = ['sudo', unit_test_path, '--topo', topo] + flags
        testproc = call(test)
        if testproc == 0:
            count += 1
    print "-----------------------------------------------"

    if count == len(topos):
        print "+ hub_tester PASSED [%d/%d]" % (count,len(topos))
    else:
        print "- hub_tester FAILED [%d/%d]" % (count,len(topos))
        
    # KILL CONTROLLER
    controller.send_signal( SIGINT )

if __name__ == '__main__':
    main()
