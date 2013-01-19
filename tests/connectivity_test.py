#!/usr/bin/python

"Monitor multiple hosts using popen()/pmonitor()"

from time import time, sleep
from signal import SIGINT
from subprocess import call, PIPE, STDOUT
import re as re
import sys as sys
from optparse import OptionParser

from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo, LinearTopo
from mininet.node import Host, OVSKernelSwitch, RemoteController
from mininet.util import pmonitor, buildTopo
from mininet.topolib import TreeTopo
from mininet.cli import CLI
from mininet.clean import cleanup
from mininet.log import lg


TOPODEF = 'minimal'
TOPOS = { 'minimal': lambda: SingleSwitchTopo( k=2 ),
          'linear': LinearTopo,
          'single': SingleSwitchTopo,
          'tree': TreeTopo }


def testSwitching(net,verbose):

    ## GET THE HOST AND SERVER NAMES
    hosts = net.hosts
    
    ## DICTS FOR USE W/ PMONITOR
    popens = {}
    
    results = {}
    test = ['ping', '-c', '3']

    ## CLIENT REQUEST
    for h1 in hosts:
        for h2 in hosts:
            popens[h1.name+':'+h2.name] = h1.popen(test + [h2.IP()], stdout=PIPE, stderr=STDOUT)

    ## MONITOR OUTPUT
    for pair, line in pmonitor( popens, timeoutms=5000 ):
        if pair and line:
            if re.search('packets transmitted', line):
                (h1_name,h2_name) = pair.split(':')
                if verbose: print "%s->%s\t%s" % (h1_name,h2_name,line),
                stats = line.split(',')
                for stat in stats:
                    if re.search('packet loss', stat):
                        success = 1 - float(stat.split()[0][:-1])/100
                        if not h1_name in results:
                            results[h1_name] = {}
                        results[h1_name][h2_name] = success
    
    return results


def fullConnectivity(net,results):
    hosts = net.hosts
    passed = True
    for h1 in hosts:
        for h2 in hosts:
            try:
                if results[h1.name][h2.name] == 0:
                    passed = False
                    break
            except KeyError:
                pass    
    
    return passed


def addDictOption( opts, choicesDict, default, name, helpStr=None ):
    """Convenience function to add choices dicts to OptionParser.
       opts: OptionParser instance
       choicesDict: dictionary of valid choices, must include default
       default: default choice key
       name: long option name
       help: string"""
    if default not in choicesDict:
        raise Exception( 'Invalid  default %s for choices dict: %s' %
                         ( default, name ) )
    if not helpStr:
        helpStr = ( '|'.join( sorted( choicesDict.keys() ) ) +
                    '[,param=value...]' )
    opts.add_option( '--' + name,
                     type='string',
                     default = default,
                     help = helpStr )

def parseArgs():
    """Parse command-line args and return options object.
    returns: opts parse options dict"""
    if '--custom' in sys.argv:
        index = sys.argv.index( '--custom' )
        if len( sys.argv ) > index + 1:
            filename = sys.argv[ index + 1 ]
            self.parseCustomFile( filename )
        else:
            raise Exception( 'Custom file name not found' )

    desc = ( "The %prog utility creates Mininet network from the\n"
             "command line. It can create parametrized topologies,\n"
             "invoke the Mininet CLI, and run tests." )

    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    
    opts = OptionParser( description=desc, usage=usage )
    addDictOption( opts, TOPOS, TOPODEF, 'topo' )
    opts.add_option( '--verbosity', '-v', type='choice',
                     choices=['quiet','verbose'], default = 'quiet',
                     help = '|'.join( ['quiet','verbose'] )  )
    options, args = opts.parse_args()
    return (options, args)

def main():
    (options, args) = parseArgs()
    if options.verbosity == 'verbose':
        verbose = True
    else:
        verbose = False

    ## SET LOGGING AND CLEANUP PREVIOUS MININET STATE, IF ANY
#    lg.setLogLevel('info')
    cleanup()

    ## SET UP TOPOLOGY
    topo = buildTopo( TOPOS, options.topo )
#    N = len(topo.hosts())

    ## SET UP MININET INSTANCE AND START
    net = Mininet( topo, switch=OVSKernelSwitch, host=Host, controller=RemoteController )
    net.start()

    results = testSwitching(net,verbose)
    connectivity = fullConnectivity(net,results)
    
    ## SHUTDOWN MININET
    net.stop()

    if connectivity:
        sys.exit(0)
    else:
        sys.exit(-1)
            
    
if __name__ == '__main__':
    main()
