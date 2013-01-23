#!/usr/bin/python

"Monitor multiple hosts using popen()/pmonitor()"

from time import time, sleep
from signal import SIGINT
from subprocess import call, PIPE, STDOUT
import re as re
import sys as sys
import os as os
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


def ping_all(net,verbose,ping_type,count,extra_ips=[]):

    ## GET THE HOST AND SERVER NAMES
    hosts = net.hosts
    
    ## DICTS FOR USE W/ PMONITOR
    popens = {}
    
    results = {}
    if ping_type == 'ICMP':
        test = ['ping', '-c', '3']
    elif ping_type == 'TCP80SYN':
        test = ['hping3', '-c', count,'-S' ,'-p' ,'80']
    else:
        test = ['ping', '-c', count]

    if verbose: print "ping using %s" % test

    ## CLIENT REQUEST
    for h1 in hosts:
        for h2 in hosts:
            if h1 == h2:
                continue
            popens[h2.name] = h1.popen(test + [h2.IP()], stdout=PIPE, stderr=STDOUT)
        for ip in extra_ips:
            popens[ip] = h1.popen(test + [ip], stdout=PIPE, stderr=STDOUT)

        ## MONITOR OUTPUT
        for name, line in pmonitor( popens, timeoutms=5000 ):
            if name and line:
                if re.search('packets transmitted', line):
                    if verbose: print "%s->%s\t%s" % (h1.name,name,line),
                    stats = line.split(',')
                    for stat in stats:
                        if re.search('packet loss', stat):
                            success = 1 - float(stat.split()[0][:-1])/100
                            if not h1.name in results:
                                results[h1.name] = {}
                            results[h1.name][name] = success
    
    return results


def clientServerConnectivity(clients,servers,canonical_ip,results):

    for c1 in clients:
        for c2 in clients:
            try:
                # IF ALL PINGS FAILED FOR ANY CLIENT PAIR
                # CONNECTIVITY FAILS
                if results[c1.name][c2.name] == 0:
                    return False
            except KeyError:
                pass    

        missing = 0
        for s in servers:
            if results[c1.name][s.name] == 0:
                missing += 1
        # EXACTLY ONE SERVER SHOULD BE UNREACHABLE
        if missing != 1:
            return False

        # AND SHOULD RESPOND AS THE CANONICAL IP
        if results[c1.name][canonical_ip] == 0:
                return False

    return True



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

def setCustom( name, value ):
    "Set custom parameters for MininetRunner."
    if name in ( 'topos', 'switches', 'hosts', 'controllers' ):
        # Update dictionaries
        param = name.upper()
        globals()[ param ].update( value )
    else:
        # Add or modify global variable or class
        globals()[ name ] = value


def parseCustomFile( fileName ):
    "Parse custom file and add params before parsing cmd-line options."
    customs = {}
    if os.path.isfile( fileName ):
        execfile( fileName, customs, customs )
        for name, val in customs.iteritems():
            setCustom( name, val )
    else:
        raise Exception( 'could not find custom file: %s' % fileName )

def parseArgs():
    """Parse command-line args and return options object.
    returns: opts parse options dict"""
    parseCustomFile(os.path.expanduser('~/pyretic/mininet/extra-topos.py'))
    
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
    opts.add_option( '--ping-type', '-p', type='choice',
                     choices=['ICMP','TCP80SYN'], default = 'ICMP',
                     help = '|'.join( ['ICMP','TCP80SYN'] )  )
    opts.add_option( '--count', '-c', action="store", type="string", 
                     dest="count", default='1', help = 'number of ping attempts'  )
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

    ## SET UP MININET INSTANCE AND START
    net = Mininet( topo, switch=OVSKernelSwitch, host=Host, controller=RemoteController )
    net.start()

    results = ping_all(net,verbose,options.ping_type,options.count,['10.0.0.100'])
    connectivity = clientServerConnectivity(net.hosts[:5],net.hosts[-3:],'10.0.0.100',results)

    ## SHUTDOWN MININET
    net.stop()

    if connectivity:
        sys.exit(0)
    else:
        sys.exit(-1)
            
    
if __name__ == '__main__':
    main()
