import os as os
import sys as sys
import re as re

# SET PYTHONPATH FOR ROOT USER
sys.path.append('/home/mininet/pox')
sys.path.append('/home/mininet/pyretic')
sys.path.append('/home/mininet/mininet')

from mininet.topo import SingleSwitchTopo, LinearTopo
from mininet.topolib import TreeTopo
from mininet.util import pmonitor, buildTopo
from mininet.net import Mininet
from mininet.node import Host, OVSKernelSwitch, RemoteController
from mininet.clean import cleanup
from mininet.log import lg

from subprocess import call, PIPE, STDOUT

from optparse import OptionParser

TOPODEF = 'minimal'
TOPOS = { 'minimal': lambda: SingleSwitchTopo( k=2 ),
          'linear': LinearTopo,
          'single': SingleSwitchTopo,
          'tree': TreeTopo }


def ping_all_sequential(net,verbose,ping_type,count,extra_ips=[]):
    """pings each host pair, one at a time.
       This is how the built-in pingall works """

    ## GET THE HOST AND SERVER NAMES
    hosts = net.hosts
    
    ## DICTS FOR USE W/ PMONITOR
    popens = {}
    
    results = {}
    if ping_type == 'ICMP':
        test = ['ping', '-c', count]
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


def ping_all_intermediate(net,verbose,ping_type,count,extra_ips=[]):
    """pings all hosts in parallel from host 1 then, from host 2, ..."""

    ## GET THE HOST AND SERVER NAMES
    hosts = net.hosts
    
    ## DICTS FOR USE W/ PMONITOR
    popens = {}
    
    results = {}
    if ping_type == 'ICMP':
        test = ['ping', '-c', count]
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


def ping_all_parallel(net,verbose,ping_type,count,extra_ips=[]):
    """pings all host pairs simultaneously"""

    ## GET THE HOST AND SERVER NAMES
    hosts = net.hosts
    
    ## DICTS FOR USE W/ PMONITOR
    popens = {}
    
    results = {}
    if ping_type == 'ICMP':
        test = ['ping', '-c', count]
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
            popens[h1.name+':'+h2.name] = h1.popen(test + [h2.IP()], stdout=PIPE, stderr=STDOUT)
        for ip in extra_ips:
            popens[h1.name+':'+ip] = h1.popen(test + [ip], stdout=PIPE, stderr=STDOUT)

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

