import os as os
import sys as sys
import re as re
from time import sleep, time

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
from signal import SIGINT
from optparse import OptionParser

WARMUP = 3

TOPODEF = 'minimal'
TOPOS = { 'minimal': lambda: SingleSwitchTopo( k=2 ),
          'linear': LinearTopo,
          'single': SingleSwitchTopo,
          'tree': TreeTopo }

def ping_all(net,verbose,ping_type,count,pattern='sequential',extra_ips=[]):
    if pattern == 'sequential':
        return ping_all_sequential(net,verbose,ping_type,count,extra_ips)
    elif pattern == 'intermediate':
        return ping_all_intermediate(net,verbose,ping_type,count,extra_ips)
    elif pattern == 'parallel':
        return ping_all_parallel(net,verbose,ping_type,count,extra_ips)
    else:
        raise RuntimeError('ERROR:ping_all: invalid option ' + pattern)


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


from threading import Thread

class pmonitorBackground(Thread):
    
    def __init__(self,popens,pdumps):
        self.popens = popens
        self.pdumps = pdumps
        self.stopped = False
        Thread.__init__(self)

    def run(self):
        for h, line in pmonitor( self.popens ):
            if h and line:
                try:
                    self.pdumps[h.name].append(line.strip())
                except:
                    self.pdumps[h.name] =[line.strip()]

def collect_tcpdumps(hosts):
    popens = {}
    for host in hosts:
        popens[host] = host.popen('/home/mininet/pyretic/tests/tcpdump_wrapper.sh', stdout=PIPE, stderr=STDOUT)
    sleep(1)
    pdumps = {}
    pb = pmonitorBackground(popens,pdumps)
    pb.start()
    return (pb,pdumps)

def get_tcpdumps((pb,pdumps)):
    sleep(0)
    pb.join()
    return pdumps

def dumps_to_packets(dumps):
    packets = {}
    for h in dumps.keys():
        packets[h] = []
        cur = ''
        for line in dumps[h]:
            if re.search('^IP', line):
                if cur != '':
                    packets[h].append(cur)
                cur = line + '\n'
            elif re.search('^ARP', line):
                if cur != '':
                    packets[h].append(cur)
                cur = line + '\n'
            elif re.search('^tcpdump', line):
                if cur != '':
                    packets[h].append(cur)
                cur = ''
            else:
                if cur != '':
                    cur += line + '\n'
        if cur != '':
            packets[h].append(cur)
        #if len(packets[h]) != len(set(packets[h])):
        #    print "WARNING: multiple identical packets captured by tcpdump host %s" % h
        c = 0

    # STORE PACKET INDICIES
    for h in packets.keys():
        packet_index = {}
        c = 0
        for p in packets[h]:
            c +=1
            packet_index[p] = c            
        packets[h] = (packets[h],packet_index)
    return packets

def hub_packet_behavior(packets,verbose):
    for h1 in packets.keys():
        h1_packets, h1_inds = packets[h1]
        for h2 in packets.keys():
            h2_packets, h2_inds = packets[h2]
            difference = set(h1_packets) ^ set(h2_packets)
            # TCPDUMP BEHAVIOR NOT COMPLETELY SYNCHRONIZED
            if len(difference) > 0:
                # CHECK EACH PACKET TO SEE WHETHER REALLY A PROBLEM 
                # (DIFFERENCES AT VERY END OF TCPDUMP TO BE EXPECTED)
                for packet in difference:
                    if packet in h1_inds:
                        if float(h1_inds[packet])/float(len(h1_packets)) < 0.9:
                            if verbose:  print (h1_inds[packet],len(h1_packets),float(h1_inds[packet])/float(len(h1_packets)))
                            return False
                    if packet in h2_inds:
                        if float(h2_inds[packet])/float(len(h2_packets)) < 0.9:
                            if verbose:  print (h2_inds[packet],len(h2_packets),float(h2_inds[packet])/float(len(h2_packets)))
                            return False
    return True

def passed_str(b):
    if b:
        return '+'
    else:
        return '-'




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

