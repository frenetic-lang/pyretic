#!/usr/bin/python

"Monitor multiple hosts using popen()/pmonitor()"

from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo, LinearTopo
from mininet.node import Host, OVSKernelSwitch, RemoteController
from mininet.util import pmonitor
from mininet.cli import CLI
from mininet.clean import cleanup
from mininet.log import lg
from time import time, sleep
from signal import SIGINT
from subprocess import call, PIPE, STDOUT

def httpTest( N=2 ):
    "Run pings and monitor multiple hosts using pmonitor"

    ## SET LOGGING AND CLEANUP PREVIOUS MININET STATE, IF ANY
    lg.setLogLevel('info')
    cleanup()

    ## INSTEAD OF RUNNING PYRETIC HUB, UNCOMMENT LINE 
    ## TO SEE THAT THIS WORKS FINE WHEN RUNNING REFERENCE CONTROLLER
#    call('controller ptcp: &', shell=True)

    ## SET UP TOPOLOGY
    topo = LinearTopo( N )        ## (tcp parse) warning TCP data offset too long or too short
#    topo = SingleSwitchTopo( N ) ## SILENT STALL


    ## SET UP MININET INSTANCE AND START
    net = Mininet( topo, switch=OVSKernelSwitch, host=Host, controller=RemoteController )
    net.start()

    print "Starting test..."

    ## GET THE HOST AND SERVER NAMES
    hosts = net.hosts
    client = hosts[ 0 ]
    server = hosts[ 1 ]
    
    ## DICTS FOR USE W/ PMONITOR
    spopens = {}
    cpopens = {}

    ## WARMUP SERVER 
    spopens[server] = server.popen('python', '-m', 'SimpleHTTPServer', '80')
    sleep(1)

    ## CLIENT REQUEST
    cpopens[client] = client.popen('wget', '-O', '-', server.IP(), stdout=PIPE, stderr=STDOUT)

    ## MONITOR OUTPUT
    for h, line in pmonitor( cpopens, timeoutms=5000 ):
        if h and line:
            print '%s: %s' % ( h.name, line ),

    ## TO USE THE COMMAND LINE INTERFACE, BEFORE FINISHING, UNCOMMENT
#    CLI( net )

    ## SHUTDOWN SERVER
    spopens[server].send_signal( SIGINT )
    
    ## SHUTDOWN MININET
    net.stop()

if __name__ == '__main__':
    httpTest()
