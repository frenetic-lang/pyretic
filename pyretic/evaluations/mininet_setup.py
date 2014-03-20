from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from extratopos import *
import subprocess

num_hosts = 5

def mnCleanup():
    subprocess.call("sudo mn -c", shell=True)

def SetupTopo():
    return CycleTopo(num_hosts, num_hosts)

def pingFlowPairs(net, hosts_src, hosts_dst):
    """ Test connectivity between flow sources and destinations """
    assert len(hosts_src) == len(hosts_dst)
    for i in range(0, len(hosts_src)):
        result = hosts_src[i].cmd('ping -c1 %s' % (hosts_dst[i].IP()))
        sent, received = net._parsePing(result)
        print ('%d ' % i) if received else 'X '

def getHosts(net):
    """ Get a list of host objects from the network object """
    hosts = []
    for i in range(1, num_hosts+1):
        hosts.append(net.getNodeByName('h' + str(i)))
    return hosts

def getSwitches(net):
    switches = []
    for i in range(1, num_hosts+1):
        switches.append(net.getNodeByName('s' + str(i)))
    return switches

def runIperfTest(net, hosts_src, hosts_dst, switches_list):
    print "Nothing to do here."

def queryTest():
    """ Main """
    mnCleanup()

    topo = SetupTopo()
    # net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController, listenPort=6634)
    net.start()

    hosts = getHosts(net)
    hosts_src = hosts
    hosts_dst = hosts

    print "Testing network connectivity"
    pingFlowPairs(net, hosts_src, hosts_dst)

    print "Starting iperf tests"
    switches_list = getSwitches(net)
    runIperfTest(net, hosts_src, hosts_dst, switches_list)

    CLI(net)

    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    queryTest()
