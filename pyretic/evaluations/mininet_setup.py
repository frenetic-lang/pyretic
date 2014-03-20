from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from extratopos import *
import subprocess

num_hosts = 5
listen_port = 6634

def mn_cleanup():
    subprocess.call("sudo mn -c", shell=True)

def setup_topo():
    return CycleTopo(num_hosts, num_hosts)

def ping_flow_pairs(net, hosts_src, hosts_dst):
    """ Test connectivity between flow sources and destinations """
    assert len(hosts_src) == len(hosts_dst)
    for i in range(0, len(hosts_src)):
        result = hosts_src[i].cmd('ping -c1 %s' % (hosts_dst[i].IP()))
        sent, received = net._parsePing(result)
        print ('%d ' % i) if received else 'X '

def get_hosts(net):
    """ Get a list of host objects from the network object """
    hosts = []
    for i in range(1, num_hosts+1):
        hosts.append(net.getNodeByName('h' + str(i)))
    return hosts

def get_switches(net):
    switches = []
    for i in range(1, num_hosts+1):
        switches.append(net.getNodeByName('s' + str(i)))
    return switches

def run_iperf_test(net, hosts_src, hosts_dst, switches_list):
    print "Nothing to do here."

def test_switch_rules(switches):
    print "Nothing done here yet, either."

def query_test():
    """ Main """
    mn_cleanup()

    topo = setup_topo()
    # net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=listen_port)
    net.start()

    hosts = get_hosts(net)
    switches = get_switches(net)
    hosts_src = hosts
    hosts_dst = hosts

    print "Testing network connectivity"
    ping_flow_pairs(net, hosts_src, hosts_dst)

    print "Testing switch rules"
    test_switch_rules(switches)

    print "Starting iperf tests"
    run_iperf_test(net, hosts_src, hosts_dst, switches)

    CLI(net)

    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    query_test()
