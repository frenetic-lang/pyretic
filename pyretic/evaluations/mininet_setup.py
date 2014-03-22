from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from extratopos import *
import subprocess, shlex, time, signal, os, sys
from threading import Timer
import argparse

################################################################################
#### Test-case-specific functions
################################################################################

# First, common functions which call the test-case-specific functions:
def setup_network(test, global_params, testwise_params):
    """ A function that returns a 3-tuple (network, hosts, switches), based on
    the test case that's being run.
    """
    if test == "tm":
        return setup_tm_network(global_params, testwise_params)
    elif test == "waypoint":
        return setup_waypoint_network(global_params, testwise_params)
    else:
        print "Unknown test case topology!"
        sys.exit(0)

def setup_full_traffic_measurement(test, global_params, testwise_params,
                                   switches):
    if test == "tm":
        return setup_tm_full_traffic_measurement(global_params,
                                                 testwise_params,
                                                 switches)
    elif test == "waypoint":
        return setup_waypoint_full_traffic_measurement(global_params,
                                                       testwise_params,
                                                       switches)
    else:
        print "Unknown test case traffic measurement call!"
        sys.exit(0)

def setup_workload(test, global_params, testwise_params, hosts):
    if test == "tm":
        return setup_tm_workload(global_params, testwise_params, hosts)
    elif test == "waypoint":
        return setup_waypoint_workload(global_params, testwise_params, hosts)
    else:
        print "Unknown test case for workload setup!"
        sys.exit(0)

### Helper functions for getting hosts and switches from a network
def get_hosts(net, num_hosts):
    """ Get a list of host objects from the network object """
    hosts = []
    for i in range(1, num_hosts+1):
        hosts.append(net.getNodeByName('h' + str(i)))
    return hosts

def get_switches(net, num_switches):
    switches = []
    for i in range(1, num_switches+1):
        switches.append(net.getNodeByName('s' + str(i)))
    return switches

def get_default_net_hosts_switches(topo, listen_port, num_hosts, num_switches):
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=listen_port)
    net.start()
    hosts = get_hosts(net, num_hosts)
    switches = get_switches(net, num_switches)
    return (net, hosts, switches)

### Test 1: traffic matrix
def setup_tm_network(global_params, testwise_params):
    """ Set up a cycle topology of num_hosts. """
    assert 'n' in testwise_params
    assert 'listen_port' in global_params
    num_hosts = int(testwise_params['n'])
    listen_port = int(global_params['listen_port'])
    topo = CycleTopo(num_hosts, num_hosts)
    return get_default_net_hosts_switches(topo, listen_port, num_hosts,
                                          num_hosts)

def setup_tm_workload(global_params, testwise_params, hosts):
    hosts_src = hosts
    hosts_dst = hosts[1:] + [hosts[0]]
    per_flow_bw = ["8M"] * len(hosts)
    return (hosts_src, hosts_dst, per_flow_bw)

def setup_tm_full_traffic_measurement(global_params, testwise_params, switches):
    """ Setup tshark collectors and statistics for the 'total' traffic in the
    network.
    """
    total_traffic_prefix = global_params['total_traffic_prefix']
    test_duration_sec = global_params['test_duration_sec']
    slack = global_params['slack_factor']
    # setup internal and external interfaces
    internal_ints = reduce(lambda r, sw: r + [sw.name + '-eth1',
                                              sw.name + '-eth2'],
                           switches, [])
    external_ints = reduce(lambda r, sw: r + [sw.name + '-eth3'], switches, [])
    return run_tshark_full_traffic_measurement(internal_ints, external_ints,
                                               test_duration_sec,
                                               total_traffic_prefix, slack)

### Test 2. Detecting violations of waypoint constraints
class WaypointTopo(Topo):
    """ A simple topology to check waypoint specifications in the routing."""
    def __init__(self):
        Topo.__init__(self)
        # Switches
        for i in range(1,5):
            self.addSwitch('s' + str(i))
        self.addLink('s1', 's2')
        self.addLink('s2', 's3')
        self.addLink('s3', 's4')
        self.addLink('s4', 's1')
        # Hosts.
        for i in range(1,5):
            self.addHost('h' + str(i))
        self.addLink('h1', 's1')
        self.addLink('h2', 's3')
        self.addLink('h3', 's1')
        self.addLink('h4', 's3')

def setup_waypoint_network(global_params, testwise_params):
    assert 'listen_port' in global_params
    listen_port = global_params['listen_port']
    topo = WaypointTopo()
    return get_default_net_hosts_switches(topo, listen_port, 4, 4)

def setup_waypoint_workload(global_params, testwise_params, hosts):
    assert 'violating_frac' in testwise_params
    frac = float(testwise_params['violating_frac'])
    assert 'total_bw' in testwise_params
    total_bw = int(testwise_params['total_bw'])

    hosts_src = [hosts[0], hosts[2]]
    hosts_dst = [hosts[1], hosts[3]]
    per_flow_bw = [str(int(frac*total_bw)), str(int((1-frac)*total_bw))]
    return (hosts_src, hosts_dst, per_flow_bw)

def setup_waypoint_full_traffic_measurement(global_params,
                                            testwise_params,
                                            switches):
    total_traffic_prefix = global_params['total_traffic_prefix']
    test_duration_sec = global_params['test_duration_sec']
    slack = global_params['slack_factor']
    # setup internal and external interfaces
    internal_ints = reduce(lambda r, sw: r + [sw.name + '-eth1',
                                              sw.name + '-eth2'],
                           switches, [])
    external_ints = reduce(lambda r, sw: r + [sw.name + '-eth3',
                                              sw.name + '-eth4'],
                           [switches[0], switches[2]], [])
    return run_tshark_full_traffic_measurement(internal_ints, external_ints,
                                               test_duration_sec,
                                               total_traffic_prefix, slack)

################################################################################
#### Diagnostics
################################################################################

def ping_flow_pairs(net, hosts_src, hosts_dst):
    """ Test connectivity between flow sources and destinations """
    assert len(hosts_src) == len(hosts_dst)
    for i in range(0, len(hosts_src)):
        result = hosts_src[i].cmd('ping -c1 %s' % (hosts_dst[i].IP()))
        sent, received = net._parsePing(result)
        print ('%d ' % i) if received else 'X '

################################################################################
### Essentials test setup functions on all test cases
################################################################################

def pyretic_controller(test, testwise_params, c_out, c_err, pythonpath):
    c_outfile = open(c_out, 'w')
    c_errfile = open(c_err, 'w')
    # Hackety hack. I don't know of any other way to supply the PYTHONPATH
    # variable for the pyretic controller!
    py_env = os.environ.copy()
    if not "PYTHONPATH" in py_env:
        py_env["PYTHONPATH"] = pythonpath

    cmd = ("pyretic.py -m p0 pyretic.evaluations.eval_path --test=" + test +
           reduce(lambda r, k: r + ("--" + k + "=" + testwise_params[k] + " "),
                  testwise_params.keys(), " "))
    c = subprocess.Popen(shlex.split(cmd), stdout=c_outfile, stderr=c_errfile,
                         env=py_env)
    return ([c], [c_outfile, c_errfile])

def wait_switch_rules_installed(switches):
    """This function waits for switch rule installation to stabilize on all
    switches before running tests.
    """
    print "Waiting for switch rule installation to complete..."
    not_fully_installed = True
    num_rules = {}
    num_iterations = 0
    per_iter_timeout = 3
    while not_fully_installed:
        num_iterations += 1
        not_fully_installed = False
        for s in switches:
            if not s in num_rules:
                num_rules[s] = 0
            rules = s.cmd("dpctl dump-flows tcp:localhost:6634 | grep -v \
                           'stats_reply' | grep -v cookie=0 | wc -l")
            rules = int(rules)
            if not (rules == num_rules[s] and rules > 2): # not converged!
                not_fully_installed = True
                print '.'
            num_rules[s] = rules
        time.sleep(per_iter_timeout)
    print
    time_waited = per_iter_timeout * num_iterations
    print "Rules fully installed after waiting", time_waited, "seconds"

def run_iperf_test(net, hosts_src, hosts_dst, test_duration_sec,
                   per_transfer_bandwidth, client_prefix, server_prefix):
    """Run UDP iperf transfers between hosts_src and hosts_dst pairs for
    test_duration_sec seconds, with a targeted bandwidth of
    per_transfer_bandwidth.
    """
    # start iperf servers
    for dst in hosts_dst:
        dst_server_file = dst.name + '-' + server_prefix
        dst.cmd("iperf -u -s -p 5002 -i 5 2>&1 > " + dst_server_file + " &")
    print "Finished starting up iperf servers..."

    # start iperf client transfers
    for i in range(0, len(hosts_src)):
        src = hosts_src[i]
        src_client_file = src.name + '-' + client_prefix
        src.cmd("iperf -t " + str(test_duration_sec) + " -c " +
                hosts_dst[i].IP() + " -u -p 5002 -i 5 -b " +
                per_transfer_bandwidth[i] + " 2>&1 > " + src_client_file + "&")
    print "Client transfers initiated."

def setup_overhead_statistics(overheads_file, test_duration_sec, slack):
    cmd = ("tshark -q -i lo -z io,stat," + str(slack * test_duration_sec) +
           ",'of.pktin||of.stats_flow_byte_count' -f 'tcp port 6633'")
    f = open(overheads_file, "w")
    p = subprocess.Popen(shlex.split(cmd), stdout=f, stderr=subprocess.STDOUT)
    print "Started tshark process"
    return ([p], [f])

def run_tshark_full_traffic_measurement(internal_ints, external_ints,
                                        test_duration_sec, total_traffic_prefix,
                                        slack):
    """Given a list of "internal" and "external"-facing interfaces in the
    network, set up tshark captures to count the number of total packets on all
    the links in the network (separate traffic counted once and twice for later
    merging). This function is generic across test cases.
    """
    def get_interfaces(intr_list):
        """ Get tshark interface argument for a switch sw, whose interfaces in
        interface_list must be captured. """
        return reduce(lambda r, intr: r + "-i " + intr + " ", intr_list, ' ')

    def get_tshark_cmd_file(interfaces, file_suffix):
        cmd = ("tshark -q " + get_interfaces(interfaces) +
               " -z io,stat," + str(slack * test_duration_sec))
        fname = total_traffic_prefix + file_suffix
        return (cmd, fname)

    def get_fds_processes(cmds, files):
        out_fds = []
        processes = []
        assert len(cmds) == len(files)
        for i in range(0, len(cmds)):
            f = files[i]
            cmd = cmds[i]
            out_fds.append(open(f, 'w'))
            processes.append(subprocess.Popen(shlex.split(cmd),
                                              stdout=out_fds[-1],
                                              stderr=subprocess.STDOUT))
        return processes, out_fds

    (cmd_once,  file_once)  = get_tshark_cmd_file(external_ints,  '-once.txt')
    (cmd_twice, file_twice) = get_tshark_cmd_file(internal_ints, '-twice.txt')
    return get_fds_processes([cmd_once, cmd_twice], [file_once, file_twice])

################################################################################
### The main function.
################################################################################

def query_test():
    """ Main """
    # Configuring the experiment.
    # Global parameters used by specific tests as well
    listen_port = 6634
    test_duration_sec = 30
    slack_factor = 5 # slack for ensuring tshark statistics fall into one interval
    total_traffic_prefix = "total-traffic"
    global_params = { 'listen_port' : listen_port,
                      'test_duration_sec': test_duration_sec,
                      'total_traffic_prefix': total_traffic_prefix,
                      'slack_factor' : slack_factor }

    # Global parameters not used elsewhere outside this function
    controller_debug_mode = False
    overheads_file = "tshark_output.txt"
    c_out = "pyretic-stdout.txt"
    c_err = "pyretic-stderr.txt"
    iperf_client_prefix = "client-udp.txt"
    iperf_server_prefix = "server-udp.txt"

    # Specification of testwise parameters (in code, for now)
    full_testwise_params = { "tm" : {'n': '5'},
                             "waypoint": {'violating_frac': '0.10',
                                          'total_bw': '1800000' }
                           }
    test = "waypoint"

    # Get test settings
    args = parseArgs()

    # Hack to set pythonpath.
    pypath = "/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox"

    # Actual experiment setup.
    mn_cleanup()

    testwise_params = full_testwise_params[test]

    ctlr = None
    if not controller_debug_mode:
        print "Starting pyretic controller"
        ctlr = pyretic_controller(test, testwise_params, c_out, c_err, pypath)

    print "Setting up topology"
    (net, hosts, switches) = setup_network(test, global_params, testwise_params)

    print "Setting up overhead statistics measurements"
    tshark = setup_overhead_statistics(overheads_file, test_duration_sec,
                                       slack_factor)

    print "Setting up collectors for total traffic"
    switch_stats = setup_full_traffic_measurement(test, global_params,
                                                  testwise_params, switches)

    print "Setting up handlers for graceful experiment abort"
    signal.signal(signal.SIGINT, get_abort_handler(controller_debug_mode, ctlr,
                                                   tshark, switch_stats, net))

    print "Setting up workload configuration"
    (hosts_src, hosts_dst, per_flow_bw) = setup_workload(test, global_params,
                                                         testwise_params, hosts)

    print "Setting up switch rules"
    if controller_debug_mode:
        print "*** YOU must start the controller separately for this to work!"
    wait_switch_rules_installed(switches)

    # print "Testing network connectivity"
    # ping_flow_pairs(net, hosts_src, hosts_dst)

    print "Starting iperf tests"
    run_iperf_test(net, hosts_src, hosts_dst, test_duration_sec, per_flow_bw,
                   iperf_client_prefix, iperf_server_prefix)

    print ("Running iperf transfer tests. This may take a while (" +
           str(test_duration_sec) + " seconds)...")
    time.sleep(test_duration_sec)
    print "Experiment done!"

    finish_up(controller_debug_mode, ctlr, tshark, switch_stats, net)

    if controller_debug_mode:
        CLI(net)
        net.stop()

################################################################################
### Cleanup-related functions
################################################################################

def mn_cleanup():
    subprocess.call("sudo mn -c", shell=True)

def finish_up(controller_debug_mode, ctlr, tshark, switch_stats, net):
    def close_fds(fds, fd_str):
        for fd in fds:
            fd.close()
        print "Closed", fd_str, "file descriptors"

    print "--- Cleaning up after experiment ---"
    # controller
    if not controller_debug_mode:
        ([p], fds) = ctlr
        kill_process(p, "controller")
        close_fds(fds, "controller")
    # overhead statistics tshark
    ([p], fds) = tshark
    kill_process(p, "tshark overhead statistics collection")
    close_fds(fds, "overhead statistics")
    # switch statistics
    (procs, fds) = switch_stats
    for p in procs:
        kill_process(p, "tshark switch statistics collection")
    close_fds(fds, "switch statistics")
    # mininet network
    if not controller_debug_mode:
        net.stop()
        print "Killed mininet network"

def get_abort_handler(controller_debug_mode, ctlr, tshark, switch_stats, net):
    def abort_handler(signum, frame):
        finish_up(controller_debug_mode, ctlr, tshark, switch_stats, net)
    return abort_handler

def kill_process(p, process_str):
    print "Signaling", process_str, "for experiment completion"
    p.send_signal(signal.SIGINT)

################################################################################
### Argument parsing
################################################################################

def parseArgs():
    parser = argparse.ArgumentParser(description="Run tests for query evaluations")
    parser.add_argument("--test_duration_sec", type=int,
                        help="Duration for running data transfers",
                        default=30)
    parser.add_argument("-d", "--controller_debug_mode", action="store_true",
                        help="Run controller separately for debugging")

    parser.add_argument("-t", "--test", default="waypoint",
                        choices=['tm', 'waypoint'], help="Test case to run")

    # Test-case-specific options

    # traffic matrix
    parser.add_argument("-n", "--num_hosts", default=5, type=int,
                        help="Number of hosts")

    # waypoint
    parser.add_argument("-v", "--violating_frac", default=0.10, type=float,
                        help="Traffic fraction violating waypoint constraints")
    parser.add_argument("-b", "--total_bw", type=int, default=1800000,
                        help="Total traffic injected into the network per sec")

    args = parser.parse_args()
    return args

################################################################################
### Call to main function
################################################################################
if __name__ == "__main__":
    setLogLevel('info')
    query_test()
