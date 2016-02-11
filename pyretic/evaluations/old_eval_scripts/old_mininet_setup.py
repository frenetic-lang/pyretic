from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from mininet.extratopos import *
import subprocess, shlex, time, signal, os, sys
from threading import Timer
import time
import argparse
import copy

import sys
sys.path.append('/home/mininet/pyretic')
from pyretic.evaluations.Tests import congested_link
################################################################################
#### setup functions
################################################################################

def setup_network(test_module, params):
    topo_args = params.topo_args
    listen_port = params.listen_port
    topo = test_module.setup.setup_topo(*topo_args)
    return get_default_net_hosts_switches(topo, listen_port) + (topo,)

def get_default_net_hosts_switches(topo, listen_port):
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=listen_port)
    net.start()
    hosts = get_nodes(net, topo.hosts())
    switches = get_nodes(net, topo.switches())
    return (net, hosts, switches)

def get_nodes(net, node_list):
    res = []
    for node_name in node_list:
        res.append(net.getNodeByName(node_name))

    return res

def setup_workload(test_module, params, net):
    return test_module.setup.setup_workload(net, *params.topo_args)  

def standardize_bw(bw_list):
    if bw_list and len(bw_list) > 0:
        sample = bw_list[0]
        if sample[-1] == 'M':
            return [ int(bw[:-1]) * 1000 * 1000 * 8 for bw in bw_list ]
        if sample[-1] == 'K':
            return [ int(bw[:-1]) * 1000 * 8 for bw in bw_list ]
        return [ int(bw)  * 8 for bw in bw_list ]

    return bw_list   
    
            
   
################################################################################
#### Test-case-specific functions
################################################################################

# First, common functions which call the test-case-specific functions:
def prev_setup_network(test, params):
    """ A function that returns a 3-tuple (network, hosts, switches), based on
    the test case that's being run.
    """
    if test == "tm":
        return setup_tm_network(params)
    elif test == "waypoint":
        return setup_waypoint_network(params)
    else:
        print "Unknown test case topology!"
        sys.exit(0)

def setup_full_traffic_measurement(test, params, switches):
    if test == "tm":
        return setup_tm_full_traffic_measurement(params, switches)
    elif test == "waypoint":
        return setup_waypoint_full_traffic_measurement(params, switches)
    else:
        print "Unknown test case traffic measurement call!"
        sys.exit(0)

def prev_setup_workload(test, params, hosts):
    if test == "tm":
        return setup_tm_workload(params, hosts)
    elif test == "waypoint":
        return setup_waypoint_workload(params, hosts)
    else:
        print "Unknown test case for workload setup!"
        sys.exit(0)

def setup_overhead_statistics(test, overheads_file, test_duration_sec, slack):
    if test == "tm":
        overheads_filter = 'of.stats_flow_byte_count'
        return setup_overhead_statistics_global(overheads_filter,
                                                overheads_file,
                                                test_duration_sec, slack)
    elif test == "waypoint":
        overheads_filter = 'of.pktin'
        return setup_overhead_statistics_global(overheads_filter,
                                                overheads_file,
                                                test_duration_sec, slack)
    else:
        overheads_filter = 'of.pktin'
        return setup_overhead_statistics_global(overheads_filter,
                                                overheads_file,
                                                test_duration_sec, slack)

        #sys.exit(0)

def setup_optimal_overheads_global(test, optimal_prefix, test_duration_sec,
                                   slack):
    if test == "waypoint":
        return setup_waypoint_optimal_overheads(optimal_prefix,
                                                 test_duration_sec, slack)
    elif test == "tm":
        return None
    else:
        return None
        #print "Unknown test case for optimal overhead statistics measurement!"

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

def prev_get_default_net_hosts_switches(topo, listen_port, num_hosts, num_switches):
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=listen_port)
    net.start()
    hosts = get_hosts(net, num_hosts)
    switches = get_switches(net, num_switches)
    return (net, hosts, switches)

### Test 1: traffic matrix
def setup_tm_network(params):
    """ Set up a cycle topology of num_hosts. """
    num_hosts = params.num_hosts
    listen_port = params.listen_port
    topo = CycleTopo(num_hosts, num_hosts)
    return get_default_net_hosts_switches(topo, listen_port, num_hosts,
                                          num_hosts)

def setup_tm_workload(params, hosts):
    hosts_src = hosts
    hosts_dst = hosts[1:] + [hosts[0]]
    per_flow_bw = ["1M"] * len(hosts)
    return (hosts_src, hosts_dst, per_flow_bw)

def setup_tm_full_traffic_measurement(params, switches):
    """ Setup tshark collectors and statistics for the 'total' traffic in the
    network.
    """
    adjust_path = get_adjust_path(params)
    total_traffic_prefix = adjust_path(params.total_traffic_prefix)
    test_duration_sec = params.test_duration_sec
    slack = params.slack_factor
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

def setup_waypoint_network(params):
    listen_port = params.listen_port
    topo = WaypointTopo()
    return get_default_net_hosts_switches(topo, listen_port, 4, 4)

def setup_waypoint_workload(params, hosts):
    frac = params.violating_frac
    total_bw = params.total_bw

    hosts_src = [hosts[0], hosts[2]]
    hosts_dst = [hosts[1], hosts[3]]
    per_flow_bw = [str(int(frac*total_bw)), str(int((1-frac)*total_bw))]
    return (hosts_src, hosts_dst, per_flow_bw)

def setup_waypoint_full_traffic_measurement(params,
                                            switches):
    adjust_path = get_adjust_path(params)
    total_traffic_prefix = adjust_path(params.total_traffic_prefix)
    test_duration_sec = params.test_duration_sec
    slack = params.slack_factor
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

def setup_waypoint_optimal_overheads(optimal_prefix, test_duration_sec, slack):
    """ Setup tshark collectors for optimal traffic measurement """
    interfaces = [["s3-eth1"], ["s1-eth1"]]
    filters = ["'host 10.0.0.1 and inbound'",
               "'host 10.0.0.2 and inbound'"]
    return setup_optimal_overhead_statistics(filters, interfaces,
                                             optimal_prefix,
                                             test_duration_sec, slack)

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
        dst_server_file = server_prefix + '-' + dst.name + '.txt'
        dst.cmd("iperf -fK -u -s -p 5002 2>&1 > " + dst_server_file + " &")
    print "Finished starting up iperf servers..."

    # start iperf client transfers
    iperf_min = 1.63 * 1000 * 8
    std_bw = standardize_bw(per_transfer_bandwidth)
    for i in range(0, len(hosts_src)):
        src = hosts_src[i]
        src_client_file = client_prefix + '-' + src.name + '.txt'
        if std_bw[i] >= iperf_min:
            src.cmd("iperf -fK -t " + str(test_duration_sec) + " -c " +
                    hosts_dst[i].IP() + " -u -p 5002 -b " +
                    per_transfer_bandwidth[i] + " 2>&1 > " + src_client_file +
                    "&")
        else:
            print ("Avoiding transfer %s ---> %s because target bandwidth is too"
                   " low" % (src.name, hosts_dst[i].name))
    print "Client transfers initiated."

def get_interfaces(intr_list):
    """ Helper function to get tshark interface argument for a switch sw, whose
    interfaces in interface_list must be captured."""
    return reduce(lambda r, intr: r + "-i " + intr + " ", intr_list, ' ')

def get_fds_processes(cmds, files):
    """ Helper function to get the processes and output files of commands
    specified in `cmds`, with corresponding output/error streams written to
    entries in `files`."""
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

def setup_overhead_statistics_global(overheads_filter, overheads_file,
                                     test_duration_sec, slack):
    cmd = ("tshark -q -i lo -z io,stat,0,'" + overheads_filter + "' -f " +
           "'tcp port 6633' -a duration:" + str(test_duration_sec+3))
    f = open(overheads_file, "w")
    p = subprocess.Popen(shlex.split(cmd), stdout=f, stderr=subprocess.STDOUT)
    print "Started tshark process"
    print '--->', cmd
    return ([p], [f])

def setup_optimal_overhead_statistics(filters, interfaces, files_prefix,
                                      test_duration_sec, slack):
    """ Capture tshark statistics to calculate "optimal" overheads. """
    assert len(filters) == len(interfaces)
    cmds_list = []
    f_list = []
    for i in range(0, len(filters)):
        cmd = ("tshark -q -f " + filters[i] + ' ' +
               get_interfaces(interfaces[i]) +
               " -z io,stat,0 -a duration:" + str(test_duration_sec+3))
        print '--->', cmd
        f_list.append('%s-%d.txt' % (files_prefix, i+1))
        cmds_list.append(cmd)
    return get_fds_processes(cmds_list, f_list)

def run_tshark_full_traffic_measurement(internal_ints, external_ints,
                                        test_duration_sec, total_traffic_prefix,
                                        slack):
    """Given a list of "internal" and "external"-facing interfaces in the
    network, set up tshark captures to count the number of total packets on all
    the links in the network (separate traffic counted once and twice for later
    merging). This function is generic across test cases.
    """
    def get_tshark_cmd_file(interfaces, file_suffix):
        cmd = ("tshark -f inbound -q " + get_interfaces(interfaces) +
               " -z io,stat,0 -a duration:" + str(test_duration_sec+3))
        print '--->', cmd
        fname = total_traffic_prefix + file_suffix
        return (cmd, fname)

    def get_ints_grouped_list(ints_list, k=4):
        """ Capture k interfaces at a time to avoid kernel OOM killer """
        assert isinstance(k, int) and k > 0
        assert len(ints_list) > 1
        curr_k = 0
        curr_list = []
        all_ints = []
        for i in ints_list:
            curr_k += 1
            if curr_k < (k+1):
                curr_list.append(i)
            else: # create a new sublist of interfaces, appending the current
                  # one to "all interfaces" list
                all_ints.append(copy.copy(curr_list))
                curr_list = [i]
                curr_k = 1
        assert curr_k <= k
        all_ints.append(curr_list)
        assert len(all_ints) == len(ints_list) / 4
        assert (len(all_ints[-1]) % k) == (len(ints_list) % k)
        return all_ints

    int_groups = get_ints_grouped_list(external_ints + internal_ints, 4)
    group_num = 1
    cmds_list = []
    f_list = []
    for group in int_groups:
        (cmd, f) = get_tshark_cmd_file(group, '-%d.txt' % group_num)
        group_num += 1
        cmds_list.append(cmd)
        f_list.append(f)
    return get_fds_processes(cmds_list, f_list)

################################################################################
### The main function.
################################################################################

def query_test():
    """ Main """
    # Configuring the experiment.
    args = parse_args()

    # Get path adjustment function
    adjust_path = get_adjust_path(args)

    # Global parameters used by specific tests as well
    listen_port = args.listen_port
    test_duration_sec = args.test_duration_sec
    slack_factor = args.slack_factor
    controller_debug_mode = args.controller_debug_mode
    test = args.test

    # Global parameters not used elsewhere outside this function
    overheads_file = adjust_path("overhead-traffic.txt")
    optimal_files_prefix = adjust_path("optimal-overhead")
    c_out = adjust_path("pyretic-stdout.txt")
    c_err = adjust_path("pyretic-stderr.txt")
    iperf_client_prefix = adjust_path("client-udp")
    iperf_server_prefix = adjust_path("server-udp")
    params_file = adjust_path("params.txt")
    tshark_wait_slack_sec = 3

    # Explicit spelling-out of testwise parameters for pyretic controller
    testwise_params = get_testwise_params(test, args)

    # Hack to set pythonpath.
    pypath = "/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox"
    test_module_path = "pyretic.evaluations.Tests."
    # Actual experiment setup.
    mn_cleanup()
    import importlib
    test_module = importlib.import_module(test_module_path + test)

    ctlr = None
    if not controller_debug_mode:
        print "Starting pyretic controller"
        ctlr = pyretic_controller(test, testwise_params, c_out, c_err, pypath)

    print "Setting up topology"
    (net, hosts, switches, topo) = setup_network(test_module, args)
    print "Setting up workload configuration"
    (hosts_src, hosts_dst, per_flow_bw) = setup_workload(test_module, args, net)

    print "Setting up handlers for graceful experiment abort"
    ovhead_stats = None
    switch_stats = None
    opt_stats    = None
    signal.signal(signal.SIGINT, get_abort_handler(controller_debug_mode, ctlr,
                                                   ovhead_stats, switch_stats,
                                                   opt_stats, net, hosts_dst))

    print "Setting up switch rules"
    if controller_debug_mode:
        print "*** YOU must start the controller separately for this to work!"
    wait_switch_rules_installed(switches)

    '''
    print "Setting up overhead statistics measurements"
    ovhead_stats = setup_overhead_statistics(test, overheads_file,
                                             test_duration_sec,
                                             slack_factor)

    print "Setting optimal overheads measurements"
    opt_stats = setup_optimal_overheads_global(test,
                                               optimal_files_prefix,
                                               test_duration_sec,
                                               slack_factor)

    print "Setting up collectors for total traffic"
    switch_stats = setup_full_traffic_measurement(test, args, switches)
    
    print "Resetting abort handler to tackle overhead stats"
    signal.signal(signal.SIGINT, get_abort_handler(controller_debug_mode, ctlr,
                                                   ovhead_stats, switch_stats,
                                                   opt_stats, net, hosts_dst))
    

    
    # print "Testing network connectivity"
    # ping_flow_pairs(net, hosts_src, hosts_dst)

    # Wait for tshark to start up
    print "Waiting for tshark to start up..."
    time.sleep(tshark_wait_slack_sec)

    print "Starting iperf tests"
    run_iperf_test(net, hosts_src, hosts_dst, test_duration_sec, per_flow_bw,
                   iperf_client_prefix, iperf_server_prefix)

    print ("Running iperf transfer tests. This may take a while (" +
           str(test_duration_sec) + " seconds)...")
    time.sleep(test_duration_sec)
    print "Experiment done!"

    # Wrapping up and cleaning up
    print "Writing down experiment parameters for successful completion"
    write_expt_settings(args, params_file)
    '''

    finish_up(controller_debug_mode, ctlr, ovhead_stats, switch_stats,
              opt_stats, net, hosts_dst)

    if controller_debug_mode:
        CLI(net)
        net.stop()

################################################################################
### Cleanup-related functions
################################################################################

def mn_cleanup():
    subprocess.call("sudo mn -c", shell=True)

def write_expt_settings(params, params_file):
    f = open(params_file, 'w')
    params_dict = vars(params)
    for k in params_dict.keys():
        f.write(k + " " + str(params_dict[k]) + "\n")
    f.close()

def finish_up(controller_debug_mode, ctlr, ovhead_stats, switch_stats,
              opt_stats, net, hosts_dst):
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
    if ovhead_stats:
        ([p], fds) = ovhead_stats
        kill_process(p, "tshark overhead statistics collection")
        close_fds(fds, "overhead statistics")
    # switch statistics
    if switch_stats:
        (procs, fds) = switch_stats
        for p in procs:
            kill_process(p, "tshark switch statistics collection")
        close_fds(fds, "switch statistics")
    # optimal overhead statistics
    if opt_stats:
        (procs, fds) = opt_stats
        for p in procs:
            kill_process(p, "tshark optimal overhead statistics")
        close_fds(fds, "optimal overhead statistics")
    # mininet network
    if not controller_debug_mode:
        net.stop()
        print "Killed mininet network"

def get_abort_handler(controller_debug_mode, ctlr, ovhead_stats, switch_stats,
                      opt_stats, net, hosts_dst):
    def abort_handler(signum, frame):
        finish_up(controller_debug_mode, ctlr, ovhead_stats, switch_stats,
                  opt_stats, net, hosts_dst)
        sys.exit(0)
    return abort_handler

def kill_process(p, process_str):
    print "Signaling", process_str, "for experiment completion"
    p.send_signal(signal.SIGINT)

################################################################################
### Argument parsing
################################################################################

def parse_args():
    parser = argparse.ArgumentParser(description="Run tests for query evaluations")
    parser.add_argument("--test_duration_sec", type=int,
                        help="Duration for running data transfers",
                        default=30)
    parser.add_argument("-d", "--controller_debug_mode", action="store_true",
                        help="Run controller separately for debugging")
    parser.add_argument("-t", "--test", required=True
                        , help="Test case to run")
    parser.add_argument("-l", "--listen_port", default=6634, type=int,
                        help="Starting port for OVS switches to listen on")
    parser.add_argument("--total_traffic_prefix", default="total-traffic",
                        help="Naming prefix for total traffic measurement")
    parser.add_argument("--slack_factor", default=5.0, type=float,
                        help="Slack multiple of duration for tshark interval")
    parser.add_argument("-r", "--results_folder",
                        default="./results/",
                        help="Folder to put the raw results data into")

    parser.add_argument("-targs", "--topo_args", nargs='+', type=int)

    # Test-case-specific options

    # traffic matrix
    parser.add_argument("-n", "--num_hosts", default=5, type=int,
                        help="Number of hosts")
    parser.add_argument("--query_duration_sec", default=180, type=int,
                        help="Duration after which no stat queries issued")
    parser.add_argument("--query_period_sec", default=10, type=int,
                        help="Polling frequency for switch statistics")

    # waypoint
    parser.add_argument("-v", "--violating_frac", default=0.10, type=float,
                        help="Traffic fraction violating waypoint constraints")
    parser.add_argument("-b", "--total_bw", type=int, default=1800000,
                        help="Total traffic injected into the network per sec")

    args = parser.parse_args()
    return args

def get_testwise_params(test, args):
    params = {}
    if test == "tm":
        params['n'] = str(args.num_hosts)
        params['poll'] = str(args.query_period_sec)
        params['test_duration'] = str(args.query_duration_sec)
    elif test == "waypoint":
        params['violating_frac'] = str(args.violating_frac)
        params['total_bw'] = str(args.total_bw)
    #else:
     #   print "Error! Requesting test-wise-args for unknown test", test
      #  sys.exit(1)
    return params

def get_adjust_path(args):
    """ Return a function that adjusts the path of all file outputs into the
    results folder provided in the arguments.
    """
    results_folder = args.results_folder
    def adjust_path(rel_path):
        return os.path.join(results_folder, rel_path)
    return adjust_path

################################################################################
### Call to main function
################################################################################
if __name__ == "__main__":
    setLogLevel('info')
    query_test()
