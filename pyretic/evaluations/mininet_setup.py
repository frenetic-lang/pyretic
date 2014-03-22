from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from extratopos import *
import subprocess, shlex, time, signal, os, sys
from threading import Timer

################################################################################
### Cleanup-related functions
################################################################################

def mn_cleanup():
    subprocess.call("sudo mn -c", shell=True)

def finish_up(ctlr, tshark, switch_stats, net):
    def close_fds(fds, fd_str):
        for fd in fds:
            fd.close()
        print "Closed", fd_str, "file descriptors"

    print "--- Cleaning up after experiment ---"
    # controller
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
    net.stop()
    print "Killed mininet network"

def get_abort_handler(ctlr, tshark, switch_stats, net):
    def abort_handler(signum, frame):
        finish_up(ctlr, tshark, switch_stats, net)
    return abort_handler

def kill_process(p, process_str):
    print "Signaling", process_str, "for experiment completion"
    p.send_signal(signal.SIGINT)

################################################################################
#### Test-case-specific functions
################################################################################

def setup_cycle_topo(num_hosts):
    return CycleTopo(num_hosts, num_hosts)

def get_workload_setup(hosts):
    hosts_src = hosts
    hosts_dst = hosts[1:] + [hosts[0]]
    return (hosts_src, hosts_dst)

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

def measure_total_traffic(total_traffic_prefix, test_duration_sec, slack,
                          switches):
    """ Setup tshark collectors and statistics for the 'total' traffic in the
    network.
    """
    out_fds = []
    processes = []
    for s in switches:
        s_index = s.name[1:]
        local_ip = "10.0.0." + s_index

        # Traffic that gets counted exactly once into the total traffic
        cap_filter_once  = "-f 'host " + local_ip + "' "
        ints_once = ("-i " + s.name + "-eth1 -i " + s.name + "-eth2 -i " + s.name
                     + "-eth3 ")
        cmd_once = ("tshark -q " + ints_once + cap_filter_once +
                    "-z io,stat," + str(slack * test_duration_sec))
        file_once = s.name + '-' + total_traffic_prefix + '-once.txt'

        # Traffic that gets counted twice, and needs to be halved before adding
        # into total traffic volume
        cap_filter_twice = "-f 'not host " + local_ip + "' "
        ints_twice = "-i " + s.name + "-eth1 -i " + s.name + "-eth2 "
        cmd_twice = ("tshark -q " + ints_twice + cap_filter_twice +
                     "-z io,stat," + str(slack * test_duration_sec))
        file_twice = s.name + '-' + total_traffic_prefix + '-twice.txt'

        # Collect tshark statistics on separate slices of traffic
        out_fds.append(open(file_once, 'w'))
        processes.append(subprocess.Popen(shlex.split(cmd_once),
                                          stdout=out_fds[-1],
                                          stderr=subprocess.STDOUT))
        out_fds.append(open(file_twice, 'w'))
        processes.append(subprocess.Popen(shlex.split(cmd_twice),
                                          stdout=out_fds[-1],
                                          stderr=subprocess.STDOUT))
    return (processes, out_fds)

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
                   per_transfer_bandwidth):
    """Run UDP iperf transfers between hosts_src and hosts_dst pairs for
    test_duration_sec seconds, with a targeted bandwidth of
    per_transfer_bandwidth.
    """
    # start iperf servers
    for dst in hosts_dst:
        dst_server_file = dst.name + "-server-udp.txt"
        dst.cmd("iperf -u -s -p 5002 -i 5 > " + dst_server_file + " &")
    print "Finished starting up iperf servers..."

    # start iperf client transfers
    for i in range(0, len(hosts_src)):
        src = hosts_src[i]
        src_client_file = src.name + "-client-udp.txt"
        src.cmd("iperf -t " + str(test_duration_sec) + " -c " +
                hosts_dst[i].IP() + " -u -p 5002 -i 5 -b " +
                per_transfer_bandwidth[i] + " > " + src_client_file + "&")
    print "Client transfers initiated."

def set_up_overhead_statistics(overheads_file, test_duration_sec, slack):
    cmd = ("tshark -q -i lo -z io,stat," + str(slack * test_duration_sec) +
           ",'of.pktin||of.stats_flow_byte_count' -f 'tcp port 6633'")
    f = open(overheads_file, "w")
    p = subprocess.Popen(shlex.split(cmd), stdout=f, stderr=subprocess.STDOUT)
    print "Started tshark process"
    return ([p], [f])

################################################################################
### The main function.
################################################################################

def query_test():
    """ Main """
    # Configuring the experiment.
    num_hosts = 5
    listen_port = 6634
    test_duration_sec = 30
    per_flow_bw = ["8M"] * num_hosts
    overheads_file = "tshark_output.txt"
    slack_factor = 5 # slack for ensuring tshark statistics fall into one interval
    test = "tm"
    testwise_params = {'n': str(num_hosts)}
    c_out = "pyretic-stdout.txt"
    c_err = "pyretic-stderr.txt"
    total_traffic_prefix = "total-traffic"

    # Hack to set pythonpath.
    pypath = "/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox"

    # Actual experiment setup.
    mn_cleanup()

    print "Start pyretic controller"
    ctlr = pyretic_controller(test, testwise_params, c_out, c_err, pypath)

    print "Setting up topology"
    topo = setup_cycle_topo(num_hosts)
    net = Mininet(topo=topo, host=CPULimitedHost, controller=RemoteController,
                  listenPort=listen_port)
    net.start()
    hosts = get_hosts(net, num_hosts)
    switches = get_switches(net, num_hosts)

    print "Setting up overhead statistics measurements"
    tshark = set_up_overhead_statistics(overheads_file, test_duration_sec,
                                        slack_factor)

    print "Setting up collectors for total traffic"
    switch_stats = measure_total_traffic(total_traffic_prefix,
                                         test_duration_sec,
                                         slack_factor,
                                         switches)

    print "Setting up handlers for graceful experiment abort"
    signal.signal(signal.SIGINT, get_abort_handler(ctlr, tshark, switch_stats, net))

    print "Setting up workload configuration"
    (hosts_src, hosts_dst) = get_workload_setup(hosts)

    print "Setting up switch rules"
    wait_switch_rules_installed(switches)

    # print "Testing network connectivity"
    # ping_flow_pairs(net, hosts_src, hosts_dst)

    print "Starting iperf tests"
    run_iperf_test(net, hosts_src, hosts_dst, test_duration_sec, per_flow_bw)

    print ("Running iperf transfer tests. This may take a while (" +
           str(test_duration_sec) + " seconds)...")
    time.sleep(test_duration_sec)
    print "Experiment done!"

    # CLI(net)

    finish_up(ctlr, tshark, switch_stats, net)

if __name__ == "__main__":
    setLogLevel('info')
    query_test()
