from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
import subprocess, shlex, time, signal, os, sys
from threading import Timer
import time
import argparse
import copy

import sys
sys.path.append('/home/mininet/pyretic')
import pyretic.evaluations.stat
################################################################################
#### setup functions
################################################################################

def get_dpctl(sw_id):
    try:
        trial_cmd = subprocess.check_output(['dpctl', '--help'])
        cmd = "dpctl dump-flows tcp:localhost:%d | grep -v cookie=0 | grep -v \
               'stats_reply' | grep -v cookie=0 | wc -l" % sw_id
    except OSError:
        cmd = "ovs-ofctl dump-flows tcp:127.0.0.1:%d | grep -v cookie=0x0 | \
               grep -v REPLY | grep -v cookie=0x0 | wc -l" % sw_id
    return cmd

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
    
            
def report_rule_counts(switches, file_path):
    f = open(file_path, 'a')
    f.write('rule count statistics: \n')
    rule_cnt = {} 
    for s in switches:
        switch_num = int(s.name[1:])
        rules = s.cmd(get_dpctl(6633 + switch_num))
        rules = int(rules)
        rule_cnt[s.name] = rules

    total = sum(rule_cnt.values())
    average = float(total) / len(rule_cnt)
    f.write('switch count: ' + str(len(rule_cnt)) + '\n')
    f.write('total rule count: ' + str(total) + '\n')
    f.write('average rule count: ' + str(average) + '\n')
    f.write('------details-------\n')
    for s in rule_cnt:
        f.write(s + " -> " + str(rule_cnt[s]) + "\n")
    f.write('--------end--------\n')
    f.close()
        

################################################################################
### Essentials test setup functions on all test cases
################################################################################

def pyretic_controller(test, testwise_params, c_out, c_err, pythonpath, results_path, args):
    c_outfile = open(c_out, 'w')
    c_errfile = open(c_err, 'w')
    # Hackety hack. I don't know of any other way to supply the PYTHONPATH
    # variable for the pyretic controller!
    py_env = os.environ.copy()
    if not "PYTHONPATH" in py_env:
        py_env["PYTHONPATH"] = pythonpath

    optimize_flags = ''
    if args.disjoint_enabled:
        optimize_flags += '-d '
    if args.integrate_enabled:
        optimize_flags += '-i '
    if args.multitable_enabled:
        optimize_flags += '-u '
    if args.ragel_enabled:
        optimize_flags += '-r '

    cmd = ("pyretic.py " + optimize_flags + " -m p0 pyretic.evaluations.eval_path -e " + results_path  + " --test=" + test +
           reduce(lambda r, k: r + ("--" + k + "=" + testwise_params[k] + " "),
                  testwise_params.keys(), " "))
    c = subprocess.Popen(shlex.split(cmd), stdout=c_outfile, stderr=c_errfile,
                         env=py_env)
    return ([c], [c_outfile, c_errfile])

def wait_switch_rules_installed(switches, wait_timeout=0):
    """This function waits for switch rule installation to stabilize on all
    switches before running tests.
    """
    print "Waiting for switch rule installation to complete..."
    not_fully_installed = True
    num_rules = {}
    num_iterations = 0
    per_iter_timeout = 3
    time_waited = 0
    while not_fully_installed and wait_timeout and time_waited < wait_timeout:
        num_iterations += 1
        time_waited = per_iter_timeout * num_iterations
        not_fully_installed = False
        for s in switches:
            if not s in num_rules:
                num_rules[s] = 0
            rules = s.cmd(get_dpctl(6633 + int(s.name[1:])))
            rules = int(rules)
            if not (rules == num_rules[s] and rules > 2): # not converged!
                not_fully_installed = True
                print '.'
            num_rules[s] = rules
        print num_rules.values()
        time.sleep(per_iter_timeout)
    print
    if time_waited >= wait_timeout:
        print "!!! Rules *not* fully installed within the timeout!"
        return False
    else:
        print "Rules fully installed after waiting", time_waited, "seconds"
        return True

################################################################################
### The main function.
################################################################################

def query_test():
    """ Main """
    # Configuring the experiment.
    args = parse_args()
    results_path = args.results_folder
    
    if not os.path.exists(results_path):
        os.makedirs(results_path)
        
    # Get path adjustment function
    adjust_path = get_adjust_path(results_path)


    for f in os.listdir(results_path):
        fpath = adjust_path(f)
        os.unlink(fpath)
    # Global parameters used by specific tests as well
    listen_port = args.listen_port
    test_duration_sec = args.test_duration_sec
    slack_factor = args.slack_factor
    test = args.test

    
    # Global parameters not used elsewhere outside this function
    c_out = adjust_path("pyretic-stdout.txt")
    c_err = adjust_path("pyretic-stderr.txt")
    s_cnt = adjust_path("rule-count.txt") 
    

    params_file = adjust_path("params.txt")

    # Explicit spelling-out of testwise parameters for pyretic controller
    testwise_params = get_testwise_params(test, args)

    # Hack to set pythonpath.
    pypath = "/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox"
    test_module_path = "pyretic.evaluations.Tests."
    # Actual experiment setup.
    mn_cleanup()
    import importlib
    test_module = importlib.import_module(test_module_path + test)


    print "Starting pyretic controller"
    ctlr = pyretic_controller(test, testwise_params, c_out, c_err, pypath, results_path, args)

    print "Setting up topology"
    (net, hosts, switches, topo) = setup_network(test_module, args)
    print "Setting up workload configuration"
    (hosts_src, hosts_dst, per_flow_bw) = setup_workload(test_module, args, net)

    print "Setting up handlers for graceful experiment abort"
    ovhead_stats = None
    switch_stats = None
    opt_stats    = None
    signal.signal(signal.SIGINT, get_abort_handler(False, ctlr,
                                                   ovhead_stats, switch_stats,
                                                   opt_stats, net, hosts_dst))
    
    
    print "Setting up switch rules"
    wait_switch_rules_installed(switches)

    report_rule_counts(switches,s_cnt)
    
    #net.pingAll()
    #report_rule_counts(switches, s_cnt)
 
    if(args.cli):
        CLI(net)
    

    write_expt_settings(args, params_file)

    finish_up(False, ctlr, ovhead_stats, switch_stats,
              opt_stats, net, hosts_dst)
    
    

       

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
    parser.add_argument("-t", "--test", required=True
                        , help="Test case to run")
    parser.add_argument("-l", "--listen_port", default=6634, type=int,
                        help="Starting port for OVS switches to listen on")
    parser.add_argument("-f", "--results_folder",
                        default="./results/",
                        help="Folder to put the raw results data into")

    parser.add_argument("-targs", "--topo_args", nargs='+', type=int)

    
    parser.add_argument("-x", "--cli", action="store_true") 
    parser.add_argument("-profile", "--profile", action="store_true") 
    parser.add_argument("-polargs", "--policy_args", nargs='+')
    
    
    parser.add_argument( '--enable_disjoint', '-d', action="store_true",
                    dest="disjoint_enabled",
                    help = 'enable disjoint optimization')

    parser.add_argument('--enable_integration', '-i', action="store_true",
                    dest='integrate_enabled',
                    help = 'enable integration of tag and capture optimization, only works with multitable on')

    parser.add_argument('--enable_multitable', '-u', action="store_true",
                    dest = 'multitable_enabled',
                    help = 'enable multitable optimization')

    parser.add_argument('--enable_ragel', '-r', action="store_true",
                    dest = 'ragel_enabled',
                    help = 'enable ragel optimization')


    parser.add_argument('--enable_partition', '-s', type=int,
                    dest = 'switch_cnt',
                    help = 'enable partition optimization')

    
    #traffic arguments
    parser.add_argument("--total_traffic_prefix", default="total-traffic",
                        help="Naming prefix for total traffic measurement")
    parser.add_argument("--slack_factor", default=5.0, type=float,
                        help="Slack multiple of duration for tshark interval")
    
    
    args = parser.parse_args()
    return args



def get_testwise_params(test, args):
    params = {}
    if args.policy_args:
        arg_iter = iter(args.policy_args)
        for arg in arg_iter:
            val = next(arg_iter)
            params[arg] = val
    print params
    return params

def get_adjust_path(results_folder):
    """ Return a function that adjusts the path of all file outputs into the
    results folder provided in the arguments.
    """
    def adjust_path(rel_path):
        return os.path.join(results_folder, rel_path)
    return adjust_path

################################################################################
### Call to main function
################################################################################
if __name__ == "__main__":
    setLogLevel('info')
    query_test()
