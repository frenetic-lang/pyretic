from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import CPULimitedHost, RemoteController
from mininet.cli import CLI
from extratopos import *
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
        rules = s.cmd("dpctl dump-flows tcp:localhost:%d | grep -v \
                           'stats_reply' | grep -v cookie=0 | wc -l" % (6633 + switch_num))
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
        

def report_dfa_state_count(dfa_path, output_path):
    f = open(dfa_path, 'r')
    cnt = 0
    for line in f.readlines():
        if 'shape' in line:
            cnt += 1

    f.close()
    f = open(output_path, 'w')
    f.write('dfa state count : %d \n' % cnt)
    f.write('--------------------\n')
    f.close()   
################################################################################
#### Test-case-specific functions
################################################################################


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
            rules = s.cmd("dpctl dump-flows tcp:localhost:%d | grep -v \
                           'stats_reply' | grep -v cookie=0 | wc -l" %(6633 + int(s.name[1:])))
            rules = int(rules)
            if not (rules == num_rules[s] and rules > 2): # not converged!
                not_fully_installed = True
                print '.'
            num_rules[s] = rules
        print num_rules.values()
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


################################################################################
### The main function.
################################################################################

def query_test():
    """ Main """
    # Configuring the experiment.
    args = parse_args()
    default_results_path = './results/'
    
    if not os.path.exists(default_results_path):
        os.makedirs(default_results_path)
        
    # Get path adjustment function
    adjust_path = get_adjust_path(default_results_path)


    for f in os.listdir(default_results_path):
        fpath = adjust_path(f)
        os.unlink(fpath)
    # Global parameters used by specific tests as well
    listen_port = args.listen_port
    test_duration_sec = args.test_duration_sec
    slack_factor = args.slack_factor
    controller_debug_mode = args.controller_debug_mode
    test = args.test

    
    # Global parameters not used elsewhere outside this function
    c_out = adjust_path("pyretic-stdout.txt")
    c_err = adjust_path("pyretic-stderr.txt")
    s_cnt = adjust_path("rule-count.txt") 
    

    iperf_client_prefix = adjust_path("client-udp")
    iperf_server_prefix = adjust_path("server-udp")
    params_file = adjust_path("params.txt")
    tshark_wait_slack_sec = 3

    # Explicit spelling-out of testwise parameters for pyretic controller
    testwise_params = get_testwise_params(test, args)

    # Hack to set pythonpath.
    pypath = "/home/mininet/pyretic:/home/mininet/mininet:/home/mininet/pox"
    test_module_path = "pyretic.evaluations.Tests."
    dfa_path = "/tmp/pyretic-regexes.txt.dot"
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

    report_dfa_state_count(dfa_path, s_cnt)
    report_rule_counts(switches,s_cnt)
    
    #net.pingAll()
    #report_rule_counts(switches, s_cnt)
 
    if(args.cli):
        CLI(net)
    

    write_expt_settings(args, params_file)

    finish_up(controller_debug_mode, ctlr, ovhead_stats, switch_stats,
              opt_stats, net, hosts_dst)
    
    
    if controller_debug_mode:
        CLI(net)
        net.stop()

    create_overall_report(default_results_path, s_cnt)
    create_excel_report(default_results_path, s_cnt)
    import shutil
    shutil.move(default_results_path, args.results_folder)
    shutil.copy('/tmp/pyretic-regexes.txt.dot', args.results_folder)
    shutil.copy('/tmp/symbols.txt', args.results_folder)
        

################################################################################
### Cleanup-related functions
################################################################################

def create_overall_report(results_path, s_cnt):
    adjust_func = get_adjust_path(results_path)
    f = open(adjust_func('performance_report.txt'), 'w')

    g = open(s_cnt, 'r');
    for line in g.readlines():
        f.write(line)
    g.close()

    files = os.listdir(results_path)
    profiles = [ p for p in files if (".profile" in p)]
    cls = [p for p in files if ".cls" in p]

    for prof in profiles:
        g = open(adjust_func(prof), 'r')
        name = prof[:-8]
        f.write(name + '\n')
        for line in g.readlines():
            f.write(line)
        g.close()
        c = [p for p in cls if name in p]
        if len(c) == 1:
            g = open(adjust_func(c[0]), 'r')
            for line in g.readlines():
                f.write(line)
        f.write('--------------------------------------\n')

    f.close() 
    

def create_excel_report(results_path, s_cnt):
    cols = [ ["makeDFA_vector", 'compile', 'forwarding_compile', 'tagging_compile', 'capture_compile', 'tag_fw_cap_compile'],
                ['vf_tag_compile', 'vf_untag_compile', 'whole_policy_compile'],   
            ]

    adjust_func = get_adjust_path(results_path)
    f = open(adjust_func('excel_report.txt'), 'w')
    
    for col in cols:
        for c in col:
            cpath = adjust_func(c + '.profile')
            if os.path.exists(cpath):
                g = open(cpath, 'r')
                for line in g.readlines():
                    if "average" in line:
                        f.write(line[line.index(':') + 2 :-1] + "\t")
                        break
                g.close()
            else:
                f.write('0\t')

            cpath = adjust_func(c + '.cls')
            if os.path.exists(cpath):
                g = open(cpath, 'r')
                for line in g.readlines():
                    if "classifier" in line:
                        f.write(line[line.index(':') + 2 :-1] + "\t")
                        break
                g.close()

        f.write('\n')
    
    dfa_state_cnt = 0
    rule_cnt = 0
    rule_avg = 0
    
    g = open(adjust_func('rule-count.txt'), 'r')
    for line in g.readlines():
        if "dfa state count" in line:
            dfa_state_cnt = int(line[line.index(':') + 2:-1])

        elif 'total rule count' in line:
            rule_cnt = int(line[line.index(':') + 2 : -1])

        elif 'average rule count' in line:
            rule_avg = float(line[line.index(':') + 2 : -1])
    g.close()

    tagging_edge = 0
    capture_edge = 0
    
    g = open(adjust_func('general_stats.txt'), 'r')
    for line in g.readlines():
        if "tagging edges" in line:
            tagging_edge = int(line[line.index(':') + 2:-1])

        elif 'capture edges' in line:
            capture_edge = int(line[line.index(':') + 2 : -1])

    g.close()

    gen_list = [rule_avg, rule_cnt, dfa_state_cnt, tagging_edge, capture_edge] 

    for gen in gen_list:
        f.write(str(gen) + "\t")
    f.write('\n')        

    f.close()

           
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
    parser.add_argument("-r", "--results_folder",
                        default="./results/",
                        help="Folder to put the raw results data into")

    parser.add_argument("-targs", "--topo_args", nargs='+', type=int)

    
    parser.add_argument("-c", "--cli", action="store_true") 
    parser.add_argument("-profile", "--profile", action="store_true") 
    parser.add_argument("-polargs", "--policy_args", nargs='+')
    
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
