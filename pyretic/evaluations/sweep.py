import subprocess, shlex, os, sys, argparse

def parseArgs():
    parser = argparse.ArgumentParser(description="Run tests & extract results")
    parser.add_argument("-r", "--results_folder",
                        default="./pyretic/evaluations/results/",
                        help="Folder where raw result files reside")
    parser.add_argument("-h", "--queried_hosts", default="h1",
                        help=("List of host names whose iperf clients count into"
                              + "queried traffic"))

    args = parser.parse_args()
    return args

def get_adjust_path(results_folder):
    """ Return a function that adjusts the path of all file outputs into the
    results folder provided in the arguments.
    """
    def adjust_path(rel_path):
        return os.path.join(results_folder, rel_path)
    return adjust_path

def get_tshark_bytes(tshark_file):
    """ Given a file with tshark bytes statistics summary, extract the number of
    bytes counted.
    """
    cmd = ('grep -A 2 "Bytes" ' + tshark_file + ' | tail -1 | ' +
           "awk -F'|' '{print $4}'")
    bytes = subprocess.check_output(cmd, shell=True)
    return int(bytes.strip())

def get_iperf_client_bytes(client_file):
    """ Given an iperf file (total transfer reported in KBytes), extract the
    number of bytes sent.
    """
    cmd = ("grep -B 2 Sent " + client_file + " | grep '0.0-' | tail -1  | awk "
           + " '{print $5}'")
    kbytes = subprocess.check_output(cmd, shell=True)
    return int(kbytes.strip()) * 1000

def has_pyretic_error(error_file):
    """ Detect if pyretic controller had an error output. """
    cmd = "wc -l " + error_file + " | awk '{print $1}'"
    error_lines = subprocess.check_output(cmd, shell=True)
    return int(error_lines.strip()) > 0

def get_stats_single_run(results_folder, queried_hosts):
    """ Get statistics of interest for a single run of an experiment. 

    :param results_folder: folder where the raw result files are dumped.
    :param queried_hosts: list of host names whose iperf client files count into
    the queried traffic volume.

    This function relies on specific naming conventions in mininet_setup.py for
    specific output files which this function understands.
    """
    adjust_path = get_adjust_path(results_folder)
    overheads_file = adjust_path("tshark_output.txt")
    total_traffic_prefix = adjust_path("total-traffic")
    once_file  = total_traffic_prefix + '-once.txt'
    twice_file = total_traffic_prefix + '-twice.txt'
    iperf_client_prefix = adjust_path("client-udp")
    pyretic_stderr = adjust_path("pyretic-stderr.txt")

    if not has_pyretic_error(pyretic_stderr):
        ovhead_bytes = get_tshark_bytes(overheads_file)
        total_bytes = (get_tshark_bytes(once_file) +
                       (get_tshark_bytes(twice_file)/2.0))
        queried_bytes = 0
        for host in queried_hosts:
            client_file = iperf_client_prefix + '-' + host + '.txt'
            queried_bytes += get_iperf_client_bytes(client_file)
        return (ovhead_bytes, total_bytes, queried_bytes)
    else:
        return None # signals an error in pyretic during the experiment run!

def single_stat_test():
    """ Some local testing. Can use this after testing mininet_setup.py with
    default args.
    """
    results_folder = "./pyretic/evaluations/results/"
    queried_hosts = ["h1"]
    stats = get_stats_single_run(results_folder, queried_hosts)
    print stats

if __name__ == "__main__":
    single_stat_test()
