import subprocess, shlex, os, sys, argparse, string

################################################################################
### Parameter sweep functions
################################################################################

def sweep_waypoint_fractions():
    """ Sweep across fractions of waypoint constraint violating traffic for the
    "waypoint" test case for mininet_setup.py.

    Generating plots using this script requires installing some additional
    packages in the VM:

    sudo apt-get install gnuplot-x11 texlive-font-utils
    """
    def get_runwise_folder(frac):
        return adjust_path("waypoint-" + frac)

    args = parse_args()
    results_base_folder = args.results_base_folder
    adjust_path = get_adjust_path(results_base_folder)
    mininet_errfile = adjust_path("mininet_err.txt")
    stats_file = adjust_path("stats.txt")
    plot_file = adjust_path("frac-vs-overhead.eps")
    plot_script = "./pyretic/evaluations/pubplot.py"
    stats = []

    # Fix details of the sweep first (as it's used in multiple stages)
    frac_list = []
    for index in range(0,11):
        frac_list.append(str(0.10 * index))

    # Run mininet tests
    if not args.no_mininet:
        print "***Starting sweep for different waypoint violation fractions..."
        for frac in frac_list:
            print "Fraction", frac, "mininet test running ..."
            folder = get_runwise_folder(frac)
            create_folder_if_not_exists(folder)
            run_mininet_test({'test': 'waypoint',
                              'violating_frac': frac,
                              'results_folder': folder}, mininet_errfile)

    # Extract stats from runs
    if not args.no_stats:
        print "***Getting stats from mininet raw output data..."
        for frac in frac_list:
            print "Extracting fraction", frac, "statistics..."
            folder = get_runwise_folder(frac)
            single_run_stats = get_single_run_stats(folder, ["h1"])
            stats.append((frac, single_run_stats))
        write_stats(stats, stats_file)

    # Generate plots
    if not args.no_plots:
        print "***Generating plots for waypoint sweep experiment..."
        generate_waypoint_graph(stats_file, plot_file, plot_script)

    print "***Done!"

################################################################################
### Helpers for parameter sweep
################################################################################

def get_cl_string(params):
    """ Get command-line parameter string from a dictionary. """
    return reduce(lambda r, k: r + '--' + k + '=' + params[k] + ' ',
                  params.keys(), ' ')

def run_mininet_test(params, mininet_errfile):
    """ Running a single experiment run on mininet + pyretic. """
    cmd = ("sudo python pyretic/evaluations/mininet_setup.py" +
           get_cl_string(params))
    mininet_err = open(mininet_errfile, 'w')
    output = subprocess.check_output(cmd, shell=True, stderr=mininet_err)
    mininet_err.close()

def create_folder_if_not_exists(folder):
    output = subprocess.check_output("if [ ! -d " + folder + " ]; then mkdir " +
                                     folder + " ; fi", shell=True)

def write_stats(stats, stats_file):
    """ Write stats into a data file for plotting. """
    f = open(stats_file, 'w')
    f.write('# frac overhead_bytes total_bytes queried_bytes(iperf)\n')
    for (frac, byte_stats) in stats:
        f.write(str(frac) + ' ' + repr(byte_stats) + '\n')
    f.close()

def generate_waypoint_graph(stats_file, plot_output_file, plot_script):
    """ Given a stats file, and a plot_output_file, generate a publication
    quality plot with the given data using plot_script.
    """
    def change_file_extension(f):
        parts = f.split('.')
        return string.join(parts[:-1], '.') + '.pdf'

    cmd = ('sudo python ' + plot_script + ' -g -a ' +
           '"font ' + "'Helvetica,24'" + '" ' +
           '-p 2 -f "postscript enhanced color" ' +
           '-o ' + plot_output_file + ' ' +
           '-k "left top" ' +
           '-x "Fraction of traffic satisfying waypoint query" ' +
           '-y "Fraction overhead/total bytes" ' +
           '--xrange "[0:1]" ' +
           '--bmargin 5.2 --rmargin 4.3 ' +
#           stats_file + ' "#bytes at collector" "1:2" ' +
#           stats_file + ' "#bytes satisfying query" "1:3" ' +
#           stats_file + ' "fraction overhead/total bytes" "1:(\$2/\$3)" ' +
           stats_file + ' "" "1:(\$2/\$3)" ' +
           ' | gnuplot')
    out = subprocess.check_output(cmd, shell=True)
    pdf_cmd = 'epstopdf ' + plot_output_file + ' --autorotate=All'
    out = subprocess.check_output(pdf_cmd, shell=True)
    print ("Plots are at " + plot_output_file + " and " +
           change_file_extension(plot_output_file))

################################################################################
### Statistics from a single run
################################################################################
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
    return float(kbytes.strip()) * 1000

def has_pyretic_error(error_file):
    """ Detect if pyretic controller had an error output. """
    cmd = "wc -l " + error_file + " | awk '{print $1}'"
    error_lines = subprocess.check_output(cmd, shell=True)
    return int(error_lines.strip()) > 0

class run_stat:
    def __init__(self, overhead_bytes, total_bytes, queried_bytes):
        self.overhead_bytes = overhead_bytes
        self.total_bytes = total_bytes
        self.queried_bytes = queried_bytes

    def __repr__(self):
        return (str(self.overhead_bytes) + ' ' +
                str(self.total_bytes) + ' ' +
                str(self.queried_bytes) )

def get_single_run_stats(results_folder, queried_hosts):
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
        return run_stat(ovhead_bytes, total_bytes, queried_bytes)
    else:
        return None # signals an error in pyretic during the experiment run!

def single_stat_test():
    """ Some local testing. Can use this after running mininet_setup.py with
    default args.
    """
    results_folder = "./pyretic/evaluations/results/"
    queried_hosts = ["h1"]
    stats = get_single_run_stats(results_folder, queried_hosts)
    print stats

################################################################################
### Argument parsing to select sub-parts of the sweep to run
################################################################################

def parse_args():
    parser = argparse.ArgumentParser(description="Run tests & extract results")
    parser.add_argument("-s", "--sweep", choices=['waypoint'],
                        default='waypoint', help="Select experiment to sweep")
    parser.add_argument("--no_mininet", action="store_true",
                        help="Don't run mininet experiments")
    parser.add_argument("--no_stats", action="store_true",
                        help="Don't generate any stats")
    parser.add_argument("--no_plots", action="store_true",
                        help="Don't generate any plots")
    parser.add_argument("-r", "--results_base_folder",
                        default="./pyretic/evaluations/results/waypoint",
                        help="Folder to put results of experiments")

    args = parser.parse_args()
    return args

################################################################################
### Call to main function
################################################################################

if __name__ == "__main__":
    sweep_waypoint_fractions()
