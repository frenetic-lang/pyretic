import subprocess, shlex, os, sys, argparse, string

################################################################################
### Parameter sweep functions
################################################################################

def sweep(args, runwise_folder_prefix, sweep_list, sweep_str,
          get_test_params_fun, queried_hosts, generate_graph_fun):
    """ Generic sweep function used by various sweep test cases.

    Generating plots using this script requires installing some additional
    packages in the VM:

    sudo apt-get install gnuplot-x11 texlive-font-utils
    """
    def get_runwise_folder(frac):
        return adjust_path(runwise_folder_prefix + '-' + frac)

    results_base_folder = args.results_base_folder
    create_folder_if_not_exists(results_base_folder)
    adjust_path = get_adjust_path(results_base_folder)
    mininet_errfile_suffix = "mininet_err.txt"
    stats_file = adjust_path("stats.txt")
    plot_script = "./pyretic/evaluations/pubplot.py"
    stats = []

    # Run mininet tests
    if not args.no_mininet:
        print "***Starting sweep for different " + sweep_str + " values..."
        for value in sweep_list:
            print sweep_str, value, "mininet test running ..."
            folder = get_runwise_folder(value)
            create_folder_if_not_exists(folder)
            mininet_errfile = get_adjust_path(folder)(mininet_errfile_suffix)
            run_mininet_test(get_test_params_fun(value, folder), mininet_errfile)

    # Extract stats from runs
    if not args.no_stats:
        print "***Getting stats from mininet raw output data..."
        for value in sweep_list:
            print "Extracting", sweep_str, value, "statistics..."
            folder = get_runwise_folder(value)
            single_run_stats = get_single_run_stats(folder, queried_hosts)
            stats.append((value, single_run_stats))
        write_stats(stats, stats_file)

    # Generate plots
    if not args.no_plots:
        print "***Generating plots for", sweep_str, "sweep experiment..."
        generate_graph_fun(stats_file, plot_script, adjust_path)

    print "***Done!"

def sweep_waypoint_fractions(args):
    """ Sweep access-control violating fractions for the "waypoint" test case in
    mininet_setup.
    """
    def mininet_waypoint_test_params(frac, folder):
        return {'test': 'waypoint',
                'violating_frac': frac,
                'results_folder': folder}

    sweep(args,
          "waypoint",
          map(lambda i: str(0.10 * i), range(0,11)),
          "waypoint violating fraction",
          mininet_waypoint_test_params,
          ["h1"],
          generate_waypoint_graph)

def sweep_query_periods(args):
    """ Sweep across different intervals between successive queries for the
    traffic matrix ("tm") case in mininet_setup.
    """
    num_hosts = 5
    def mininet_tm_test_params(query_period, folder):
        return {'test': 'tm',
                'query_period_sec': query_period,
                'results_folder': folder,
                'num_hosts': str(num_hosts),
                'test_duration_sec': str(180)}

    sweep(args,
          "tm",
          map(lambda i: str(5 * i), range(1, 7)),
          "query period",
          mininet_tm_test_params,
          map(lambda i: 'h'+str(i), range(1, num_hosts+1)),
          generate_tm_graph)

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
    f.write('# frac overhead_bytes total_bytes queried_bytes(iperf) optimal_ovhead_bytes\n')
    for (frac, byte_stats) in stats:
        f.write(str(frac) + ' ' + repr(byte_stats) + '\n')
    f.close()

def plot_one_quantity(stats_file, plot_output_file, plot_script, x_label,
                      y_label, x_range, fields_str, single_col=True,
                      y_range="[0:1]"):
    """ Generic function to plot one quantity versus another using the plotting
    script.
    """
    def change_file_extension(f):
        parts = f.split('.')
        return string.join(parts[:-1], '.') + '.pdf'

    if single_col:
        cmd = ('sudo python ' + plot_script + ' -g -a ' +
               '"font ' + "'Helvetica,24'" + '" ' +
               '-p 2 -f "postscript enhanced color" ' +
               '-o ' + plot_output_file + ' ' +
               '-k "left top" ' +
               '-x "' + x_label + '" ' +
               '-y "' + y_label + '" ' +
               '--xrange "' + x_range + '" ' +
               '--bmargin 5.2 --rmargin 4.3 ' +
               stats_file + ' "" "' + fields_str + '" ' +
               ' | gnuplot')
    else:
        cmd = ('sudo python ' + plot_script + '  --small -g ' +
               '-a "font ' + "'Helvetica,34'" + '" ' +
               '-p 2 -f "postscript enhanced color" ' +
               '-o ' + plot_output_file + ' ' +
               '-k "left center vertical width 20 spacing 2.0 font ' +
               "'Helvetica,34'" + '" ' +
               '-x "' + x_label + '" ' +
               '-y "' + y_label + '" ' +
               '--xrange "' + x_range + '" ' +
               '--yrange "' + y_range + '" ' +
               '--bmargin 8.5 --rmargin 5 --lmargin 17 ' +
               stats_file + ' "all packets, every hop" "' + '1:(\$3/\$3)' + '" ' +
               stats_file + ' "this paper" "' + fields_str + '" ' +
#               stats_file + ' "" "' + fields_str + '" ' +
               stats_file + ' "optimal" "' + '1:(\$5/\$3)' + '" ' +
               ' | gnuplot')
    out = subprocess.check_output(cmd, shell=True)
    pdf_cmd = 'epstopdf ' + plot_output_file + ' --autorotate=All'
    out = subprocess.check_output(pdf_cmd, shell=True)
    print ("Plots are at " + plot_output_file + " and " +
           change_file_extension(plot_output_file))

def generate_tm_graph(stats_file, plot_script, adjust_path):
    """ TM-specific function: Given a stats file, and a plot_output_file,
    generate a publication quality plot with the given data using plot_script.
    """
    plot_one_quantity(stats_file,
                      adjust_path("overhead-vs-period.eps"),
                      plot_script,
                      "Query period (sec)",
                      "Overhead (Kilobytes)",
                      "[10:30]", "1:(\$2/1000)",
                      single_col=False,
                      y_range="[0:]")

def generate_waypoint_graph(stats_file, plot_script, adjust_path):
    """ Waypoint-specific function: Given a stats file, and a plot_output_file,
    generate a publication quality plot with the given data using plot_script.
    """
    plot_one_quantity(stats_file,
                      adjust_path("overhead-vs-frac.eps"),
                      plot_script,
                      "Ratio query-satisfying/total",
                      "Ratio overhead/total",
                      "[0:1]", "1:(\$2/\$3)",
                      single_col=False, 
                      y_range="[0:1.05]")

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
    if kbytes:
        return float(kbytes.strip()) * 1000
    else:
        print "No iperf output found in %s!" % client_file
        return 0.0

def has_pyretic_error(error_file):
    """ Detect if pyretic controller had an error output. """
    cmd = "wc -l " + error_file + " | awk '{print $1}'"
    shut_err = "grep 'interpreter shutdown' " + error_file + " | wc -l"
    error_lines = subprocess.check_output(cmd, shell=True)
    shut_lines  = subprocess.check_output(shut_err, shell=True)
    return int(error_lines.strip()) > 0 and not int(shut_lines.strip()) > 0

class run_stat:
    def __init__(self, overhead_bytes, total_bytes, queried_bytes,
                 optimal_ovhead):
        self.overhead_bytes = overhead_bytes
        self.total_bytes = total_bytes
        self.queried_bytes = queried_bytes
        self.optimal_ovhead = optimal_ovhead

    def __repr__(self):
        return (str(self.overhead_bytes) + ' ' +
                str(self.total_bytes) + ' ' +
                str(self.queried_bytes) + ' ' +
                str(self.optimal_ovhead))

def get_single_run_stats(results_folder, queried_hosts):
    """ Get statistics of interest for a single run of an experiment. 

    :param results_folder: folder where the raw result files are dumped.
    :param queried_hosts: list of host names whose iperf client files count into
    the queried traffic volume.

    This function relies on specific naming conventions in mininet_setup.py for
    specific output files which this function understands.
    """
    adjust_path = get_adjust_path(results_folder)
    overheads_file = adjust_path("overhead-traffic.txt")
    total_traffic_prefix = adjust_path("total-traffic")
    total_traffic_file = total_traffic_prefix + '.txt'
    optimal_ovhead_prefix = adjust_path("optimal-overhead")
    iperf_client_prefix = adjust_path("client-udp")
    pyretic_stderr = adjust_path("pyretic-stderr.txt")

    def get_tshark_bytes_from_sequence(file_prefix):
        def get_num_files_with_prefix(pfx):
            cmd = "ls %s-*.txt | wc -l" % pfx
            return int(subprocess.check_output(cmd, shell=True))
        num_files = get_num_files_with_prefix(file_prefix)
        total_bytes = 0
        for i in range(1, num_files+1):
            f = '%s-%d.txt' % (file_prefix, i)
            total_bytes += get_tshark_bytes(f)
        return total_bytes

    if not has_pyretic_error(pyretic_stderr):
        ovhead_bytes = get_tshark_bytes(overheads_file)
        total_bytes = get_tshark_bytes_from_sequence(total_traffic_prefix)
        optimal_ovhead = get_tshark_bytes_from_sequence(optimal_ovhead_prefix)
        queried_bytes = 0
        for host in queried_hosts:
            client_file = iperf_client_prefix + '-' + host + '.txt'
            queried_bytes += get_iperf_client_bytes(client_file)
        return run_stat(ovhead_bytes, total_bytes, queried_bytes,
                        optimal_ovhead)
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
    parser.add_argument("-s", "--sweep", choices=['waypoint1', 'tm1'],
                        default='waypoint1', help="Select experiment to sweep")
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
    args = parse_args()
    if args.sweep == "waypoint1":
        sweep_waypoint_fractions(args)
    elif args.sweep == "tm1":
        sweep_query_periods(args)
