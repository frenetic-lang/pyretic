"""Stanford end to end experiment. All test parameters are set up through
specific functions in this file:

init_setup(**kwargs):
  used to set up common preliminaries before calling the topology, workload and
  filters setup. Note that main and path_main are invoked in a different process
  from pyretic.py, so any actions there will not persist when the former
  functions are called.

topo_setup(**kwargs):
  return a Mininet Topo object

path_main(**kwargs):
  path queries to test

main(**kwargs):
  forwarding policy

workload_setup(bw_budget, **kwargs): 
  given an overall budget of bandwidth, partition into the bandwidths between
  host pairs in the topology. These will later be implemented using iperf.

ovhead_filter_setup(**kwargs):
  a tshark capture filter to denote the packets at the controller that denote
  "overheads".

optimal_filter_setup(**kwargs):
  a list of (interface, tshark capture filter) pairs that denote packets
  constituting the "optimal" (or something close) set of packets that can be
  captured by wireshark for the query of this test
"""

from pyretic.examples.stanford_shortest_path import (
    get_topo_info, get_forwarding_policy, get_shortest_paths,
    path_main as stanford_query, main as stanford_fwding)
from local_mininet.extratopos import StanfordTopo

FW=1
NUM_SWITCHES=16
port_map_file="pyretic/examples/stanford_data/port_map.txt"
topo_file = "pyretic/examples/stanford_data/backbone_topology.tf"

def stanford_nx(topo=None):
    if topo:
        stanford_nx.topo = topo
        print "I set stanford nx topo to", topo
        return topo
    else:
        return stanford_nx.topo

def stanford_paths(paths=None):
    if paths:
        stanford_paths.paths = paths
        print "Set stanford_paths.paths to", stanford_paths.paths
        return paths
    else:
        return stanford_paths.paths

def get_acc_other_pairs_sample():
    acc_pairs = [(17, 18)]
    other_pairs = [(24, 29)]
    return (acc_pairs, other_pairs)

def get_acc_other_pairs():
    paths = stanford_paths()
    acc_pairs, other_pairs = [], []
    for p in paths:
        if not FW in p:
            acc_pairs.append((p[0], p[-1]))
        else:
            other_pairs.append((p[0], p[-1]))
    return (acc_pairs, other_pairs)

def init_setup(**kwargs):
    topo, link_port_map = get_topo_info(port_map_file, topo_file)
    paths = get_shortest_paths(topo)
    stanford_nx(topo)
    stanford_paths(paths)

def workload_setup(bw_budget, net, **kwargs):
    params = dict(kwargs)
    viol_frac = float(params.get('viol_frac', 0.3))
    print "The fraction of query-satisfying traffic is", viol_frac
    acc_pairs, other_pairs = get_acc_other_pairs()

    from random import shuffle
    shuffle(acc_pairs)
    shuffle(other_pairs)
    print "Accepted pairs:", acc_pairs
    print "Other pairs:", other_pairs
    acc_count = 3 #3
    other_count = 4 #4
    per_acc_bw = viol_frac * bw_budget / acc_count
    per_other_bw = (1-viol_frac) * bw_budget / other_count
    srcs, dsts, bws = [], [], []

    for (src, dst) in acc_pairs[:acc_count]:
        srcs.append(net.hosts[src-NUM_SWITCHES-1])
        dsts.append(net.hosts[dst-NUM_SWITCHES-1])
        bws.append(per_acc_bw)
    for (src, dst) in other_pairs[:other_count]:
        srcs.append(net.hosts[src-NUM_SWITCHES-1])
        dsts.append(net.hosts[dst-NUM_SWITCHES-1])
        bws.append(per_other_bw)
    return (srcs, dsts, bws)
    
def topo_setup(**kwargs):
    return StanfordTopo()

def ovhead_filter_setup(**kwargs):
    params = dict(kwargs)
    if 'pyopts' in params and '--nx' in params['pyopts']:
        return "of.vendor or of.pktin"
    else:
        return "of.pktin"

def optimal_filter_setup(**kwargs):
    (accs, others) = get_acc_other_pairs()
    topo = stanford_nx()
    intfs_capfs = []
    for (src, dst) in accs:
        assert len(topo.neighbors(dst)) == 1, "expected one switch per host"
        sw = topo.neighbors(dst)[0]
        intf = len(topo.neighbors(sw))
        capf = 'outbound and src net 10.0.%d.1' % (src-1)
        intfs_capfs.append(('s%d-eth%d' % (sw, intf), capf))
    return intfs_capfs

def path_main(**kwargs):
    return stanford_query(**kwargs)

def main(**kwargs):
    return stanford_fwding(**kwargs)
    # return get_forwarding_policy(topo, link_port_map)

if __name__ == "__main__":
    main()
    print get_acc_other_pairs()
