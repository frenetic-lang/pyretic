""" Generate connected waxman topologies.

Author: Srinivas Narayana (narayana@cs.princeton.edu)

Run as:

python gen-waxman.py <node-count> <alpha> <beta>

To generate topologies over a range of node counts, you could use a bash loop,
like

alpha=0.4; beta=0.2; for i in `echo 20 40 60 80 100 120 140 160 180 200`; do mkdir -p pyretic/evaluations/Tests/waxman-${alpha}-${beta}/$i ; python pyretic/evaluations/gen-waxman.py $i $alpha $beta > pyretc/evaluations/Tests/waxman-${alpha}-${beta}/${i}/original-topo.txt ; done | grep FAIL

alpha=0.4; beta=0.2; for i in `echo 20 40 60 80 100 120 140 160 180 200`; do python pyretic/evaluations/rw_sertopo.py pyretic/evaluations/Tests/waxman-${alpha}-${beta}/${i}/original-topo.txt > pyretic/evaluations/Tests/waxman-${alpha}-${beta}/${i}/topo.txt ; done

"""

import fnss
import networkx as nx
import time
import sys

n=int(sys.argv[1])
alpha=float(sys.argv[2])
beta=float(sys.argv[3])
standard_bw = 100 # dummy bandwidth value to go on topo files

disconnected = True
tries = 0
while disconnected:
    topo = fnss.waxman_1_topology(n, alpha=alpha, beta=beta)
    disconnected = not nx.is_connected(topo)
    tries += 1
    if tries == 300:
        sys.stderr.write("%d FAIL\n" % n)
        break

if not disconnected:
    print "edges"
    nodes = list(topo.nodes())
    num_nodes = len(nodes)
    for n in nodes[:int(0.7*num_nodes)]:
        print n, 'p%d' % n
    print "links"
    for (src,dst) in topo.edges():
        print src, dst, standard_bw
