import sys
import os

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "specify directory"
    else:
        target = sys.argv[1]
        for dirr in os.listdir(target):
            if os.path.isdir(dirr):
                dfa_path = os.path.join(os.path.join(target, dirr), "pyretic-regexes.txt.dot")
                if os.path.exists(dfa_path):
                    states = []
                    in_edges = {}
                    out_edges = {}
                    f = open(dfa_path, 'r')
                    for line in f.readlines():
                        if not "Q" in line:
                            continue
                        if "shape" in line:
                            states.add(int(line[1:line.index('[')].strip()))
                        else:
                            arrow = line.index('->')
                            first = int(line[1:arrow].strip())
                            second = int(line[arrow + 4 : arrow + 6].strip())
                            if not first in out_edges:
                                out_edges[first] = []
                            out_edges[first].append(second)
                            if not second in in_edges:
                                in_edges[second] = []
                            in_edges[second].append(first)

                    
                    dead_state = None
                    for st in out_edges:
                        if out_edges[st] == 0:
                            dead_state = st
                            break
                    edge_cnt = [len(v) for k,v in out_edges.items()]
                    print dirr
                    print float(in_edges[dead_state]) / sum(edge_cnt)
                    print "-----------------------------------------"

