import sys
import os


def get_dead_state(out_edges):
    for st in out_edges:
        flag = False
        for dst in out_edges[st]:
            if not dst is st:
                flag = True
                break
        if not flag:
            return st
    return None

                    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "specify directory"
    else:
        target = sys.argv[1]
        res = []
        for dirr in os.listdir(target):
            if os.path.isdir(os.path.join(target, dirr)):
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
                            states.append(int(line[1:line.index('[')].strip()))
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
                    dead_state = get_dead_state(out_edges)
                    
                    edge_cnt = [len(v) for k,v in out_edges.items()]
                    #print dirr
                    effect =  float(len(in_edges[dead_state]) - len(out_edges[dead_state])) / (sum(edge_cnt) - len(out_edges[dead_state]))
                    res.append(str(effect))
                    #print "-----------------------------------------"
        print "\n".join(res)
