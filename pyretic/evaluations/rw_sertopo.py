#!/usr/bin/python

import sys
import argparse

''' Read a topo.txt file and rewrite to an isomorphic graph, but with serially
ordered vertices. This ensures that if there are N nodes in the graph, they are
always numbered 1 ... N, to ensure predicate partitioning in the path library
works smoothly. '''

nodemap = {}
nodecnt = 0

def get_sw(sw):
    global nodemap, nodecnt
    if sw in nodemap:
        return nodemap[sw]
    else:
        nodecnt += 1
        nodemap[sw] = nodecnt
        return nodecnt

def get_topo(fname):
    edge_map = {}
    link_list = []
    f = open(fname, 'r')
    in_edge = False
    in_link = False
    for line in f.readlines():
        if 'edge' in line:
            in_edge = True
        elif 'link' in line:
            in_edge = False
            in_link = True
        elif in_edge:
            parts = [x.strip() for x in line.split()]
            sw = get_sw(int(parts[0]))
            ports = ' '.join(parts[1:])
            edge_map[sw] = ports
        elif in_link:
            parts = [x.strip() for x in line.split()]
            src = get_sw(int(parts[0]))
            dst = get_sw(int(parts[1]))
            bw = parts[2]
            link_list.append((src, dst, bw))
    
    return edge_map, link_list

def print_new_topo(edge_map, link_list):
    print 'edges'
    for sw in edge_map:
        print sw, edge_map[sw]
    print 'links'
    for (src,dst,bw) in link_list:
        print src, dst, bw

if __name__ == "__main__":
    fname = sys.argv[1]
    res = get_topo(fname)
    print_new_topo(*res)

