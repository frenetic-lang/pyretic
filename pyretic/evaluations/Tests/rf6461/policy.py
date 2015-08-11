from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.path import *

import itertools
import os

import networkx as nx

def get_topo():
    topo = nx.Graph()
    edge_map = {}
    f = open('pyretic/evaluations/Tests/rf6461/topo.txt', 'r')
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
            sw = int(parts[0])
            ports = range(1, len(parts))
            edge_map[sw] = ports
        elif in_link:
            parts = [x.strip() for x in line.split()]
            src = int(parts[0])
            dst = int(parts[1])
            topo.add_edge(src, dst) 
    
    return topo, edge_map

def ddos_query(topo, edge_map):
    ports = edge_map
    switches = ports.keys()
    
    target = switches[0]

    port_pol = None
    
    target_match = None
    for p in ports[target]:
        if target_match is None:
            target_match = match(port = p)
        else:
            target_match |= match(port = p)
    
    target_match = match(switch = target) & target_match

    for sw in switches:
        if sw == target:
            continue
        sw_ports = ports[sw]
        in_port_match = None
        for p in sw_ports:
            if in_port_match is None:
                in_port_match = match(port = p)
            else:
                in_port_match |= match(port = p)

        partial_port_pol = in_atom(match(switch = sw) & in_port_match) ** out_atom(target_match) 

        if port_pol is None:
            port_pol = partial_port_pol
        else:
            port_pol += partial_port_pol
 
    return  port_pol       


def link_congestion_query(topo, edge_map):
    ports = edge_map
    switches = ports.keys()
    egress_pairs = itertools.product(switches, switches)

    cores = set(topo.nodes()) - set(switches)
    core_topo = topo.subgraph(cores)
    (s1, s2) = core_topo.edges()[0]

    pol = None
    
    for pair in egress_pairs:
        partial_match_0 = drop
        for p in ports[pair[0]]:
            partial_match_0 |= match(port = p)
        partial_match_0 = match(switch = pair[0]) & partial_match_0
        
        partial_match_1 = drop
        for p in ports[pair[1]]:
            partial_match_1 |= match(port = p)
        partial_match_1 = match(switch = pair[1]) & partial_match_1

        partial_query = in_atom(partial_match_0) ** out_atom(match(switch = s1)) ^ in_atom(match(switch = s2)) ** out_atom(partial_match_1)
        
        if pol is None:
            pol = partial_query
        else:
            pol += partial_query

    return pol        

def firewall_query(topo, edge_map):
    ports = edge_map
    switches = ports.keys()
    egress_pairs = itertools.product(switches, switches)
    
    cores = set(topo.nodes()) - set(switches)
    fw = list(cores)[0]

    pol = None
   
    in_predicate = None
    out_predicate = None
        
    for sw in switches:
        for p in ports[sw]:
            if in_predicate is None:
                in_predicate = match(switch = sw, port = p)
            else:
                in_predicate |= match(switch = sw, port = p)

            if out_predicate is None:
                out_predicate = match(switch = sw, port = p)
            else:
                out_predicate |= match(switch = sw, port = p)

    pol = in_atom(in_predicate) ^ +(in_atom(~match(switch = fw))) ^ out_atom(out_predicate) 

    return pol  


def path_loss_query(topo, edge_map):
    ip_h1 = '10.0.0.1'
    ip_h2 = '10.0.0.2'
   
    assert isinstance(topo, nx.Graph)
    
    h1 = 11
    h2 = 30

    shortest_path_length = nx.shortest_path_length(topo, h1, h2)
    paths = nx.all_simple_paths(topo, h1, h2, cutoff=shortest_path_length + 2)

    base_query = atom(match(switch = h1) & match(srcip=ip_h1) & match(dstip=ip_h2))
    
    p = base_query
    
    prefix_queries = {}
  
    cnt = 0
    for path in paths:
        cnt += 1
        partial_query = base_query
        for hop in path:
            ind = path.index(hop)
            prefix = tuple(path[:ind + 1])
            if prefix in prefix_queries:
                partial_query = prefix_queries[prefix]
            else:
                partial_query = partial_query ^ atom(match(switch = hop))
                prefix_queries[prefix] = partial_query
                p += partial_query
    return p

def get_slices(s):
    assert s < 256
    base = '10.0.%d.0/24'
    
    res = []
    for i in range(s):
        res.append(base % i)

    return res

def slice_query(topo, edge_map):    
    s = 2
    slices = get_slices(s)
    pairs = itertools.combinations(slices, 2)
    pol = None 
    
    for pair in pairs:
        slice1 = match(srcip = pair[0], dstip = pair[0])
        slice2 = match(srcip = pair[1], dstip = pair[1])

        partial_pol = in_out_atom(slice1, slice2) | in_out_atom(slice2, slice1)
        #partial_pol = in_out_atom(slice1, slice2)

        if pol is None:
            pol = partial_pol
        else:
            pol |= partial_pol
    
    return +(in_atom(identity)) ^ pol


def tm_query(topo, edge_map):
    ports = edge_map
    switches = ports.keys()
    
    egress_pairs = itertools.product(switches, switches)
    
    pol = None
    
    for pair in egress_pairs:
        partial_match_0 = drop
        for p in ports[pair[0]]:
            if partial_match_0 == drop:
                partial_match_0 = match(port = p)
            else:
                partial_match_0 |= match(port = p)
        partial_match_0 = match(switch = pair[0]) & partial_match_0
        
        partial_match_1 = drop
        for p in ports[pair[1]]:
            if partial_match_1 == drop:
                partial_match_1 = match(port = p)
            else:
                partial_match_1 |= match(port = p)
        partial_match_1 = match(switch = pair[1]) & partial_match_1

        
        partial_query = in_atom(partial_match_0) ** out_atom(partial_match_1)
        
        if pol is None:
            pol = partial_query
        else:
            pol += partial_query
    
    port_pol = None

    for sw in switches:
        sw_ports = ports[sw]
        in_port_match = None
        out_port_match = None
        for p in sw_ports:
            if in_port_match is None:
                in_port_match = match(port = p)
            else:
                in_port_match |= match(port = p)

            if out_port_match is None:
                out_port_match = match(port = p)
            else:
                out_port_match |= match(port = p)

        partial_port_pol = in_out_atom(match(switch = sw) & in_port_match, match(switch = sw) & out_port_match)

        if port_pol is None:
            port_pol = partial_port_pol
        else:
            port_pol += partial_port_pol
 
    return  pol + port_pol        

def get_queries(params):
    queries = []
    for (k, v) in sorted(params.items()):
        if 'q' in k:
            queries.append(v)
    return queries

def path_main(**kwargs):
    query_dict = {'ddos' : ddos_query, 'congested_link' : link_congestion_query,
                  'firewall' : firewall_query, 'path_loss' : path_loss_query,
                  'slice' : slice_query, 'tm' : tm_query}
    params = dict(**kwargs)
    queries = get_queries(params)
    if len(queries) == 0:
        queries = query_dict.keys()
        print 'using all queries combined'

    queries = [query_dict[q] for q in queries]
    (topo, edge_map) = get_topo()
    path_policy = None
    for q in queries:
        path_query = q(topo, edge_map)
        if path_policy is None:
            path_policy = path_query
        else:
            path_policy += path_query
    
    return path_policy

def main(**kwargs):
    return identity

if __name__ == "__main__":
    path_main()
