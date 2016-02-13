from pyretic.core.language import *
from pyretic.lib.path import *
from pyretic.core.netkat import cls_to_pol
from pyretic.core.classifier import Rule, Classifier
import networkx as nx

PORT_ID_MULTIPLIER = 1
INTERMEDIATE_PORT_TYPE_CONST = 1
OUTPUT_PORT_TYPE_CONST = 2
PORT_TYPE_MULTIPLIER = 10000
SWITCH_ID_MULTIPLIER = 100000

DUMMY_SWITCH_BASE = 1000

port_map_file = "pyretic/examples/stanford_data/port_map.txt"
topo_file = "pyretic/examples/stanford_data/backbone_topology.tf"

def load_ports(filename):
    ports = {}
    f = open(filename, 'r')
    for line in f:
        if not line.startswith("$") and line != "":
            tokens = line.strip().split(":")
            port_flat = int(tokens[1])
            
            dpid = port_flat / SWITCH_ID_MULTIPLIER
            port = port_flat % PORT_TYPE_MULTIPLIER
            
            if dpid not in ports.keys():
                ports[dpid] = set()
            if port not in ports[dpid]:
                ports[dpid].add(port)             
    f.close()
    return ports
        
def load_topology(filename):
    links = set()
    f = open(filename, 'r')
    for line in f:
        if line.startswith("link"):
            tokens = line.split('$')
            src_port_flat = int(tokens[1].strip('[]').split(', ')[0])
            dst_port_flat = int(tokens[7].strip('[]').split(', ')[0])
            links.add((src_port_flat, dst_port_flat))
    f.close()
    return links
        
def get_topo_info(port_map_file, topo_file):

    topo = nx.Graph()
    link_port_map = {}
    
    # Read topology info
    ports = load_ports(port_map_file)        
    links = load_topology(topo_file)
    switches = ports.keys()

    sw_port_max = {}
    # Create switch nodes
    for s in switches:
        topo.add_node(s, isHost = False)
        if not s in link_port_map:
            link_port_map[s] = {}
            sw_port_max[s] = 1
        
    # Wire up switches       
    link_set = set()
    for (src_port_flat, dst_port_flat) in links:
        src_dpid = src_port_flat / SWITCH_ID_MULTIPLIER
        dst_dpid = dst_port_flat / SWITCH_ID_MULTIPLIER

        if not (src_dpid, dst_dpid) in link_set:
            port1 = sw_port_max[src_dpid]
            port2 = sw_port_max[dst_dpid]
            topo.add_edge(src_dpid, dst_dpid)
            link_port_map[src_dpid][dst_dpid] = port1
            link_port_map[dst_dpid][src_dpid] = port2
            sw_port_max[src_dpid] += 1
            sw_port_max[dst_dpid] += 1
            link_set.add((src_dpid, dst_dpid))
            link_set.add((dst_dpid, src_dpid))

    # Wire up hosts
    host_id = len(switches) + 1
    for s in switches:
        # Edge ports
        topo.add_node( host_id, isHost = True )
        topo.add_edge( host_id, s)
        link_port_map[s][host_id] = sw_port_max[s]
        sw_port_max[s] += 1
        host_id += 1
    
    return topo, link_port_map

topo, link_port_map = get_topo_info(port_map_file, topo_file)

def get_shortest_paths(topo):
    edge_nodes = [n for n in topo.nodes() if topo.node[n]["isHost"]]
    shortest_paths = []
    for u in edge_nodes:
        paths = nx.single_source_shortest_path(topo, u)
        for v in edge_nodes:
            if u != v:
                shortest_paths.append(paths[v])
    return shortest_paths

def get_forwarding_policy(topo, link_port_map):
    #rules = []

    pol = None
    base_ip = "10.0.%d.1"

    edge_nodes = [n for n in topo.nodes() if topo.node[n]["isHost"]]
    core_nodes = [n for n in topo.nodes() if topo.node[n]["isHost"] == False]

    # print "start"
    for u in edge_nodes: 
        dst_ip = base_ip % (u - 1)       
        
        paths = nx.single_source_shortest_path(topo, u)
        for v in edge_nodes:
            if u != v:
                pass
                # print u, v, paths[v]
        for s in core_nodes:
            next_hop = paths[s][-2]
            #m = match(switch = s, dstip = dst_ip).compile().rules[0].match 
            #act = fwd(link_port_map[s][next_hop]).compile().rules[0].actions
            if pol:
                pol += match(switch = s, dstip = dst_ip) >> fwd(link_port_map[s][next_hop])
            else:
                pol = match(switch = s, dstip = dst_ip) >> fwd(link_port_map[s][next_hop])

            #rules.append(Rule(m, act))
    return pol
    #return cls_to_pol(Classifier(rules))

def get_sample_query(topo):
    return in_atom(match(srcip='10.0.18.1', dstip='10.0.19.1'))

def get_firewall_query(topo):
    switches = [n for n in topo.nodes() if not topo.node[n]["isHost"]]
    fw = 1
    pol = None
   
    edge_predicate = None
        
    for sw in switches:
        if sw == fw:
            continue
        p = len(nx.neighbors(topo, sw))
        if edge_predicate is None:
            edge_predicate = match(switch = sw, port = p)
        else:
            edge_predicate |= match(switch = sw, port = p)
        

    pol = in_atom(edge_predicate) ^ +(in_atom(~match(switch = fw))) ^ out_atom(edge_predicate) 
    
    def call_back(pkt):
        print pkt
    pol.register_callback(call_back)
    return pol  

def path_main(**kwargs):
    # return get_sample_query(topo)
    return get_firewall_query(topo) 

def main(**kwargs):
    return get_forwarding_policy(topo, link_port_map) 

if __name__ == "__main__":
    port_map_file = "pyretic/examples/stanford_data/port_map.txt"
    topo_file = "pyretic/examples/stanford_data/backbone_topology.tf"

    topo, link_port_map = get_topo_info(port_map_file, topo_file)
    #nx.write_dot(topo, "stanford.dot")
    get_forwarding_policy(topo, link_port_map)
