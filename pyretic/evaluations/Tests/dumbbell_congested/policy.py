from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.path import *

ip1 = IPAddr('10.0.0.1')
ip2 = IPAddr('10.0.0.2')
ip3 = IPAddr('10.0.0.3')
ip4 = IPAddr('10.0.0.4')

def edge_network_dumbbell_n(n):
    edge=None
    for i in range(1,n+1) + range(n+3,2*n+3):
        if edge:
            edge = edge | match(switch=i, port=2)
        else:
            edge = match(switch=i, port=2)
    return edge

def edge_network_cycle_4_4():
    return (
        match(switch=1, port=3) |
        match(switch=2, port=3) |
        match(switch=3, port=3) |
        match(switch=4, port=3)
    )

def static_fwding_dumbbell_n(n):
    """This method assumes the links from the dumb-bell to the edge were created
    first before the link between the two halves of the dumb-bell
    topology. Further, we assume that *all* links in one half of the dumb-bell
    were created before the links from the other half. Each switch is attached
    to exactly one host.
    """
    def get_ip_by_host(h):
        return IPAddr('10.0.0.%d' % h)
    pol_list = []
    for host in range(1,n+1):
        hip = get_ip_by_host(host)
        for sw in range(1,2*n+3):
            if sw == host:
                port = 2
            elif sw != n+1 and sw != n+2:
                port = 1
            elif sw == n+1:
                port = host
            elif sw == n+2:
                port = n+1            
            pol_list.append(match(switch=sw, dstip=hip) >> fwd(port))
    for host in range(n+3,2*n+3):
        hip = get_ip_by_host(host)
        for sw in range(1,2*n+3):
            if sw == host:
                port = 2
            elif sw != n+1 and sw != n+2:
                port = 1
            elif sw == n+1:
                port = n+1
            elif sw == n+2:
                port = host-(n+2)
            pol_list.append(match(switch=sw, dstip=hip) >> fwd(port))
    return parallel(pol_list)

def query_callback(id_str, print_counts=True):
    def actual_callback(pkt):
        if print_counts:
            print '**************'
            print datetime.now()
            print 'Test', id_str, ' -- got a callback from installed path query!'
            print pkt
            print type(pkt)
            print '**************'
    return actual_callback

def static_fwding_cycle_4_4_spanning_tree_1():
    return (
        (match(dstip=ip1) >> ((match(switch=1) >> fwd(3)) +
                              (match(switch=2) >> fwd(1)) +
                              (match(switch=3) >> fwd(1)) +
                              (match(switch=4) >> fwd(1)))) +
        (match(dstip=ip2) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(3)) +
                              (match(switch=3) >> fwd(1)) +
                              (match(switch=4) >> fwd(1)))) +
        (match(dstip=ip3) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(3)) +
                              (match(switch=4) >> fwd(1)))) +
        (match(dstip=ip4) >> ((match(switch=1) >> fwd(1)) +
                              (match(switch=2) >> fwd(2)) +
                              (match(switch=3) >> fwd(2)) +
                              (match(switch=4) >> fwd(3))))
        )

def congested_link_dumbbell_n(n):
    pol = None
    for i in range(1,n+1):
        first_match = in_atom(match(switch=i, port=2))
        for j in range(n+3,2*n+3):
            second_match = out_atom(match(switch=j, port=2))
            partial_query = (first_match ^ +in_atom(identity) ^
                             out_atom(match(switch=n+1)) ^
                             in_atom(match(switch=n+2)) ^ +in_atom(identity) ^
                             second_match) 
            if pol:
                pol += partial_query
            else:
                pol = partial_query
    return pol

def path_test_waypoint_violation_general_static():
    fw = match(switch=4)
    edge = edge_network_cycle_4_4()
    p = ((in_atom(edge & ~fw) ^ +in_atom(~fw) ^ out_atom(edge & ~fw)) |
         (in_out_atom(edge, edge & ~fw)))
    p.register_callback(query_callback("generalized_waypoint_violation_static"))
    return p

DUMBBELL_N=15

def main(**kwargs):
    return static_fwding_dumbbell_n(DUMBBELL_N)

def path_main(**kwargs):
    return congested_link_dumbbell_n(DUMBBELL_N)

# Left here for some basic testing.
# def main(**kwargs):
#     return static_fwding_cycle_4_4_spanning_tree_1()
# def path_main(**kwargs):
#     return path_test_waypoint_violation_general_static()

if __name__ == "__main__":
    print "Dummy print."
