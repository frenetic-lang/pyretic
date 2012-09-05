
from frenetic.lib import *

def learning_switch(network):
    policy = flood
    network.install_policy(policy)

    host_to_outport = {}
    for pkt in query(network, all_packets, fields=["switch", "srcmac"]):
        host_p = switch_p(pkt.header['switch']) & dstmac_p(pkt.header['srcmac'])
        outport = host_to_outport.get((pkt.header['switch'],pkt.header['srcmac']))

        if outport is not None and int(outport) == int(pkt.header['inport']):
            continue

        host_to_outport[(pkt.header['switch'],pkt.header['srcmac'])] = pkt.header['inport']
           
        policy -= host_p    # Don't do our old action.
        policy += host_p >> fwd(int(pkt.header['inport']))  # Do this instead.
        network.install_policy(policy)

start(learning_switch)


