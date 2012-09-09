
from frenetic.lib import *

def learning_switch(network):
    policy = flood
    network.install_policy(policy)

    host_to_outport = {}
    for pkt in network.query(all_packets, fields=["switch", "srcmac"]):
        host_p = (_.switch == pkt.switch) & (_.dstmac == pkt.srcmac)
        outport = host_to_outport.get((pkt.switch, pkt.srcmac))

        if outport == pkt.inport:
            continue

        host_to_outport[(pkt.switch, pkt.srcmac)] = pkt.inport
           
        policy -= host_p    # Don't do our old action.
        policy |= host_p & fwd(pkt.inport)  # Do this instead.
        network.install_policy(policy)

start(learning_switch)


