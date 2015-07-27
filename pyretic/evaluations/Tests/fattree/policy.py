import sys
from pyretic.evaluations.Tests.ddos.policy import DDoSStats
from pyretic.evaluations.Tests.congested_link.policy import LinkCongestionStats
from pyretic.evaluations.Tests.firewall.policy import FirewallStats
from pyretic.evaluations.Tests.path_packet_loss.policy import PathPacketLossStats
from pyretic.evaluations.Tests.slice_isolation.policy import SliceStats
from pyretic.evaluations.Tests.traffic_matrix.policy import TrafficMatrixStats

 
def path_main(**kwargs):
    path_policy = ( LinkCongestionStats(5, 10).link_congestion_query(**kwargs) 
                   + DDoSStats(5, 10).ddos_query(**kwargs)
                   + FirewallStats(5, 10).firewall_query(**kwargs) 
                   + PathPacketLossStats(5, 10).query(**kwargs)
                   + SliceStats(5, 10).slice_isolation_query(**kwargs)
                   + TrafficMatrixStats(5, 10).traffic_matrix_query(**kwargs)
                  )
    return path_policy


def main(**kwargs):
    return identity
