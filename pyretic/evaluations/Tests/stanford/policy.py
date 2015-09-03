from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.lib.path import *
from pyretic.lib.query import counts
from pyretic.evaluations.Tests.common_modules.stanford_forwarding import *
from Topos import *

import threading
import itertools
import os
import json
import socket

from pyretic.evaluations.Tests.ddos_stanford.policy import DDosStats
from pyretic.evaluations.Tests.congested_stanford.policy import LinkCongestionStats
from pyretic.evaluations.Tests.firewall_stanford.policy import FirewallStats
from pyretic.evaluations.Tests.path_loss_stanford.policy import PathPacketLossStats
from pyretic.evaluations.Tests.slice_stanford.policy import SliceStats
from pyretic.evaluations.Tests.traffic_matrix_stanford.policy import TrafficMatrixStats


def path_main(**kwargs):
    path_policy = (DDosStats(5, 10).ddos_query() +
                   LinkCongestionStats(5, 10).link_congestion_query() +
                   FirewallStats(5, 10).firewall_query() + 
                   PathPacketLossStats(5, 10).query() + 
                   SliceStats(5, 10).slice_isolation_query() +
                   TrafficMatrixStats(5, 10).traffic_matrix_query()
                  )
    return path_policy

def main(**kwargs):
    return StanfordForwarding()


if __name__ == "__main__":
    print get_forwarding_classifier()
