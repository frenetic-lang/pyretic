from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.core.language_tools import *
from pyretic.modules.mac_learner import *
from pyretic.lib.query import *

test_global = lambda p: hackathon_ast_map(localized_copy, p, False)

class local_packets(LocalDynamicPolicy, packets):
    def __init__(self):
        super(local_packets, self).__init__()

class local_fwdbucket(LocalDynamicPolicy, FwdBucket):
    def __init__(self):
        super(local_fwdbucket, self).__init__()

class local_mac_learner(LocalDynamicPolicy, mac_learner):
    def __init__(self):
        super(local_mac_learner, self).__init__()

if __name__ == "__main__":

    # local_mac_learner = LocalDynamicPolicy(mac_learner())

    # local_fwdbucket = LocalDynamicPolicy(FwdBucket())
    
    # local_packets = LocalDynamicPolicy(packets())

    pol = [
        drop,
        match(srcip='10.0.0.1'),
        local_mac_learner(),
        local_fwdbucket(),
        local_packets()
        ]

    print '***'
    for p in pol:
        print test_global(p)
        print '***'
        
