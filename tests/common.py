
from frenetic.netcore import *
from frenetic.network import *
from frenetic.virt import *
from frenetic.generators import *
from frenetic.pox_backend import *

from pox.lib.packet import *
from pox.openflow.libopenflow_01 import *

backend = POXBackend(lambda n: None, False, False, {})
 
payloads = []
packets = []
pox_packets = []
pox_matches = []

def get_single_packet(policy, packet):
    l = list(policy.eval(packet).elements())
    assert len(l) == 1
    return l[0]

def from_payload(payload, **kwargs):
    payloads.append(payload)
    packets.append(backend.create_packet(payload)._push("switch", "inport")._modify(**kwargs))
    pox_packets.append(ethernet(payload))
    pox_matches.append(ofp_match.from_packet(ethernet(payload)))
    
def from_header(**kwargs):
    p = backend.create_packet('r\xd8dQ\xc7\xa0\xfeE\x9e+8C\x08\x00E\x00\x00(\x00\x00@\x00@\x06&\xcc\n\x00\x00\x03\n\x00\x00\x02\x00\x16\xd4+\x00\x00\x00\x00e\xe5\xccsP\x14\x00\x00\x951\x00\x00')._modify(**kwargs)
    payload = backend.get_packet_payload(p)
    payloads.append(payload)
    packets.append(p)
    pox_packets.append(ethernet(payload))
    pox_matches.append(ofp_match.from_packet(ethernet(payload)))
    
# Packet 0: from ping
from_payload('\xff\xff\xff\xff\xff\xff\xea4\xe2\xed\x1e\x8a\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xea4\xe2\xed\x1e\x8a\n\x00\x00\x02\x00\x00\x00\x00\x00\x00\n\x00\x00\x03')

# Packet 1: ...
from_header(srcip="1.2.3.4", dstip="127.0.0.1", srcmac="01:01:01:01:01:01", srcport=30, dstport=700)

# Packet 2: ...
from_payload('\xff\xff\xff\xff\xff\xff\x06\xed\x12\x9a\xb1\xad\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x06\xed\x12\x9a\xb1\xad\n\x00\x00\n\x00\x00\x00\x00\x00\x00\n\x00\x00\x0c', switch=1, inport=1)
