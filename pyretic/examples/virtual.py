from pyretic.lib.std import *
from pyretic.modules.mac_learner import *
from pyretic.modules.hub import *
from pyretic.modules.hub import *
from pyretic.examples.dpi import dpi
from pyretic.core.runtime import virtual_field
from pyretic.core.language import egress_network, ingress_network


virtual_field(name="acl",values=["permit","deny","inspect"],type="string")

def main():
    firewall_policy = (
     (match(srcip=IPAddr("10.0.0.1")) 
        >> modify(acl="permit")) +
     (match(srcip=IPAddr("10.0.0.3")) 
        >> modify(acl="inspect")) +
     (match(srcip=IPAddr("10.0.0.2")) 
        >> modify(acl="deny")))

    routing_policy  = (
        (match(acl="inspect") >> (dpi() + hub)) +
        (match(acl="deny") >> drop) + 
        (match(acl="permit") >> hub))

    return firewall_policy >> routing_policy
