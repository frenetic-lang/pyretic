from pyretic.lib.std import *
from pyretic.modules.mac_learner import *
from pyretic.modules.hub import *
from pyretic.core.runtime import virtual_field
from pyretic.core.language import egress_network


virtual_field(name="acl",values=["permit","deny","inspect"],type="string")

def main():
    firewall_policy = (((match(srcip=IPAddr("10.0.0.1")) + match(srcip=IPAddr("10.0.0.2"))) >> modify(acl="permit")) +
                        (match(srcip=IPAddr("10.0.0.3")) >> modify(acl="inspect")))

    routing_policy  = (match(acl="inspect") >> hub) + (match(acl="permit") >> mac_learner())

    untagging_policy = ((egress_network()  >> modify(vlan_id=None, vlan_pcp=None)) +(~egress_network()))

    policy = firewall_policy >> routing_policy >> untagging_policy

    return policy
