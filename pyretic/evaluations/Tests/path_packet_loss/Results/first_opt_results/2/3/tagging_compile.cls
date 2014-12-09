classifier size: 7
print : match: ('switch', 2) ('vlan_pcp', 0) ('vlan_id', 4)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 5)])
 match: ('vlan_pcp', 0) ('vlan_id', 4)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)])
 match: ('switch', 3) ('vlan_pcp', 0) ('vlan_id', 6)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 7)])
 match: ('vlan_pcp', 0) ('vlan_id', 6)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)])
 match: ('srcip', IPv4Network('10.0.0.1/32')) ('switch', 1) ('dstip', IPv4Network('10.0.0.2/32')) ('vlan_pcp', 0) ('vlan_id', 0)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 2)])
 match: ('vlan_pcp', 0) ('vlan_id', 0)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)])
 identity
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)]) 
---------------------------------
