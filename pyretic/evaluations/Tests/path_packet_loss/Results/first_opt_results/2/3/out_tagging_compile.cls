classifier size: 4
print : match: ('vlan_pcp', 0) ('vlan_id', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 4)])
 match: ('vlan_pcp', 0) ('vlan_id', 5)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 6)])
 match: ('vlan_pcp', 0) ('vlan_id', 7)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 8)])
 identity
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)]) 
---------------------------------
