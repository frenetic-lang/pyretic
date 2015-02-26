classifier size: 3
print : match: ('vlan_pcp', 0) ('vlan_id', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 4)])
 match: ('vlan_pcp', 0) ('vlan_id', 5)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 6)])
 identity
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)]) 
---------------------------------
