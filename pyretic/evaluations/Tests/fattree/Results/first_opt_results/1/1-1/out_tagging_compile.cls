classifier size: 6
print : match: ('vlan_pcp', 0) ('vlan_id', 9)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 10)])
 match: ('vlan_pcp', 0) ('vlan_id', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 4)])
 match: ('vlan_pcp', 0) ('vlan_id', 11)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 12)])
 match: ('vlan_pcp', 0) ('vlan_id', 5)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 6)])
 match: ('vlan_pcp', 0) ('vlan_id', 7)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 8)])
 identity
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)]) 
---------------------------------
