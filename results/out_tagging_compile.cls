classifier size: 5
print : match: ('vlan_pcp', 0) ('vlan_id', 3)
  -> set([identity])
 match: ('vlan_pcp', 0) ('vlan_id', 0)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)])
 match: ('vlan_pcp', 0) ('vlan_id', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 4)])
 match: ('vlan_pcp', 0) ('vlan_id', 4)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)])
 identity
  -> set([]) 
---------------------------------
classifier size: 2
print : match: ('vlan_pcp', 0) ('vlan_id', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 4)])
 identity
  -> set([modify: ('path_tag', 2)]) 
---------------------------------
classifier size: 2
print : match: ('vlan_pcp', 0) ('vlan_id', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 4)])
 identity
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)]) 
---------------------------------
