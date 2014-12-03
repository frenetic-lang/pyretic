classifier size: 7
print : match: ('switch', 3) ('vlan_pcp', 0) ('vlan_id', 3)
  -> set([identity])
 match: ('switch', 3) ('vlan_pcp', 0) ('vlan_id', 0)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 2)])
 match: ('switch', 3) ('vlan_pcp', 0) ('vlan_id', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)])
 match: ('switch', 3) ('vlan_pcp', 0) ('vlan_id', 4)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)])
 match: ('switch', 3)
  -> set([])
 match: ('vlan_pcp', 0) ('vlan_id', 3)
  -> set([identity])
 identity
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)]) 
---------------------------------
classifier size: 3
print : match: ('switch', 3) ('vlan_pcp', 0) ('vlan_id', 0)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 2)])
 match: ('vlan_pcp', 0) ('vlan_id', 0)
  -> set([modify: ('path_tag', 2)])
 identity
  -> set([modify: ('path_tag', 2)]) 
---------------------------------
classifier size: 3
print : match: ('switch', 3) ('vlan_pcp', 0) ('vlan_id', 0)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 2)])
 match: ('vlan_pcp', 0) ('vlan_id', 0)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)])
 identity
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)]) 
---------------------------------
