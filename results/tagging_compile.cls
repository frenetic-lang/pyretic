classifier size: 4
---------------------------------
classifier size: 4
print : match: ('switch', 3) ('vlan_pcp', 0) ('vlan_id', 3)
  -> set([identity])
 match: ('switch', 3)
  -> set([])
 match: ('vlan_pcp', 0) ('vlan_id', 3)
  -> set([identity])
 identity
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 3)]) 
---------------------------------
