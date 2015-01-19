classifier size: 12
max switch rule count: 12
average switch rule count: 12
print : match: ('vlan_pcp', 0) ('vlan_id', 18)
  -> set([identity])
 match: ('vlan_pcp', 0) ('vlan_id', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 12)])
 match: ('vlan_pcp', 0) ('vlan_id', 3)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 13)])
 match: ('vlan_pcp', 0) ('vlan_id', 4)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 14)])
 match: ('vlan_pcp', 0) ('vlan_id', 5)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 13)])
 match: ('vlan_pcp', 0) ('vlan_id', 6)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 15)])
 match: ('vlan_pcp', 0) ('vlan_id', 7)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 13)])
 match: ('vlan_pcp', 0) ('vlan_id', 8)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 16)])
 match: ('vlan_pcp', 0) ('vlan_id', 9)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 13)])
 match: ('vlan_pcp', 0) ('vlan_id', 10)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 17)])
 match: ('vlan_pcp', 0) ('vlan_id', 11)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 13)])
 identity
  -> set([]) 
---------------------------------
