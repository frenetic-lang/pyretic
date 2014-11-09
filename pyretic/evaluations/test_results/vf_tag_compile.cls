classifier size: 6
print : match: ('switch', 4) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 match: ('switch', 3) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 match: ('switch', 5) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 match: ('switch', 6) ('inport', 1)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 match: ('switch', 2) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 identity
  -> set([identity]) 
---------------------------------
classifier size: 6
print : match: ('switch', 1) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 match: ('switch', 4) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 match: ('switch', 3) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 match: ('switch', 5) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 match: ('switch', 2) ('inport', 2)
  -> set([modify: ('vlan_pcp', 0) ('vlan_id', 0)])
 identity
  -> set([identity]) 
---------------------------------
