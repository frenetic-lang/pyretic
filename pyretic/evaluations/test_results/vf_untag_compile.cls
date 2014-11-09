classifier size: 6
print : match: ('outport', 2) ('switch', 4)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 match: ('outport', 2) ('switch', 3)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 match: ('outport', 2) ('switch', 5)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 match: ('outport', 1) ('switch', 6)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 match: ('outport', 2) ('switch', 2)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 identity
  -> set([identity]) 
---------------------------------
classifier size: 6
print : match: ('outport', 2) ('switch', 1)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 match: ('outport', 2) ('switch', 4)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 match: ('outport', 2) ('switch', 3)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 match: ('outport', 2) ('switch', 5)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 match: ('outport', 2) ('switch', 2)
  -> set([modify: ('vlan_pcp', None) ('vlan_id', None)])
 identity
  -> set([identity]) 
---------------------------------
