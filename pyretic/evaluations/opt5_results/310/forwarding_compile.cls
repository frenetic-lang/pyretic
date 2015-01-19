classifier size: 5
print : match: ('switch', 1) ('dstip', IPv4Network('10.0.0.1/32'))
  -> set([modify: ('outport', 2)])
 match: ('dstip', IPv4Network('10.0.0.1/32'))
  -> set([modify: ('outport', 1)])
 match: ('switch', 1) ('dstip', IPv4Network('10.0.0.2/32'))
  -> set([modify: ('outport', 1)])
 match: ('dstip', IPv4Network('10.0.0.2/32'))
  -> set([modify: ('outport', 2)])
 identity
  -> set([]) 
---------------------------------
classifier size: 5
print : match: ('switch', 1) ('dstip', IPv4Network('10.0.0.1/32'))
  -> set([modify: ('outport', 2)])
 match: ('dstip', IPv4Network('10.0.0.1/32'))
  -> set([modify: ('outport', 1)])
 match: ('switch', 1) ('dstip', IPv4Network('10.0.0.2/32'))
  -> set([modify: ('outport', 1)])
 match: ('dstip', IPv4Network('10.0.0.2/32'))
  -> set([modify: ('outport', 2)])
 identity
  -> set([]) 
---------------------------------
