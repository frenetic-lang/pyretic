################################################################################
# SETUP                                                                        #
# -------------------------------------------------------------------          #
# mininet: mininet.sh --topo=clique,5,5 (or other single subnet network)       #
# test:    pingall. odd nodes should reach odd nodes w/ higher IP,             #
#          likewise for even ones                                              #
#          controller prints one message                                       #
#          e.g., "punching hole for reverse traffic [IP1]:[IP2]"               #
#          for each pair where IP1<IP2.                                        #
#          Timeout seconds after last time punched hole used,                  #
#          it will close w/ corresponding print statement                      #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.hub import hub
# from time import gmtime, localtime, strftime
import datetime

prefixIP  = '10.0.0.'
prefixMAC = '00:00:00:00:00:0'

useIP   = not True
usestr  = not True
verbose = not True

drop_ingress = if_(ingress_network(), drop)

def dbgPrint(thisObject):
  if verbose:
    print(thisObject)
  
def getPred(W):
  logFileName = "fw0match.log"
  
  timeNow = datetime.datetime.now().strftime("%Y-%m-%d.%H:%M:%S.%f")
  # nowLocal = strftime("%Y-%m-%d.%H:%M:%S%M%M", localtime())
  
  # logFile = open('%s-%s' % (timeNow, logFileName), 'w', 1)     # hph
  
  if useIP:
    return [match(srcip=s, dstip=d) for (s, d) in W]
    
  else:
    return [match(srcmac=s, dstmac=d) for (s, d) in W]
  
def poke(W, P):
  Pred = getPred(W)
  p = parallel(Pred)
  
  dbgPrint(Pred)
  dbgPrint(p)
  
  return if_(p, passthrough, P)

def static_fw(W):
    thisPoke = poke(W, drop_ingress)
    dbgPrint(thisPoke)
    
    return thisPoke
        
def getHostsGroups(iGroup1, iGroup2):  
  if useIP:
    if usestr:
      group1 = [prefixIP + str(i) for i in iGroup1]
      group2 = [prefixIP + str(i) for i in iGroup2]
    
    else:
      group1 = [IP(prefixIP + str(i)) for i in iGroup1]
      group2 = [IP(prefixIP + str(i)) for i in iGroup2]

  else:
    if usestr:
      group1 = [prefixMAC + str(i) for i in iGroup1]
      group2 = [prefixMAC + str(i) for i in iGroup2]
    
    else:
      group1 = [MAC(prefixMAC + str(i)) for i in iGroup1]
      group2 = [MAC(prefixMAC + str(i)) for i in iGroup2]
  
  return (group1, group2)

def static_firewall_example():
  iGroup1 = {2}
  iGroup2 = {1}
  
  group1, group2 = getHostsGroups(iGroup1, iGroup2)
  dbgPrint("Traffic allowed only between %s and %s" % (group1, group2))

  allowed  = set([])
  
  for host1 in group1:
    for host2 in group2:
      allowed.add((host1, host2))
      allowed.add((host2, host1))

  return static_fw(allowed) >> hub
 
def askyn(prompt, retries=4, complaint='Yes or no, please!'):
  while True:
    ok = raw_input(prompt)

    if ok in ('y', 'ye', 'yes'):
        return True

    if ok in ('n', 'no', 'nop', 'nope'):
        return False

    retries = retries - 1

    if retries < 0:
        raise IOError('Time out after %s retries' % retries)

    print complaint

def getOptions():
  global useIP
  global usestr
  global verbose

  print("\nPlease answer (y)es or (n)o for the following options;")
  
  useIP   = askyn("    useIP   (y/n): ")
  usestr  = askyn("    usestr  (y/n): ")
  verbose = askyn("    verbose (y/n): ")
  
  
def main(): 

  getOptions()
  
  return static_firewall_example()
