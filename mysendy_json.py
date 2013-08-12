#!/usr/bin/env python


'''
Coursera:
- Software Defined Networking (SDN) course
-- Module 7 Programming Assignment

Professor: Nick Feamster
Teaching Assistant: Muhammad Shahbaz
'''

################################################################################
# Resonance Project                                                            #
# Resonance implemented with Pyretic platform                                  #
# author: Hyojoon Kim (joonk@gatech.edu)                                       #
# author: Nick Feamster (feamster@cc.gatech.edu)                               #
################################################################################

import socket
import sys
import struct
import json
from optparse import OptionParser


CTRL_ADDR = '127.0.0.1'
CONN_PORT = 50001

eventTypes = {'auth': 0, 'ids': 1, 'lb': 2}

def main():

  desc = ('Send JSON Events')
  usage = ('%prog [options]\n'
            '(type %prog -h for details)')
            
  op = OptionParser(description=desc, usage=usage)
  op.add_option('--host-IP', '-i', action="store", 
                   dest="hostIP", help = 'the host IP for which a state change happens')

  op.add_option('--event-type', '-e', type='choice',
                 dest="eventType", choices=['auth','ids', 'lb'],
                 help = '|'.join( ['auth','ids','lb'] ))


  op.add_option('--event-value', '-V', action="store", 
                 dest="eventValue", help = 'the host IP for which a state change happens')

  op.add_option('--ctrl-addr', '-a', action="store", default=CTRL_ADDR,
                 dest="controlIP", help = 'the controller IP')

  op.add_option('--ctrl-port', '-p', action="store", default=CONN_PORT,
                 dest="controlPort", help = 'the controller port')

  options, args = op.parse_args()
  eventnum = eventTypes[options.eventType]
  controlIP = options.controlIP
  controlPort = options.controlPort

  print options.hostIP

  sender=dict(sender_id=1, description=1, ip_addr=1, mac_addr=1)
 
  data=dict(data_type=eventnum, data=options.hostIP, value=options.eventValue)

  transition=dict(prev=1, next=1)

  event = dict(event_id=1, event_type=eventnum, event_code=1, description=1, sender=sender, data=data, transition=transition)
  
  data = dict(event=event)

  # create socket
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  # connect to server
  s.connect((controlIP, controlPort))


  bufsize = len(data)

  # send data
  totalsent = 0
  s.send(json.dumps(data))
  s.close()

### START ###

if __name__ == '__main__':
  main()

### end of function ###
