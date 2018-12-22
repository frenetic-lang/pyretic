#!/usr/bin/env python

from optparse import OptionParser
import socket
import sys
import json
import re

def main():

    desc = ( 'Send JSON Events' )
    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    op = OptionParser( description=desc, usage=usage )

    # Options
    op.add_option( '--flow', action="store", \
                     dest="flow_tuple", help = "Flow tuple. Example: --flow='{inport=1, srcmac=00:00:00:00:00:11, dstmac=00:00:00:00:00:01,srcip=10.0.0.1, dstip=10.0.0.2/24, tos=2,srcport=90, dstport=8080, ethtype=1, protocol=2048, vlan_id=43, vlan_pcp=1}'" )

    op.add_option( '--file', action="store",  \
                     dest="file", help = 'File containing the flow tuple information. It should follow the format of the flow as above i.e., starts with {..' )

    op.add_option( '--event-name', '-n', action="store",\
                     dest="event_name", help = 'The event name.'  )

    op.add_option( '--event-value', '-l', action="store",\
                     dest="event_value", help = 'The event value.'  )

    op.add_option( '--addr', '-a', action="store",\
                     dest="addr", help = 'The address of the controller.' )
    
    op.add_option( '--port', '-p', action="store",\
                     dest="port", help = 'The port value of the controller.' )

    # Parsing and processing
    options, args = op.parse_args()

    flow_str=None

    if options.addr is None and options.port is None:
        print 'No IP address or Port information is given. Exiting.'
        return
    elif options.event_name is None:
        print 'No event name provided. Exiting.'
        return
    elif options.event_value is None:
        print 'No event value provided. Exiting.'
        return

    # Open file if specified
    elif options.file and options.flow_tuple:
        print 'Can only specify one of (file,flow_tuple)'
        return

    elif options.file:
        try:
            fd = open(options.file, 'r')
        except IOError as err:
            print 'Error opening file: ', err
            print 'Aborting.\n'
            sys.exit(1)
            
        content = fd.read()
        flow_str = content

    elif options.flow_tuple:
        flow_str = options.flow_tuple

    if flow_str:
        # Parse flow      
        flow_dict = dict(
            switch=None,
            inport=None,
            srcmac=None,
            dstmac=None,
            srcip=None,
            dstip=None,
            tos=None,
            srcport=None,
            dstport=None,
            ethtype=None, 
            protocol=None,
            vlan_id=None, 
            vlan_pcp=None)
        
        parse_flow_str(flow_dict, flow_str)

        # Construct JSON message
        json_message = dict(name=options.event_name,
                            value=options.event_value,
                            flow=flow_dict)
    else:
        # Construct JSON message
        json_message = dict(name=options.event_name,
                            value=options.event_value)

    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to server
    s.connect((options.addr, int(options.port)))
    bufsize = len(json_message)

    # Send data
    totalsent = 0
    s.sendall(json.dumps(json_message))
 
    # Receive return value
    recvdata = s.recv(1024)
    print 'return: ' + recvdata

    s.close()
    
def parse_flow_str(flow_dict, flow_str):
    print "\nFlow_Str = " + flow_str
    m = re.search("inport=(\d+)\s*",flow_str)
    if m:
        flow_dict['inport'] = m.group(1)
        
    m = re.search("srcmac=(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)\s*",flow_str)
    if m:
        flow_dict['srcmac'] = m.group(1)

    m = re.search("dstmac=(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)\s*",flow_str)
    if m:
        flow_dict['dstmac'] = m.group(1)

    m = re.search("srcip=(\d+\.\d+\.\d+\.\d+[\/\d+]*)\s*",flow_str)
    if m:
        flow_dict['srcip'] = m.group(1)

    m = re.search("dstip=(\d+\.\d+\.\d+\.\d+[\/\d+]*)\s*",flow_str)
    if m:
        flow_dict['dstip'] = m.group(1)
 
    m = re.search("tos=(\d+)\s*",flow_str)
    if m:
        flow_dict['tos'] = m.group(1)

    m = re.search("srcport=(\d+)\s*",flow_str)
    if m:
        flow_dict['srcport'] = m.group(1)

    m = re.search("dstport=(\d+)\s*",flow_str)
    if m:
        flow_dict['dstport'] = m.group(1)

    m = re.search("ethtype=(\d+)\s*",flow_str)
    if m:
        flow_dict['ethtype'] = m.group(1)

    m = re.search("protocol=(\d+)\s*",flow_str)
    if m:
        flow_dict['protocol'] = m.group(1)

    m = re.search("vlan_id=(\d+)\s*",flow_str)
    if m:
        flow_dict['vlan_id'] = m.group(1)

    m = re.search("vlan_pcp=(\d+)\s*",flow_str)
    if m:
        flow_dict['vlan_pcp'] = m.group(1)

    print "\nData Payload = " + str(flow_dict) + '\n'

# main ######
if __name__ == '__main__':
    main()



