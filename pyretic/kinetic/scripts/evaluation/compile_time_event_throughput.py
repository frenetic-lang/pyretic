from optparse import OptionParser
import socket
import sys
import json
import re
import ipaddr
import subprocess
import time
import datetime as dt
import pickle
import threading
import Queue
import random
from pyretic.kinetic.json_sender import *

#python json_sender.py -n authenticated -l True  --flow="{srcip=10.0.0.2}" -a 127.0.0.1 -p 50001

json_message_list_false = []
json_message_list_true = []
 
def forge_json(flow_str, event_name, event_value):

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
        json_message = dict(name=event_name,
                            value=event_value,
                            flow=flow_dict)
    else:
        print 'No flow_str! Abort.'
        sys.exit(1)

    return json_message

def send_message_list(json_message_list,queue):

    for jsonmsg in json_message_list:
        send_message(jsonmsg,queue)
#    # Create socket
#    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#
#    # Connect to server
#    s.connect(('127.0.0.1', int('50001')))
#    bufsize = len(json_message)
#
#    # Send data
#    totalsent = 0
#    s.sendall(json.dumps(json_message))
# 
#    # Receive return value
#    recvdata = s.recv(1024)
#
#    s.close()
#    if queue != None:
#        queue.put(recvdata)




def send_message(json_message,queue):
    # Create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to server
    s.connect(('127.0.0.1', int('50001')))
    bufsize = len(json_message)

    # Send data
    totalsent = 0
    s.sendall(json.dumps(json_message))
 
    # Receive return value
    recvdata = s.recv(1024)

    s.close()
    if queue != None:
        queue.put(recvdata)


def send_event(rate, num_exp, measure_map, variation,event_msgs_list):

    global json_message_list_false
    global json_message_list_true
    
    if True:
        process_list = []
        wait_time = 1.0/float(rate[0])
        timeout = rate[1]
        queue = Queue.Queue()
        
        for n in range(int(num_exp)):
            i = 0;
            thread_list = []
            json_message_list = []
    
#            if (n%2==0):
#                json_message_list = json_message_list_false
#            else:
#                json_message_list = json_message_list_true
    
            for b in range(5000):
                which_event1 = random.randint(0,variation-1)
                which_event2 = random.randint(0,4999)
                json_message_list.append(event_msgs_list[which_event1][which_event2])

            
#            for n in range(rate[0]):
            for n in range(rate[0]/50):
#                t = threading.Thread(target=send_message,args=(json_message_list[i],queue))
                t = threading.Thread(target=send_message_list,args=(json_message_list[i:i+50],queue))
                thread_list.append(t)

            j = 0 
            oldtime = time.time()
            while True:
                t = thread_list[j]
                j = j + 1
                t.start()
                time.sleep(wait_time)
                if time.time() - oldtime > timeout + 0.1:
                    break
                if j >= len(thread_list):
                    break

            mtime = dt.datetime.now()
            for k in range(j):
                t = thread_list[k]
                t.join()
            mtime = dt.datetime.now() - mtime
            total = 0.0

            join_time = float(mtime.microseconds)/1000.0/1000.0 + float(mtime.seconds)
            for d in range(queue.qsize()):
                #total = total + float(queue.get())
                total = 0

            print '== Sent: ' + str(j*50) + ' events.'
            print "   Join time: ", join_time
            print "   Total time: ", total

            # Store in map
            if measure_map.has_key(rate):
                measure_map[rate].append( (join_time, total) )
            else:
                measure_map[rate] = [ (join_time, total) , ]

            time.sleep(5)
    

def main():
    desc = ( 'Measure compile time for certain event rate' )
    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    op = OptionParser( description=desc, usage=usage )

    # Options
    op.add_option( '--num', '-n', action="store", \
                   dest="num_exp", help = "Specify how many times to run the experiment." )

    op.add_option( '--fsm', '-f', action="store", \
                   dest="nfsm", help = "Number of FSMs loaded" )


    if len(sys.argv) != 5:
        print "Wrong number of arguments"
        op.print_help()
        sys.exit()

    # Parsing and processing
    options, args = op.parse_args()
    wait_time = 0.0
  
    if options.num_exp is None:
        print '\nNo number of experiments given. Abort.\n'
        op.print_help()
        return

    # Rate_list
    rate_list = []
#    rate_list.append( (nevents, timeout, rate_in_str) )
#    rate_list.append( (1, 1) )
#    rate_list.append( (10, 1) )
#    rate_list.append( (20, 1) )
#    rate_list.append( (40, 1) )
#    rate_list.append( (60, 1) )
#    rate_list.append( (80, 1) )
    rate_list.append( (100, 1) )
    rate_list.append( (200, 1) )
#    rate_list.append( (300, 1) )
#    rate_list.append( (300, 1) )
    rate_list.append( (400, 1) )
#    rate_list.append( (500, 1) )
    rate_list.append( (600, 1) )
#    rate_list.append( (700, 1) )
    rate_list.append( (800, 1) )
#    rate_list.append( (900, 1) )
    rate_list.append( (1000, 1) )
#    rate_list.append( (120, 1) )
#    rate_list.append( (140, 1) )
#    rate_list.append( (150, 1) )
##    rate_list.append( (180, 1) )
#    rate_list.append( (200, 1) )
##    rate_list.append( (250, 1) )
#    rate_list.append( (500, 1) )
#   rate_list.append( (700, 1) )
#   rate_list.append( (1000, 1) )

    # Events and values
    ev_tuple_list = []
    ev_tuple_list.append(('authenticated_web','False'))
    ev_tuple_list.append(('authenticated_web','True'))
#    ev_tuple_list.append(('rate','1'))
#    ev_tuple_list.append(('rate','2'))
#    ev_tuple_list.append(('rate','3'))
#    ev_tuple_list.append(('ids','False'))
#    ev_tuple_list.append(('ids','True'))
      
    measure_map = {} ### {rate : list of (join_time, total)}

    # Create messages
    print 'Creating messages...'
    global json_message_list_false
    global json_message_list_true
    src_IP = ipaddr.IPAddress('10.0.0.1')
    dst_IP = ipaddr.IPAddress('10.0.0.2')

    event_msgs_list = []
    json_message_list = []

    for e in ev_tuple_list:
        json_message_list = []
        for i in range(5000):
            json_message_list.append(forge_json('srcip='+str(src_IP)+',dstip='+str(dst_IP), e[0], e[1]))
#            src_IP = src_IP + 1
#            dst_IP = dst_IP + 1
#            if str(src_IP).endswith('0') or str(src_IP).endswith('255'):
#                src_IP = src_IP + 1
#            if str(dst_IP).endswith('0') or str(dst_IP).endswith('255'):
#                dst_IP = dst_IP + 1
        event_msgs_list.append(json_message_list)

        src_IP = ipaddr.IPAddress('10.0.0.1')
        dst_IP = ipaddr.IPAddress('10.0.0.2')
 
    # Send
    print 'Done creating messages. Now sending...'
    for r in rate_list:
        send_event(r, options.num_exp, measure_map, len(ev_tuple_list),event_msgs_list)
        # Save map
        #endmsg = forge_json('srcip=10.0.0.1,dstip=10.0.0.2','endofworld',str(r[0]))
        #send_message(endmsg,None) 
        time.sleep(5)

#    print 'Done sending. Save data.'
#    pickle_fd = open('./measure_map_event_' + options.nfsm + '.p','wb')
#    pickle.dump(measure_map,pickle_fd)
#    pickle_fd.close()


if __name__ == '__main__':
    main()

