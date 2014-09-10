from optparse import OptionParser
import socket
import sys
import json
import re
import ipaddr
import subprocess


#python json_sender.py -n authenticated -l True  --flow="{srcip=10.0.0.2}" -a 127.0.0.1 -p 50001
BASE_CMD = "python ../../json_sender.py -a 127.0.0.1 -p 50001 " 

def main():
    desc = ( 'Measure compile time' )
    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    op = OptionParser( description=desc, usage=usage )

    # Options
    op.add_option( '--num', '-n', action="store",\
                     dest="num_events", help = 'Number of events'  )

    if len(sys.argv) != 3:
        print "Wrong number of arguments"
        op.print_help()
        sys.exit()

    # Parsing and processing
    options, args = op.parse_args()

    # Events and values
    ev_tuple_list = []
    ev_tuple_list.append(('authenticated','True'))
#   ev_tuple_list.append(('infected','True'))

    # Set starting IP address
    the_IP = ipaddr.IPAddress('1.1.1.1')

    # Start sending events
    for i in range(int(options.num_events)):
        for j in ev_tuple_list:
            cmd = BASE_CMD + "-n " + j[0] + " -l " + j[1] + " --flow='{srcip="+str(the_IP)+"}'"

            p = subprocess.Popen(cmd, stdout=subprocess.PIPE,shell=True) 
            out, err = p.communicate()

        the_IP = the_IP + 1
        if str(the_IP).endswith('0') or str(the_IP).endswith('255'):
            the_IP = the_IP + 1
 
    # End and flush.
    end_cmd = "python ../../json_sender.py -a 127.0.0.1 -p 50001 -n endofworld -l True --flow='{srcip=1.1.1.1}'"
    p = subprocess.Popen(end_cmd, stdout=subprocess.PIPE,shell=True) 
    out, err = p.communicate()



if __name__ == '__main__':
    main()

