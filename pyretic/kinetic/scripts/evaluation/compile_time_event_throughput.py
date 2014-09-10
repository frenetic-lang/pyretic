from optparse import OptionParser
import socket
import sys
import json
import re
import ipaddr
import subprocess
import time
import pickle

#python json_sender.py -n authenticated -l True  --flow="{srcip=10.0.0.2}" -a 127.0.0.1 -p 50001
BASE_CMD = "python ../../json_sender.py -a 127.0.0.1 -p 50001 " 

def perform_send_event(rate, num_exp, ev_tuple_list,  measure_map):

    process_list = []
    wait_time = rate[0]
    timeout = rate[1]
    rate_in_str = rate[2]


    for n in range(int(num_exp)):

        # Set starting IP address
        the_IP = ipaddr.IPAddress('1.1.1.1')

        oldtime = time.time()
        if (n%2==0):
            j = ev_tuple_list[0]
            basecmd = BASE_CMD + "-n " + j[0] + " -l " + j[1]
        else:
            j = ev_tuple_list[1]
            basecmd = BASE_CMD + "-n " + j[0] + " -l " + j[1]

        while True:
            cmd = basecmd + " --flow='{srcip="+str(the_IP)+"}'"
            print cmd
        
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE,shell=True)
            process_list.append(p)
            time.sleep(wait_time)
            if time.time() - oldtime > timeout:
                break
            the_IP = the_IP + 1
            if str(the_IP).endswith('0') or str(the_IP).endswith('255'):
                the_IP = the_IP + 1
 

        # Wait for returns
        print 'Wait now'
        mtime = time.time()
        m_list = []
        for p in process_list:
            out,err = p.communicate()
            t = out[out.find('return: '):].lstrip('return: ').rstrip('\n')
            if t != '':
                m_list.append(float(t))
            else:
                print 'Wrong t: ' + t
                sys.exit(1)
#            print t
        mtime = time.time() - mtime
        print "Event sending rate: " + rate_in_str
        print "Kinetic event processing time: " + str(mtime) + " seconds"
        if measure_map.has_key(rate):
            measure_map[rate].append( (m_list,mtime) )
        else:
            measure_map[rate] = [ (m_list,mtime), ]

        process_list = []



def main():
    desc = ( 'Measure compile time for certain event rate' )
    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    op = OptionParser( description=desc, usage=usage )

    # Options
    op.add_option( '--rate', '-r', action="store", \
                   dest="rate", help = "Set rate. <n>S for (n/second), <n>M for (n/minute). Don't include the brackets when specifying n" )

    op.add_option( '--num', '-n', action="store", \
                   dest="num_exp", help = "Specify how many times to run the experiment." )

    if len(sys.argv) != 5:
        print "Wrong number of arguments"
        op.print_help()
        sys.exit()

    # Parsing and processing
    options, args = op.parse_args()

    wait_time = 0.0
  
    if options.rate is not None:
      if options.rate.endswith('S'):
        num_str = options.rate.rstrip('S')
        rate_in_str = num_str + " events/sec"
        wait_time = 1.0/float(num_str)
        timeout = 1
      elif options.rate.endswith('M'):
        num_str = options.rate.rstrip('M')
        rate_in_str = num_str + "/min"
        wait_time = 60.0/float(num_str)
        timeout = 60
      else:
        print 'Wrong rate format. Abort.'
        op.print_help()
        return
    else:
      print '\nNo rate given. Abort.\n'
      op.print_help()
      return
  
    if options.num_exp is None:
        print '\nNo number of experiments given. Abort.\n'
        op.print_help()
        return

    # Rate_list
    rate_list = []
#    rate_list.append( (wait_time, timeout, rate_in_str) )
    rate_list.append( (1.0/float(1), 1, '1 events/sec') )
    rate_list.append( (1.0/float(10), 1, '10 events/sec') )
    rate_list.append( (1.0/float(100), 1, '100 events/sec') )

    # Events and values
    ev_tuple_list = []
    ev_tuple_list.append(('authenticated','False'))
    ev_tuple_list.append(('authenticated','True'))

#    if wait_time > 0.02:           
#        wait_time = wait_time - 0.02
      
    measure_map = {} ### {rate : list of (measurement_list,mtime)}

    for r in rate_list:
        perform_send_event(r, options.num_exp, ev_tuple_list, measure_map)

    # Save map
    pickle_fd = open('./measure_map_event.p','wb')
    pickle.dump(measure_map,pickle_fd)
    pickle_fd.close()

    return 
    # End and flush.
    end_cmd = "python ../../json_sender.py -a 127.0.0.1 -p 50001 -n endofworld_ex -l True --flow='{srcip=1.1.1.1}'"
    p = subprocess.Popen(end_cmd, stdout=subprocess.PIPE,shell=True) 
    out, err = p.communicate()


if __name__ == '__main__':
    main()

