from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
import threading 
from time import sleep

def count_packets_printer(counts):
    print '\nTHREAD\t'
    print threading.current_thread()
    print '----SWITCH MONITOR------'
    print counts

def port_monitoring(dst_port,time_interval):
    q=count_packets(interval=time_interval,group_by=['srcip','dstip']) 
    q.register_callback(count_packets_printer)
    return (match(dstport=dst_port) >> q)

class test(DynamicPolicy):
    def __init__(self):
        super(test,self).__init__(false)
        self.start()

    def start(self):
        print '-------- THREADS INITIAL --------------'
        for thread in threading.enumerate():
            print (thread,thread.isAlive())
        print '-------------------------------'
        x=75
        self.policy = port_monitoring(x,5)
        while(x<77):
            print '-------- THREADS %d--------------' % x
            for thread in threading.enumerate():
                print (thread,thread.isAlive())
            print '-------------------------------'
            old_pol = self.policy
            self.policy = port_monitoring(x,5)
            qs = ast_fold(add_query_sub_pols,set(),old_pol)
            for q in qs:
                q.stop()
            x +=1
            sleep(4)
        print '-------- THREADS %d--------------' % x
        for thread in threading.enumerate():
            print (thread,thread.isAlive())
        print '-------------------------------'
        old_pol = self.policy
        self.policy = drop
        qs = ast_fold(add_query_sub_pols,set(),old_pol)
        for q in qs:
            q.stop()
        time.sleep(4)
        print '-------- THREADS FINAL --------------'
        for thread in threading.enumerate():
            print (thread,thread.isAlive())
        print '-------------------------------'
        

def main():
     return test()
