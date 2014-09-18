import ast
import copy
from collections import defaultdict
from threading import Lock
import re
import inspect
import textwrap
import datetime as dt
import pickle
from threading import Thread, Event
from multiprocessing import Process,Queue

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.kinetic.language import *
from pyretic.kinetic.resettableTimer import *
import ipaddr
from threading import Timer

measures_list = []
howmany = 0
BATCH_AMOUNT = 1000

class Event(object):
    def __init__(self,name,value,flow):
        self.name = name
        self.value = value
        self.flow = flow


class LpecFSM(DynamicPolicy):
    def __init__(self,t,s,n,x,d):
        self.type = copy.copy(t)
        self.state = copy.copy(s)  # really variables, but all the variables together are the state
        self.event = dict()
        for k in self.state.keys():
            self.event[k] = None
        self.trans = n
        self.exogenous = x
        self.dependencies = d
        self._topo_init = False
        super(LpecFSM,self).__init__(self.state['policy'])

    def handle_change(self,var_name,is_event=False):

        # get the next value for this variable
        next_val = self.trans[var_name](self.state,self.event)

        # IF THIS IS AN EVENT, WE'VE NOW TAKEN IT INTO ACCOUNT
        if is_event:
            self.event[var_name] = None

        # if the value has changed
        if next_val != self.state[var_name]:
            self.state[var_name] = next_val

            # update policy, if appropriate
            if var_name == 'policy':
#                self.policy = self.state['policy']
#                print self.policy
                pass

            # cascade the changes
            for v in self.dependencies[var_name]:
                self.handle_change(v)

        # IF THIS IS AN EVENT, THE CORRESPONDING STATE MAY NEED UPDATE
        # (FOR DEFAULT CASE)
        if is_event:
            self.state[var_name] = \
                self.trans[var_name](self.state,self.event)

    def handle_event(self,event_name,event_val_rep):
        # ignore events to other modules
        if not event_name in self.type:
            print "WARNING: '%s' events not handled by this module! Check if you are sending the '%s' event to correct TCP_port." % (event_name,event_name)
            return
        # ensure event_val is typed correctly
        event_type = self.type[event_name].py_type
        if isinstance(event_val_rep,str):
            if event_type == bool:
                event_val = ast.literal_eval(event_val_rep)
            elif event_type == int:
                event_val = int(event_val_rep)
            else:
                raise RuntimeError('not yet implemented')
        else:
            event_val = event_val_rep
            if not isinstance(event_val,event_type):
                raise RuntimeError('event_val type mismatch (%s,%s)' % (type(event_val),event_type) )

        # update event data structure and handle change
        self.event[event_name] = event_val
        if not self.exogenous[event_name]:
            raise RuntimeError('var %s cannot be affected by external events!' % event_name)
        self.handle_change(event_name,is_event=True)

    def set_network(self,network):
        if not self._topo_init:
            self._topo_init = True
            return

        # topo_change IS A RESERVED NAME!!!
        if 'topo_change' in self.exogenous:
            self.handle_event('topo_change',True)


class FSMPolicy(DynamicPolicy):
    def __init__(self,lpec_fn,fsm_description,num_of_fsms=0, event_queue=None):
        self.type = dict()
        self.state = dict()
        self.trans = dict()
        self.exogenous = dict()
        self.deps = defaultdict(set)
        self.lpec_fn = lpec_fn
        self.list_of_fsm_policies = list()
        self.dict_of_fsm_policies  = {}
        self.event_list = list()
#        self.timer_thread = threading.Timer(1.0, perform_batch)
        self.timer_thread = TimerReset(1.0, self.dead)
        self.started = True
#        self.timer_thread.start()
        self.num_of_fsms = num_of_fsms
        self.event_queue = event_queue

        loadwith_varname =  ''
        loadwith_varvalue = True

        for var_name,var_def in fsm_description.map.items():
            self.type[var_name] = var_def['type']
            self.state[var_name] = var_def['init']
            self.trans[var_name] = var_def['trans']
            if type(var_def['type'])==BoolType:
                loadwith_varname = var_name
                if var_def['init']==True:
                    loadwith_varvalue = False
                else:
                    loadwith_varvalue = True
            elif var_def['type'].py_type==int:
                loadwith_varname = var_name
                vs = var_def['type'].dom.copy()
                loadwith_varvalue = vs.pop()
                if var_def['init']==v:
                    loadwith_varvalue = vs.pop()
 
            for e in events(var_def['trans']):
                e.add_type(var_def['type'])
                self.exogenous[var_name] = True
            for v in variables(var_def['trans']):
                self.deps[v].add(var_name)
        self.lpec_to_fsm = dict()
        self.initial_policy = self.state['policy']
        self.lock = Lock()
        self.event_lock = Lock()

        super(FSMPolicy,self).__init__(self.initial_policy)

        self.load_LPEC(int(num_of_fsms), loadwith_varname,loadwith_varvalue)


    def single_event_handle(self,event):
        # Events that apply to a single lpec
        if event.flow:
            try:
                lpec = self.lpec_fn(event.flow)
            except KeyError:
                print 'Error: event flow must contain all fields used in lpec_relation.  Ignoring.'
                return

            if lpec is None:
                return

            # DynamicPolicies can't be hashed
            # still need to implement hashing for static policies
            # in meantime, use string representation of the cannonical lpec
            lpec_k = repr(lpec)  

            with self.lock:
                # get the lpec objects from the flow
                if lpec_k in self.lpec_to_fsm:
                    lpec_new = False
                else:
                    self.lpec_to_fsm[lpec_k] = LpecFSM(self.type,self.state,self.trans,
                                                       self.exogenous,self.deps)
                    lpec_new = True

                # have the lpec_fsm handle the event
                lpec_fsm = self.lpec_to_fsm[lpec_k]
                lpec_fsm.handle_event(event.name,event.value)

                # if the lpec is new, update the policy
#                if lpec_new:
#                    self.policy = if_(lpec,lpec_fsm,self.policy)

                if lpec_new: 
                    self.list_of_fsm_policies.append(lpec >> lpec_fsm)
                    self.policy = disjoint(self.list_of_fsm_policies)
#                    self.policy = parallel(self.list_of_fsm_policies)
 
        # Events that apply to all lpecs
        else:
            with self.lock:
                for lpec_fsm in self.lpec_to_fsm.values():
                    lpec_fsm.handle_event(event.name,event.value)
                    
        # Add an element in event_queue after handling the event
        #print "Updating the event_queue, size: ", self.event_queue.qsize()
        self.event_queue.put(time.time())

    def dead(self): 
        print 'Times up!!~'
        self.perform_batch(timesup=True)
        return

    def perform_batch(self,timesup=False):
        compile_time = 0
        if len(self.event_list)>0:
            for e in self.event_list:
                self.single_event_handle(e)
            print "event lengh",len(self.event_list)
            # Now, compile.
            n1=dt.datetime.now()
            self.policy.compile()
            n2=dt.datetime.now()
            compile_time = float((n2-n1).microseconds)/1000.0/1000.0 + float((n2-n1).seconds)
            self.event_list = []
    
            print 'Time',compile_time
#            if timesup is True:
#                compile_time += 1.0

            measures_list.append(compile_time)

        else:
            compile_time = 0
#            print 'Ba'

        return compile_time


    def event_handler(self,event):
        self.single_event_handle(event)
        """
        global measures_list
        global howmany
        global BATCH_AMOUNT
        compile_time = 0

        howmany = howmany + 1

        if self.started is False:
            self.timer_thread.start()
            self.started = True

        if event.name=='endofworld':
            
            time.sleep(2.0)
            print 'Save result. Number of FSMs:',self.num_of_fsms
            pickle_fd = open('./measure_data_'+self.num_of_fsms+'_'+ event.value+'.p','wb')
            pickle.dump(measures_list,pickle_fd)
            pickle_fd.close() 
            measures_list = []
            
            return 0

        self.timer_thread.reset()

        self.event_list.append(event)   

        if len(self.event_list) < BATCH_AMOUNT:
            # check timer,
#            while self.timer_thread.isAlive():
#                continue;
#            compile_time = self.perform_batch()
            return 0

        else:
            compile_time = self.perform_batch()
            return compile_time
        """


    def load_LPEC(self,num_of_fsms,event_name,event_value):
        src_ip_real = ipaddr.IPAddress('10.0.0.1')
        src_ip = IPAddr(str(src_ip_real))
        dst_ip_real = ipaddr.IPAddress('10.0.0.2')
        dst_ip = IPAddr(str(dst_ip_real))
 
        list_of_fsm_policies = []
        dict_of_fsm_policies = {}

        for i in range(num_of_fsms):
            # Only works for srcip,dstip
            try:
                lpec = self.lpec_fn({'srcip':src_ip,'dstip':dst_ip})
            except KeyError:
                print 'Error: event flow must contain all fields used in lpec_relation.  Ignoring.'
                return

            if lpec is None:
                return

            # DynamicPolicies can't be hashed
            # still need to implement hashing for static policies
            # in meantime, use string representation of the cannonical lpec
            lpec_k = repr(lpec)  

            with self.lock:
                self.lpec_to_fsm[lpec_k] = LpecFSM(self.type,self.state,self.trans,
                                                       self.exogenous,self.deps)
                lpec_new = True
        
                # have the lpec_fsm handle the event
                lpec_fsm = self.lpec_to_fsm[lpec_k]
                lpec_fsm.handle_event(event_name, event_value)
        
                # if the lpec is new, update the policy
                if lpec_new:
                    this_p = lpec >> lpec_fsm
                    #print "lpec:", lpec
                    #print "lpec_fsm: ", lpec_fsm
                    list_of_fsm_policies.append(this_p)
                    dict_of_fsm_policies[lpec] = this_p
#                    self.policy = if_(lpec,lpec_fsm,self.policy)

            src_ip_real = src_ip_real + 1
            if str(src_ip_real).endswith('0') or str(src_ip_real).endswith('255'):
                src_ip_real = src_ip_real + 1
            src_ip = IPAddr(str(src_ip_real))

            dst_ip_real = dst_ip_real + 1
            if str(dst_ip_real).endswith('0') or str(dst_ip_real).endswith('255'):
                dst_ip_real = dst_ip_real + 1
            dst_ip = IPAddr(str(dst_ip_real))


        self.list_of_fsm_policies = list_of_fsm_policies
        self.dict_of_fsm_policies = dict_of_fsm_policies

        ### Parallel or Disjoint
        self.policy = disjoint(list_of_fsm_policies)
#        self.policy = parallel(list_of_fsm_policies)

        """

        print '\nInitiate policy compilation. This can take time...\n'
        n1=dt.datetime.now()
        self.policy.compile()
        n2=dt.datetime.now()
        compile_time = (float((n2-n1).microseconds)/1000.0/1000.0 + float((n2-n1).seconds))
       
        print "** Number of FSMs loaded: " + str(len(self.lpec_to_fsm))
        print "** Compilation time: " + str(compile_time) + " seconds.\n"
        """

#        print self.policy
        

