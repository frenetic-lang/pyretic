import ast
import copy
from collections import defaultdict
from threading import Lock
import re
import inspect
import textwrap

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.kinetic.language import *


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
                self.policy = self.state['policy']

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
    def __init__(self,lpec_fn,fsm_description):
        self.type = dict()
        self.state = dict()
        self.trans = dict()
        self.exogenous = dict()
        self.deps = defaultdict(set)
        self.lpec_fn = lpec_fn

        for var_name,var_def in fsm_description.map.items():
            self.type[var_name] = var_def['type']
            self.state[var_name] = var_def['init']
            self.trans[var_name] = var_def['trans']
            for e in events(var_def['trans']):
                e.add_type(var_def['type'])
                self.exogenous[var_name] = True
            for v in variables(var_def['trans']):
                self.deps[v].add(var_name)
        self.lpec_to_fsm = dict()
        self.initial_policy = self.state['policy']
        self.lock = Lock()
        super(FSMPolicy,self).__init__(self.initial_policy)

    def event_handler(self,event):

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
                if lpec_new:
                    self.policy = if_(lpec,lpec_fsm,self.policy)

        # Events that apply to all lpecs
        else:
            with self.lock:
                for lpec_fsm in self.lpec_to_fsm.values():
                    lpec_fsm.handle_event(event.name,event.value)
