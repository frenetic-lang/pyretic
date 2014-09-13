#Embedded file name: /home/sdx/pyretic/pyretic/kinetic/examples/multi_compose.py
import time, os, sys
from threading import Thread, Event
from multiprocessing import Process, Queue
import json
from pyretic.kinetic.apps.auth import auth
from pyretic.kinetic.apps.auth_web import *
from pyretic.kinetic.apps.auth_8021x import *
from pyretic.kinetic.apps.ids import *
from pyretic.kinetic.apps.gardenwall import *
from pyretic.kinetic.apps.mac_learner import *
from pyretic.kinetic.apps.rate_limiter import *
from pyretic.kinetic.apps.monitor import *
DATAFILE = 'compilation_results'

def dynamic_policy_compiler(event_queue, composed_aggregate_policies, mode, number_of_fsms):
    print 'Dynamic compiler started'
    time_list = list()
    data = {}
    while True:
        try:
            time_list.append(event_queue.get())
            print 'event_queue received: '
            time.sleep(2)
            print '# of events logged so far: ', 1 + event_queue.qsize()
            number_events = 1 + event_queue.qsize()
            start = time.time()
            composed_classifiers = composed_aggregate_policies.compile()
            compile_time = time.time() - start
            print 'Time to compile the composed policies ', compile_time
            print '# of flow rules after composition ', len(composed_classifiers)
            while event_queue.empty() == False:
                time_list.append(event_queue.get())

            event_handling_time = max(time_list) - min(time_list)
            print 'Total time to input events in event_queue: ', event_handling_time
            if number_events not in data:
                data[number_events] = []
            data[number_events].append((compile_time, event_handling_time))
            time_list = list()
        except:
            print 'Dumping the data file ...'
            with open(DATAFILE+'_'+mode+'_'+str(number_of_fsms)+'.txt', 'w') as outfile:
                json.dump(data, outfile, ensure_ascii=True, encoding='ascii')
            print 'data dumping successful'
            sys.exit()


def policy_compose(auth_w_obj, auth_x_obj, ids_obj, rl_obj):
    list_of_composed_policies = []
    lpecs_for_auth_w = auth_w_obj.fsm_pol.dict_of_fsm_policies
    lpecs_for_auth_x = auth_w_obj.fsm_pol.dict_of_fsm_policies
    lpecs_for_ids_obj = ids_obj.fsm_pol.dict_of_fsm_policies
    lpecs_for_rl_obj = rl_obj.fsm_pol.dict_of_fsm_policies
    total_lpecs = list(set(lpecs_for_auth_w.keys() + lpecs_for_auth_x.keys() + lpecs_for_ids_obj.keys() + lpecs_for_rl_obj.keys()))
    for lpec in total_lpecs:
        pol_auth_w = identity
        pol_auth_x = drop
        pol_ids_obj = identity
        pol_rl_obj = identity
        if lpec in lpecs_for_auth_w:
            pol_auth_w = lpecs_for_auth_w[lpec]
        if lpec in lpecs_for_auth_x:
            pol_auth_x = lpecs_for_auth_x[lpec]
        if lpec in lpecs_for_ids_obj:
            pol_ids_obj = lpecs_for_ids_obj[lpec]
        if lpec in lpecs_for_rl_obj:
            pol_rl_obj = lpecs_for_rl_obj[lpec]
        tmp = pol_auth_w + pol_auth_x >> pol_ids_obj >> pol_rl_obj
        list_of_composed_policies.append(tmp)

    composed_aggregate_policies = disjoint(list_of_composed_policies)
    return composed_aggregate_policies


def main():
    number_of_fsms = sys.argv[2]
    mode = sys.argv[3]
    event_queue = Queue()
    composed_aggregate_policies = drop
    if mode == 'multi':
        auth_w_obj = auth_web(number_of_fsms, event_queue)
        auth_x_obj = auth_8021x(number_of_fsms, event_queue)
        ids_obj = ids(number_of_fsms, event_queue)
        rl_obj = rate_limiter(number_of_fsms, event_queue)
        composed_aggregate_policies = policy_compose(auth_w_obj, auth_x_obj, ids_obj, rl_obj)
    else:
        auth_w_obj = auth_web(number_of_fsms, event_queue)
        composed_aggregate_policies = auth_w_obj.policy
    
    dynamic_update_policy_thread = Thread(target=dynamic_policy_compiler, args=(event_queue, composed_aggregate_policies, mode, number_of_fsms))
    dynamic_update_policy_thread.daemon = True
    dynamic_update_policy_thread.start()
    start = time.time()
    composed_classifiers = composed_aggregate_policies.compile()
    print 'Time to compile the composed policies ', time.time() - start
    print '# of flow rules after composition ', len(composed_classifiers)
    return composed_aggregate_policies
