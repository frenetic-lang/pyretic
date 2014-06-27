import threading
from socket import *
from SocketServer import *
import json
import requests
import os
import time

class SFlowEvent_T():
    
    def __init__(self, handler, addr, port):
        self.handler = handler
        self.addr = addr
        self.port = port
        self.target_url = 'http://' + addr + ':' + str(port)
        self.event_id = -1
    
    def set_max_events(self, max_events):
        self.max_events = max_events
        
    def set_timeout(self, timeout):
        self.timeout = timeout
        
    def set_groups(self, groups):
        self.groups = groups
    
    def set_flows(self, flows):
        self.flows = flows
        
    def set_threshold(self, threshold):
        self.threshold = threshold
        
    def set_action(self, message):
        self.message = message

    def start(self, queue):
        t1 = threading.Thread(target=self.event_listener, args=(queue,))
        t1.daemon = True
        t1.start()
        
    def event_listener(self, queue):
        self.event_url = self.target_url + '/events/json?maxEvents=' + str(self.max_events) + '&timeout=' + str(self.timeout)
        
        r = requests.put(self.target_url + '/group/json',data=json.dumps(self.groups))
        r = requests.put(self.target_url + '/flow/' + self.threshold['metric'] + '/json',data=json.dumps(self.flows))
        r = requests.put(self.target_url + '/threshold/' + self.threshold['metric'] + '/json',data=json.dumps(self.threshold))
        
        while 1:        
            r = requests.get(self.event_url + '&eventID=' + str(self.event_id))
            if r.status_code != 200: 
                print 'sflow_event.event_listener return invalid status_code'
                break
    
            events = r.json()
            if len(events) == 0: continue
            
            # Pyretic runtime crashes without this ... (need to find a solution)
            time.sleep(10)
            
            self.event_id = events[0]["eventID"]
            for event in events:
                if self.threshold['metric'] == event['metric']:
                    self.handler(self.message, queue)
                    



