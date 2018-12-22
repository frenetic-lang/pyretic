from pyretic.lib.corelib import *
from pyretic.lib.std import *
import pyretic.lib.query as query

class resetting_q(DynamicFilter):
    def __init__(self,cls,**kwargs):
        self.cls = cls
        self.kwargs = kwargs
        super(resetting_q,self).__init__()
        
    def register_callback(self,cb):
        self.callback = cb
        self.reset()
            
    def reset(self):        
        # policy = self.cls(self.kwargs)
        # print type(policy)
        # print policy
        # self.policy = policy
        self.policy = query.packets(limit=1,group_by=['srcmac','switch'])
        # print type(self.policy)
        # print self.policy
        self.policy.register_callback(self.callback)
            
    def set_network(self,network):
        self.reset()

