from pyretic.lib.path import *
from pyretic.core.language import *
from datetime import datetime

TEN_IP = '10.0.0.0/24'

def forwarding_policy():
    return if_(match(dstip = '10.0.0.1'),
               if_(match(switch = 1), fwd(3),
               if_(match(switch = 2), fwd(1),
               if_(match(switch = 3), fwd(1),
               if_(match(switch = 4), fwd(1),
               drop)))),
           if_(match(dstip = '10.0.0.2'),
               if_(match(switch = 1), fwd(4),
               if_(match(switch = 2), fwd(1),
               if_(match(switch = 3), fwd(2),
               if_(match(switch = 4), fwd(1),
               drop)))),
           if_(match(dstip = '10.0.0.3'),
               if_(match(switch = 1), fwd(1),
               if_(match(switch = 2), fwd(2),
               if_(match(switch = 3), fwd(3),
               if_(match(switch = 4), fwd(2),
               drop)))),
           if_(match(dstip = '10.0.0.4'),
               if_(match(switch = 1), fwd(2),
               if_(match(switch = 2), fwd(2),
               if_(match(switch = 3), fwd(4),
               if_(match(switch = 4), fwd(2),
               drop)))),
           drop))))


def agg_callback(test_num):
    def actual_callback(agg, res):
        print '**************'
        print datetime.now()
        print 'Test', test_num, ' -- got a callback from installed path query!'
        print res
        print 'from aggregate', agg
        print '**************'
    return actual_callback

def query1():
    tenant_pred = ingress_network() & match(srcip = TEN_IP, dstip = TEN_IP, ethtype=2048)
    q = in_group(tenant_pred, groupby=['switch']) ** out_group(egress_network(), groupby=['switch'])
    fb = FwdBucket()
    fb.register_callback(agg_callback("tm_groupby"))
    q.set_bucket(fb)
    #res_paths = path_grouping.expand_groupby(q, fvlist)
    return q


def path_main(**kwargs):
    return query1()

def main():
    return forwarding_policy()
