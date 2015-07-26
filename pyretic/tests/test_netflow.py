from pyretic.lib.netflow import *
from pyretic.core.language import *
import logging, time, subprocess, shlex, os, threading

# Pcap test files for testing.
TESTPCAP = "pyretic/scratch/testpcap.pcap"
VLANTEST = "pyretic/scratch/vlantest.pcap"

def myeval_tests():
    """ Test myEval function on packets """
    p1 = {"header":{"srcmac":"00:0a:95:9d:68:16", "dstmac":"00:0a:95:9d:68:18",
                    "srcip":"192.0.0.1", "dstip":"192.0.0.2", "tos":56,
                    "srcport":8008, "dstport":9900, "ethtype":0x0800,
                    "protocol":"tcp"},"pktcount":40,"bytecount":4000}

    p2 = {"header":{"srcmac":"00:0a:95:9d:78:16", "dstmac":"00:0a:9d:95:68:18",
    "srcip":"192.0.0.6", "dstip":"192.0.0.9", "tos":38, "srcport":8800,
    "dstport":9000, "ethtype":0x0800,
    "protocol":"tcp"},"pktcount":40,"bytecount":3000}

    #some sample filters
    #base cases:
    f1 = match(srcip="192.0.0.1")          #p1 = pass. p2 = fail.
    f2 = match(srcip="192.0.0.6")          #p2 = pass. p1 = fail.
    f3 = match(dstmac='00:0a:9d:95:68:18') #p2 = pass. p1 = fail.
    f4 = match(dstip='192.0.0.9')          #p2 = pass. p1 = fail.
    #compound cases:
    f5 = f1 | f3  #both pass
    f6 = f3 & f2  #p2 = pass. p1 = fail
    f7 = ~f2      #p1 = pass, p2 = fail
    f8 = f2 & f1  #both fail. f8 is just a drop. try `print f8`!
    f9 = f3 & f4  #p2 = pass, p1 = fail
    f10 = identity

    assert myEval(f1,p1) is p1 and myEval(f1,p2) is not p2
    assert myEval(f2,p1) is not p1 and myEval(f2,p2) is p2
    assert myEval(f3,p1) is not p1 and myEval(f3,p2) is p2
    assert myEval(f4,p1) is not p1 and myEval(f4,p2) is p2

    assert myEval(f5,p1) is p1 and myEval(f5,p2) is p2
    assert myEval(f6,p1) is not p1 and myEval(f6,p2) is p2
    assert myEval(f7,p1) is p1 and myEval(f7,p2) is not p2
    assert myEval(f8,p1) is not p1 and myEval(f8,p2) is not p2
    assert myEval(f9,p1) is not p1 and myEval(f9,p2) is p2
    assert myEval(f10,p1) is p1 and myEval(f10,p2) is p2

    assert myEval(f1,p2) == myEval(f2,p1) == myEval(f3,p1) == myEval(f4,p1) == set()
    assert (myEval(f6,p1) == myEval(f7,p2) == myEval(f8,p1) == myEval(f8,p2) ==
            myEval(f9,p1) == set())

def compilation_tests():
    x = NetflowBucket(start_fcapd=False)
    y = match(srcip='10.0.0.1')
    z = modify(dstip='192.168.0.2')

    print x
    print x.compile()
    print '****'
    a = y >> x
    print a
    print a.compile()
    print '****'
    b = y >> z >> x
    print b
    print b.compile()
    print '****'
    c = z + x
    print c
    print c.compile()
    print '****'
    d = y >> (z + x)
    print d
    print d.compile()
    print '****'
    e = x >> z
    print e
    print e.compile()

### Netflow bucket testing
### Helper functions for netflow bucket tests.
def nf_callback_fn(arg=''):
    def f(res):
        print '******************'
        print "Callback identifier:", arg
        print "This is a netflow bucket callback function. I got results:"
        print res
        print '******************'
    return f

def traffic_thread(loop=True):
    """ Generate a custom workload separately for nfcapd. """
    def run_workload():
        cmd = "softflowd -n localhost:%d -r %s" % (NFCAPD_PORT, VLANTEST)
        try:
            p = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
        except OSError:
            print "Errors in replaying traffic workload to netflow collector!"
            print "Got output:", p
        except subprocess.CalledProcessError:
            print "There were errors in running softflowd!"
            print "Got output:", p
    ''' Run a do-while-loop of run_workload. '''
    while True:
        run_workload()
        if not loop:
            break
        else:
            time.sleep(7)

def netflow_bucket_test1():
    """Run netflow bucket with a custom workload and see callback results. Note that
    this is an "offline" test, meaning there is no network involved. The
    functions just test the actions of the library given a running instance of
    the netflow collector daemon.
    """
    nb = NetflowBucket(cap_type="netflow")
    nb.register_callback(nf_callback_fn('#1'))
    # Check whether multiple nfcapd instances are started, and whether that
    # causes errors by starting different NetflowBuckets. Neither should
    # happen.
    nb.start_nfcapd()
    nb.start_nfcapd()
    nb2 = NetflowBucket(cap_type="netflow")
    nb2.register_callback(nf_callback_fn('#2'))

    # test "active buckets" by only setting one of the objects above active
    NetflowBucket.set_active_buckets([nb2])

    t = threading.Thread(target=traffic_thread, args=(True,))
    t.daemon = True
    t.start()

    try:
        time.sleep(300)
    except KeyboardInterrupt:
        print "Killing netflow test."

    nb.kill_nfcapd()
    print "Netflow bucket test complete"

if __name__ == "__main__":
    logging.basicConfig()
    myeval_tests()
    compilation_tests()
    netflow_bucket_test1()
