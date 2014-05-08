from pyretic.lib.corelib import *
from pyretic.lib.std import *

def hello1(pkt):
    print "Hello from 1!"

def hello2(pkt):
    print "Hello from 2!"

def main():
    b1 = FwdBucket()
    b2 = FwdBucket()
    b1.register_callback(hello1)
    b2.register_callback(hello2)
    p = flood() + b1 + b2
    print p
    print p.compile()
    q = flood() + b2 + b1
    print q
    print q.compile()
    return (flood() + b1 + b2)
