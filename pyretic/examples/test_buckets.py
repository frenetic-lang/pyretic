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
    return flood() + b1 + b2 
