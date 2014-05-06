#!/usr/bin/env python

from twisted.internet.protocol import ClientFactory, Factory
from twisted.internet import reactor
from twisted.protocols import basic
from multiprocessing import Queue
import threading
import pickle

class Client(basic.LineReceiver):
    def connectionMade(self):
        print "Got server!"
        self.factory.client = self

    def connectionLost(self, reason):
        print "Lost server!"
        self.factory.client = None
        
    def lineReceived(self, line):
        print '----------- lineReceived ---------'
        input_list = pickle.loads(line)
        print input_list
        self.factory.qrecv.put(input_list)

class ClientSocket():
    def __init__ (self, qsend, qrecv):
        self.factory = ClientFactory()
        self.factory.client = None
        self.factory.protocol = Client
        self.factory.qsend = qsend
        self.factory.qrecv = qrecv
        p = threading.Thread(target=self.dataSent,args=(self.factory.qsend,))
        p.start()
    
    def dataSent(self, q):
        while True:
            to_send_l = q.get()
            to_send = pickle.dumps(to_send_l)
            print '----------- dataSent --------------'
            print pickle.loads(to_send)
            self.factory.client.sendLine(to_send)


# --- Client ---

def printLine (line):
    print "received", repr(line)

def main():
    c = ClientSocket(printLine)
    
    reactor.connectTCP('localhost', 8000, c.factory)
    reactor.run()

if __name__ == '__main__':
    main()
