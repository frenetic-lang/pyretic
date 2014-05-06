#!/usr/bin/env python

from twisted.internet.protocol import ClientFactory, Factory
from twisted.internet import reactor
from twisted.protocols import basic
from multiprocessing import Queue
import threading

class Client(basic.LineReceiver):
    def connectionMade(self):
        print "Got client!"
        self.factory.client = self

    def connectionLost(self, reason):
        print "Lost client!"
        self.factory.client = None
        
    def lineReceived(self, line):
        print line
        self.factory.qrecv.put(line)

class ClientSocket():
    def __init__ (self, qsend, qrevc):
        self.factory = ClientFactory()
        self.factory.client = None
        self.factory.protocol = Client
        self.factory.qsend = qsend
        self.factory.qrecv = qrecv
        p = threading.Thread(target=self.dataSent,args=(self.factory.qsend,))
        p.start()
    
    def dataSent(self, q):
        while True:
            line = q.get()
            self.factory.client.sendLine(line)


# --- Client ---

def printLine (line):
    print "received", repr(line)

def main():
    c = ClientSocket(printLine)
    
    reactor.connectTCP('localhost', 8000, c.factory)
    reactor.run()

if __name__ == '__main__':
    main()