#!/usr/bin/env python

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.protocols import basic
from multiprocessing import Queue
import threading

class Server(basic.LineReceiver):
    def connectionMade(self):
        print "Got new client!"
        self.factory.clients.append(self)

    def connectionLost(self, reason):
        print "Lost a client!"
        self.factory.clients.remove(self)

    def lineReceived(self, line):
        print line
        self.factory.qrecv.put(line)
            

class ServerSocket():
    def __init__ (self, qsend, qrevc):
        self.factory = Factory()
        self.factory.clients = dict()
        self.factory.protocol = Server
        self.factory.qsend = qsend
        self.factory.qrecv = qrevc
        p = threading.Thread(target=self.dataSent,args=(self.factory.qsend,))
        p.start()
    
    def dataSent(self, q):
        while True:
            (dpid, line) = q.get()
            if self.factory.clients[dpid]:
                self.factory.clients[dpid].sendLine(line)
        

# --- Server ---

def printLine (self, line):
    print "received", repr(line)

def main():
    s = ServerSocket(printLine)
    
    reactor.listenTCP(8000, s.factory)
    reactor.run()

if __name__ == '__main__':
    main()