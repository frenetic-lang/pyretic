#!/usr/bin/env python

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.protocols import basic

class Server(basic.LineReceiver):
    def connectionMade(self):
        print "Got new client!"
        self.factory.clients.append(self)

    def connectionLost(self, reason):
        print "Lost a client!"
        self.factory.clients.remove(self)

    def lineReceived(self, line):
        self.factory.callback(self, line)

class ServerSocket():
    def __init__ (self, callback):
        self.factory = Factory()
        self.factory.clients = []
        self.factory.callback = callback
        self.factory.protocol = Server
        

# --- Server ---

def printLine (self, line):
    print "received", repr(line)

def main():
    s = ServerSocket(printLine)
    
    reactor.listenTCP(8000, s.factory)
    reactor.run()

if __name__ == '__main__':
    main()