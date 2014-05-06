#!/usr/bin/env python

from twisted.internet.protocol import ClientFactory, Factory
from twisted.internet import reactor
from twisted.protocols import basic

class Client(basic.LineReceiver):
    def connectionMade(self):
        print "Got client!"
        self.factory.client = self

    def connectionLost(self, reason):
        print "Lost client!"
        self.factory.client = None
    
    def lineReceived(line):
        self.factory.callback(line)

class ClientSocket():
    def __init__ (self, callback):
        self.factory = ClientFactory()
        self.factory.client = None
        self.factory.callback = callback
        self.factory.protocol = Client


# --- Client ---

def printLine (line):
    print "received", repr(line)

def main():
    c = ClientSocket(printLine)
    
    reactor.connectTCP('localhost', 8000, c.factory)
    reactor.run()

if __name__ == '__main__':
    main()