#!/usr/bin/env python

from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.protocols import basic
from multiprocessing import Queue
import threading
import pickle

class Server(basic.LineReceiver):
    def connectionMade(self):
        print "Got new client!"
        self.factory.clients[self] = None

    def connectionLost(self, reason):
        print "Lost a client!"
        del self.factory.clients[self]

    def lineReceived(self, line):
        print '----------- lineReceived ---------'
        input_list = pickle.loads(line)
        print input_list
        act = input_list[0]
#        print act
        if act == 'handle_switch_join':
            switch = input_list[1]
            self.factory.clients[self] = switch
            self.factory.id_to_client[switch] = self 
        self.factory.qrecv.put(input_list)
        print '-------- curent id_to_client ------------'
        print self.factory.id_to_client            

class ServerSocket():
    def __init__ (self, qsend, qrevc):
        self.factory = Factory()
        self.factory.clients = dict()
        self.factory.id_to_client = dict()
        self.factory.protocol = Server
        self.factory.qsend = qsend
        self.factory.qrecv = qrevc
        p = threading.Thread(target=self.dataSent,args=(self.factory.qsend,))
        p.start()
    
    def dataSent(self, q):
        while True:
            (sid,to_send_l) = q.get()
            import pickle
            to_send = pickle.dumps(to_send_l)
            print '----------- dataSent --------------'
            print sid,pickle.loads(to_send)
            try:
                self.factory.id_to_client[sid].sendLine(to_send)
                print "do ...."
            except KeyError:
                print 'no client for %d yet' % sid
        

# --- Server ---

def printLine (self, line):
    print "received", repr(line)

def main():
    s = ServerSocket(printLine)
    
    reactor.listenTCP(8000, s.factory)
    reactor.run()

if __name__ == '__main__':
    main()
