#!/usr/bin/python

from unit_util import *

def clientServerConnectivity(clients,servers,canonical_ip,results):

    for c1 in clients:
        for c2 in clients:
            try:
                # IF ALL PINGS FAILED FOR ANY CLIENT PAIR
                # CONNECTIVITY FAILS
                if results[c1.name][c2.name] == 0:
                    return False
            except KeyError:
                pass    

        missing = 0
        for s in servers:
            if results[c1.name][s.name] == 0:
                missing += 1
        # EXACTLY ONE SERVER SHOULD BE UNREACHABLE
        if missing != 1:
            return False

        # AND SHOULD RESPOND AS THE CANONICAL IP
        if results[c1.name][canonical_ip] == 0:
                return False

    return True


def parseArgs():
    """Parse command-line args and return options object.
    returns: opts parse options dict"""
    parseCustomFile(os.path.expanduser('~/pyretic/mininet/extra-topos.py'))
    
    desc = ( "The %prog utility creates Mininet network from the\n"
             "command line. It can create parametrized topologies,\n"
             "invoke the Mininet CLI, and run tests." )

    usage = ( '%prog [options]\n'
              '(type %prog -h for details)' )
    
    opts = OptionParser( description=desc, usage=usage )
    addDictOption( opts, TOPOS, TOPODEF, 'topo' )
    opts.add_option( '--verbose', '-v', action="store_true", dest="verbose")
    opts.add_option( '--quiet', '-q', action="store_true", dest="quiet")
    opts.add_option( '--ping-type', '-p', type='choice',
                     choices=['ICMP','TCP80SYN'], default = 'ICMP',
                     help = '|'.join( ['ICMP','TCP80SYN'] )  )
    opts.add_option( '--count', '-n', action="store", type="string", 
                     dest="count", default='1', help = 'number of ping attempts'  )
    opts.add_option( '--clients', '-c', action="store", type="string", 
                     dest="clients", default='2', help = 'number of clients'  )
    opts.add_option( '--servers', '-s', action="store", type="string", 
                     dest="servers", default='2', help = 'number of servers'  )

    options, args = opts.parse_args()
    if options.quiet and options.verbose:
        opts.error("options -q and -v are mutually exclusive")
    return (options, args)


def main():

    (options, args) = parseArgs()
    num_clients = int(options.clients)
    num_servers = int(options.servers)

    ## SET LOGGING AND CLEANUP PREVIOUS MININET STATE, IF ANY
#    lg.setLogLevel('info')
    cleanup()

    ## SET UP TOPOLOGY
    topo = buildTopo( TOPOS, options.topo )

    ## SET UP MININET INSTANCE AND START
    net = Mininet( topo, switch=OVSKernelSwitch, host=Host, controller=RemoteController )
    net.start()

    results = ping_all_sequential(net,options.verbose,options.ping_type,options.count,['10.0.0.100'])
    connectivity = clientServerConnectivity(net.hosts[:num_clients],net.hosts[-num_servers:],'10.0.0.100',results)

    if not options.quiet:
        if connectivity:
            print "Unit test: success"
        else:
            print "Unit test: failure"

    ## SHUTDOWN MININET
    net.stop()

    if connectivity:
        sys.exit(0)
    else:
        sys.exit(-1)
            
    
if __name__ == '__main__':
    main()
