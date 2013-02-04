#!/usr/bin/python

from unit_util import *

def clientServerConnectivity(clients,servers,canonical_ip,results,verbose=False):
    cutoff = 0.1
    for c1 in clients:
        for c2 in clients:
            try:
                # IF ALL PINGS FAILED FOR ANY CLIENT PAIR
                # CONNECTIVITY FAILS 
                if results[c1.name][c2.name] < cutoff:
                    if verbose:  print "(%s,%s) failed" % (c1,c2)
                    return False
            except KeyError:
                pass    

        missing = 0
        for s in servers:
            if results[c1.name][s.name] < cutoff:
                missing += 1
        # EXACTLY ONE SERVER SHOULD BE UNREACHABLE
        if missing != 1:
            if verbose:  print "%s missing %d servers" % (c1,missing)
            return False

        # AND SHOULD RESPOND AS THE CANONICAL IP
        if results[c1.name][canonical_ip] < cutoff:
            if verbose:  print "%s cannot connect to %s" (c1,cannonical_ip)
            return False

    # SERVERS SHOULD HAVE FULL CONNECTIVITY TO ALL HOSTS, NONE TO CANNONICAL ADDRESS
    for s1 in servers:
        for s2 in servers:
            try:
                if results[s1.name][s2.name] < cutoff:
                    if verbose:  print "(%s,%s) failed" % (s1,s2)
                    return False
            except KeyError:
                pass
        for c1 in clients:
            if results[s1.name][c1.name] < cutoff:
                if verbose:  print "(%s,%s) failed" % (s1,c1)
                return False

        if not results[s1.name][canonical_ip] < cutoff:
            if verbose:  print "%s can connect to %s" (s1,cannonical_ip)
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
    opts.add_option( '--ping-pattern', '-P', type='choice',
                     choices=['sequential','intermediate','parallel'], default = 'sequential' ,
                     help = '|'.join( ['sequential','intermediate','parallel'] )  )
    opts.add_option( '--count', '-n', action="store", type="string", 
                     dest="count", default='1', help = 'number of ping attempts'  )
    opts.add_option( '--clients', '-c', action="store", type="string", 
                     dest="clients", default='2', help = 'number of clients'  )
    opts.add_option( '--servers', '-s', action="store", type="string", 
                     dest="servers", default='2', help = 'number of servers'  )
    opts.add_option( '--switch', action="store", type="string", 
                     dest="switch", default='ovsk', help = 'ovsk|user'  )

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
    net = Mininet( topo, switch=SWITCHES[options.switch], host=Host, controller=RemoteController )
    net.start()
    if options.verbose:  print "Mininet started"

    # WAIT FOR CONTROLLER TO HOOK UP
    # TODO - PARAMETERIZE WAIT BASED ON NUMBER OF LINKS
    sleep(WARMUP)

    # RUN TESTS
    if options.verbose:  print "Test beginning"

    start = time()
    results = ping_all(net,options.verbose,options.ping_type,options.count,options.ping_pattern,['10.0.0.100'])
    elapsed = time() - start
    if options.verbose:  print "Test done, processing results"
    connectivity = clientServerConnectivity(net.hosts[:num_clients],net.hosts[-num_servers:],'10.0.0.100',results,options.verbose)

    if not options.quiet:
        if connectivity:
            print "%s\t%s\t%s" % (options.topo,passed_str(connectivity),elapsed)

    ## SHUTDOWN MININET
    net.stop()

    if connectivity:
        sys.exit(0)
    else:
        sys.exit(-1)
            
    
if __name__ == '__main__':
    main()
