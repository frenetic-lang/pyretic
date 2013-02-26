#!/usr/bin/python

from unit_util import *

def fullConnectivity(hosts,results):

    for h1 in hosts:
        for h2 in hosts:
            try:
                # IF ALL PINGS FAILED FOR ANY HOST PAIR
                # CONNECTIVITY FAILS
                if results[h1.name][h2.name] == 0:
                    return False
            except KeyError:
                pass    
    
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
    opts.add_option( '--count', '-c', action="store", type="string", 
                     dest="count", default='1', help = 'number of ping attempts'  )
    opts.add_option( '--switch', '-s', action="store", type="string", 
                     dest="switch", default='ovsk', help = 'ovsk|user'  )
    options, args = opts.parse_args()

    if options.quiet and options.verbose:
        opts.error("options -q and -v are mutually exclusive")
    return (options, args)


def main():

    (options, args) = parseArgs()

    ## SET LOGGING AND CLEANUP PREVIOUS MININET STATE, IF ANY
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

    # START DUMP COLLECTION 
    if options.verbose:  print "Starting tcpdump collection"
    ct = collect_tcpdumps(net.hosts)

    # RUN TESTS
    if options.verbose:  print "Test beginning"
    start = time()
    results = ping_all(net,options.verbose,options.ping_type,options.count,options.ping_pattern)
    elapsed = time() - start
    if options.verbose:  print "Test done, processing results"
    connectivity = fullConnectivity(net.hosts,results)

    ## SHUTDOWN MININET
    net.stop()

    # GET DUMPS AND PROCESS
    dumps = get_tcpdumps(ct)
    packets = dumps_to_packets(dumps)
    packet_behavior = mac_learner_packet_behavior(packets,options.verbose)

    if not options.quiet:
        print "%s\t%s\t%s\t%s" % (options.topo,passed_str(connectivity),passed_str(packet_behavior),elapsed)

    if connectivity and packet_behavior:
        sys.exit(0)
    else:
        sys.exit(-1)
            
    
if __name__ == '__main__':
    main()
