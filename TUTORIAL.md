TUTORIAL

Running examples is simple.  Simple run "screen -S test" and ctrl-a ctrl-c to open a second screen (ctrl-a, ctrl-a toggles between the two).
In one screen run mininet, in the other run the pyretic controller.
Instructions for running each example are included below.

------------------------------
arp.py
------------------------------
pyretic/mininet.sh --topo clique,4,4                                                                                                                                                                                  
run controller: pox.py --no-cli pyretic/examples/arp.py                                                                                                                                                                             
in mininet: run pingall    once or twice, try clearing a node's arp entry for one of its neighbors - e.g., h1 arp -d h2 - and ping                                                                                                            
output from controller    NO RESPONSE AVAILABLE message should only show up once for each end host IP address                                                                                                                               

------------------------------
hub.py
------------------------------
start mininet:  ./pyretic/mininet.sh --switch ovsk --topo clique,4,4                                                     
run controller: pox.py --no-cli pyretic/examples/hub.py                 
in mininet: check connectivity with pingall

------------------------------
mac_learner.py
------------------------------
start mininet:  pyretic/mininet.sh --mac --topo linear,3                                                                 
run controller: pox.py --no-cli pyretic/examples/mac_learner.py   
in mininet: check connectivity with pingall

------------------------------
monitor.py
------------------------------
start mininet:  pyretic/mininet.sh --mac --topo linear,3                                                                 
run controller: pox.py --no-cli pyretic/examples/monitor.py   
ping away and watch the statistics fly (or change which example(s) execute in main and watch the packets fly)

------------------------------
load_balancer.py
------------------------------
start mininet:  pyretic/mininet.sh --topo=bump_clique,1,5,3                                              
run controller: pox.py --no-cli pyretic/examples/load_balancer.py --clients=5 --servers=3
test:           hX ping -c 1 10.0.0.100 will work from each host                                       
#                 all nodes will be able to ping each other, except hosts to their load-balanced instance 
#                 pingall will output                                                                                                                                                                                               
#                 h1 -> h2 h3 h4 h5 X hs2 hs3                                                                     
#                 h2 -> h1 h3 h4 h5 hs1 X hs3                                                                     
#                 h3 -> h1 h2 h4 h5 hs1 hs2 X                                                                     
#                 h4 -> h1 h2 h3 h5 X hs2 hs3                                                                     
#                 h5 -> h1 h2 h3 h4 hs1 X hs3                                                                     
#                 hs1 -> h1 h2 h3 h4 h5 hs2 hs3                                                                  
#                 hs2 -> h1 h2 h3 h4 h5 hs1 hs3                                                                  
#                 hs3 -> h1 h2 h3 h4 h5 hs1 hs2                                                                  
NOTE: by default this example runs the static firewall, but uncomment to run the dynamic version
            however, b/c the current setup has all hosts on the same LAN, when rebalances occur, pings may break as hosts are caching arp entries
            this isn't a bug in the dynamic firewall, but an artifact of testing it on a LAN instead of the gateway example to which the load balancer will ultimately be applied

------------------------------
firewall.py
------------------------------
start mininet:  pyretic/mininet.sh --topo=clique,5,5                                                                      
run controller: pox.py --no-cli pyretic/examples/firewall.py                                                          
test:           pingall. odd nodes should reach odd nodes w/ higher IP, likewise for even ones     
                 controller prints one message "punching hole for reverse traffic [IP1]:[IP2]" for each pair where IP1<IP2 
                 timeout seconds after last time punched hole used, it will close w/ corresponding print statement          
NOTE: state full firewall runs by default, simpler authentication and static firewalls can be used instead by recommenting file

------------------------------
kitchen_sink.py
------------------------------
"Firewall, load balance and route."

./pyretic/mininet.sh --switch ovsk --topo gateway
pox.py --no-cli pyretic/examples/kitchen_sink.py 

in mininet:  hN ping each other and 10.0.0.100 for N={1,2,3}, all other pings fail

sample output:
poking hole for 10.0.0.100,10.0.0.1
poking hole for 10.0.0.100,10.0.0.1
poking hole for 10.0.0.100,10.0.0.1
3 seconds w/o traffic, closing hole match:
    ('srcip', 00001010000000000000000001100100)
    ('dstip', 00001010000000000000000000000001)


------------------------------
virtualize.py
------------------------------
"Lets you run any module above on an abstract topology"

e.g.,
pox.py --no-cli pyretic/examples/virtualize.py --program=pyretic/examples/mac_learner.py --virttopo=pyretic/virttopos/bfs.py
pox.py --no-cli pyretic/examples/virtualize.py --program=pyretic/examples/composition.py --clients=3 --servers=2 --virttopo=pyretic/virttopos/spanning_tree.py