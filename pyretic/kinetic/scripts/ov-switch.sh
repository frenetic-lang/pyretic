#!/bin/bash

case "$1" in
   start)
      echo "Starting Open vSwitch ..." 
      # Clear eth1
      ifconfig eth1 0
      ifconfig eth1 promisc
      # Clear eth2
      ifconfig eth2 0
      ifconfig eth2 promisc
      # Clear eth0
      ifconfig eth0 0
      ifconfig eth0 promisc
      # Configure "ov-switch"
      ovs-vsctl add-br ov-switch
      ovs-vsctl add-port ov-switch eth1
      ovs-vsctl add-port ov-switch eth2
      ovs-vsctl add-port ov-switch eth0
      # Bring up "ov-switch"
      ifconfig ov-switch up
      # Assign remote controller
      ovs-vsctl set-controller ov-switch tcp:127.0.0.1:6633
      ovs-vsctl set-fail-mode ov-switch secure
   ;;
   stop)
      echo "Stopping Open vSwitch ..."
      # Delete remote controller
      ovs-vsctl del-controller ov-switch
      ovs-vsctl del-fail-mode ov-switch
      # Turn down "ov-switch"
      ifconfig ov-switch down
      # Delete "ov-switch"
      ovs-vsctl del-br ov-switch      
      # Restart Network Service
      ifconfig eth1 -promisc
      ifconfig eth1 down
      ifconfig eth2 -promisc
      ifconfig eth2 down
      ifconfig eth0 -promisc
      ifconfig eth0 down
   ;;
   enable-sflow)
      echo "Enabling sFlow ..." 
      ovs-vsctl -- --id=@sflow create sflow agent=eth3 target=\"127.0.0.1:6343\" \
      sampling=2 polling=20 -- -- set bridge ov-switch sflow=@sflow
   ;;
   disable-sflow)
      echo "Disabling sFlow ..."  	
	  ovs-vsctl -- clear bridge ov-switch sflow
   ;;
   *)
      echo "Usage: ov-switch.sh {start|stop}"
   ;;
esac
