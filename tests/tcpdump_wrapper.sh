#!/bin/bash   

IFACE=`ifconfig | head -n 1 | awk '{print $1}'`
tcpdump -XX -vvv -t -n -i $IFACE not ether proto 0x88cc #> $IFACE.dump