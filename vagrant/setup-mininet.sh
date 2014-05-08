#!/usr/bin/env bash

git clone git://github.com/mininet/mininet
pushd mininet
git checkout -b 2.1.0 2.1.0
# Install reference switch, kernel module, wireshark disector, openvswitch, mininet
. util/install.sh -fmwvn
