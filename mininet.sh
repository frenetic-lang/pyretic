#!/bin/bash

VER=`mn --version`

if [[ "$VER" < "2.2.0" ]] 
then
    MN="$HOME/pyretic/local_mininet/mn"
else
    MN=mn
fi
sudo $MN -c
sudo $MN --custom $HOME/pyretic/local_mininet/extratopos.py --controller remote --mac $@
