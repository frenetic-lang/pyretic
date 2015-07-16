#!/bin/bash

VER=`mn --version`

if [[ "$VER" < "2.2.0" ]] 
then
    MN="$HOME/pyretic/mininet/mn"
else
    MN=mn
fi
sudo $MN -c
sudo $MN --custom $HOME/pyretic/mininet/extra-topos.py --controller remote --mac $@
