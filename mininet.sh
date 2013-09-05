#!/bin/bash

sudo ~/pyretic-dev/mininet/mn -c
sudo ~/pyretic-dev/mininet/mn --custom $HOME/pyretic-dev/mininet/extra-topos.py --controller remote --mac $@
