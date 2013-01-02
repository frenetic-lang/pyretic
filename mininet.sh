#!/bin/bash

sudo mn -c
sudo mn --custom $HOME/pyretic/mininet/extra-topos.py --controller remote --mac $@
