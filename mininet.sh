#!/bin/bash

sudo ~/pyretic/mininet/mn -c
sudo ~/pyretic/mininet/mn --custom $HOME/pyretic/mininet/extra-topos.py --controller remote --mac $@
