#!/bin/bash

sudo mn -c
sudo mn --custom /home/openflow/pyretic/mininet/extra-topos.py --controller remote $@
