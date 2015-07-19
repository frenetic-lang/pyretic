#!/usr/bin/bash

# Script invoked every time nfcapd processes a new output file from the incoming
# netflow stream. This does a couple of things:
# 1. Runs nfdump on the latest output file that was created (supplied as a
# command line argument to this script).

# 2. Kills a "dormant shell" process, which notifies (through process waiting in
# a python thread) a python callback function that a new output file has
# arrived.

cat $1 | nfdump > pyretic/scratch/latest-dump.txt
kill `ps ax | grep 'bash pyretic/lib/helpers/dormant_shell.sh' | grep -v grep | awk '{print $1}'`

