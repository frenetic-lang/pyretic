#!/bin/bash

# Check if frenetic compile-server runs, and kill it if it does.
ps ax | grep 'frenetic compile-server'
if [ `ps ax | grep 'frenetic compile-server' | wc -l` -lt 2 ]; then
    killall frenetic
fi
