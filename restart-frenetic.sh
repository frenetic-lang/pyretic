#!/bin/bash

# Kill the frenetic compile-server if it's running; then restart it.
if [ `ps ax | grep 'frenetic compile-server' | grep -v grep | wc -l` -gt 0  ];
then
    kill `ps ax | grep 'frenetic compile-server' | grep -v grep | awk '{print $1}'`
fi
./frenetic compile-server --verbosity error
