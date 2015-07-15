#!/bin/bash

# Check if frenetic compile-server runs already, and start it up if it doesn't.
if [ `ps ax | grep 'frenetic compile-server' | wc -l` -lt 2 ]; then
    ./frenetic compile-server --verbosity=error
fi
