#!/bin/bash
cd $HOME/pyretic

port=$1
port_str="0.0.0.0:${port}->"

if [ `docker ps | grep $port_str | wc -l` -lt 1 ]; then
    docker run -d -p ${port}:9000 ngsrinivas/pathquery:v1 ./pyretic/frenetic compile-server
fi
