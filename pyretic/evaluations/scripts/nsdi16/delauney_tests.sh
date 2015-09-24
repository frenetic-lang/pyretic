#!/bin/sh

source pyretic/evaluations/scripts/nsdi16/run_delauney_tests.sh
source pyretic/evaluations/scripts/nsdi16/init_settings.sh

declare -a QUERY_FLAGS_ARR=("q1 tm" "q1 congested_link" "q1 ddos" "q1 slice" "q1 path_loss" "q1 firewall")
declare -a QUERY_NAMES_ARR=("tm" "congested_link" "ddos" "slice" "path_loss" "firewall")
declare -a NUM_NODES_ARR=("20" "40" "60" "80" "100" "120" "140" "160")
declare -a OPT_FLAGS="-d -l -i -a -c -b --use_fdd"
declare -a OPT_NAME="fdd"
CNT=5
run_tests

declare -a QUERY_FLAGS_ARR=("q1 tm" "q1 congested_link" "q1 ddos" "q1 slice" "q1 path_loss" "q1 firewall")
declare -a QUERY_NAMES_ARR=("tm" "congested_link" "ddos" "slice" "path_loss" "firewall")
declare -a NUM_NODES_ARR=("180" "200" "250")
declare -a OPT_FLAGS="-d -l -i -a -c -b --use_fdd"
declare -a OPT_NAME="fdd"
CNT=5
run_tests
