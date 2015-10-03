#!/bin/sh

source pyretic/evaluations/scripts/nsdi16/run_enterprise_tests.sh
source pyretic/evaluations/scripts/nsdi16/init_settings.sh

declare -a QUERY_FLAGS_ARR=("q1 tm" "q1 congested_link" "q1 ddos" "q1 slice" "q1 path_loss" "q1 firewall")
declare -a QUERY_NAMES_ARR=("tm" "congested_link" "ddos" "slice" "path_loss" "firewall")
# remove purdue from tested enterprises; data not publicly available
# declare -a TESTS=("berkley" "purdue" "rf1755")
declare -a TESTS=("berkley" "rf1755")
declare -a NUM_NODES_ARR=("25" "98" "87")
declare -a OPT_FLAGS="-d -l -i -a -c -b --use_fdd"
declare -a OPT_NAME="fdd"
CNT=5
run_tests

declare -a QUERY_FLAGS_ARR=("q1 tm" "q1 congested_link" "q1 ddos" "q1 slice" "q1 path_loss" "q1 firewall")
declare -a QUERY_NAMES_ARR=("tm" "congested_link" "ddos" "slice" "path_loss" "firewall")
declare -a TESTS=("rf6461" "rf3257")
declare -a NUM_NODES_ARR=("138" "161")
declare -a OPT_FLAGS="-d -l -i -a -c -b --use_fdd"
declare -a OPT_NAME="fdd"
CNT=5
run_tests
