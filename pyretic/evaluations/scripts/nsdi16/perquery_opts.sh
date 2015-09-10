#!/bin/sh

source pyretic/evaluations/scripts/nsdi16/run_tests.sh
source pyretic/evaluations/scripts/nsdi16/init_settings.sh

declare -a OPT_FLAGS_ARR=("-d -l")
declare -a OPT_NAMES_ARR=("disjoint")
declare -a TESTS=("congested_stanford" "traffic_matrix_stanford")
CNT=5
run_tests

declare -a OPT_FLAGS_ARR=("")
declare -a OPT_NAMES_ARR=("noopts")
declare -a TESTS=("congested_stanford" "traffic_matrix_stanford")
CNT=5
run_tests

# remove the `exit` below to generate full table of results
exit 

declare -a OPT_FLAGS_ARR=("" "-d -l" "-d -l -i" "-d -l -i -a" "-d -l -i -a -c" "-d -l -i -a -c -b")
declare -a OPT_NAMES_ARR=("noopts" "disjoint" "integration" "partition" "cache" "preddecomp")
declare -a TESTS=("ddos_stanford" "firewall_stanford" "path_loss_stanford" "slice_stanford")
CNT=5
run_tests

declare -a OPT_FLAGS_ARR=("-d -l -i" "-d -l -i -a" "-d -l -i -a -c" "-d -l -i -a -c -b")
declare -a OPT_NAMES_ARR=("integration" "partition" "cache" "preddecomp")
declare -a TESTS=("traffic_matrix_stanford" "congested_stanford" )
CNT=5
run_tests
