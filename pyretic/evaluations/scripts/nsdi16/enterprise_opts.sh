#!/bin/sh

source pyretic/evaluations/scripts/nsdi16/run_enterprise_tests.sh
source pyretic/evaluations/scripts/nsdi16/init_settings.sh

declare -a OPT_FLAGS_ARR=("-d -l -i -a -c -b" "-d -l -i -a -c -b --use_fdd")
declare -a OPT_NAMES_ARR=("preddecomp" "fdd")
declare -a TESTS=("berkley" "purdue" "rf3257" "rf6461")
declare -a NUM_NODES_ARR=("23" "98" "161" "138")
CNT=5
run_tests
