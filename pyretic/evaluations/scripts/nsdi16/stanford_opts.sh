#!/bin/sh

source pyretic/evaluations/scripts/nsdi16/run_stanford_tests.sh
source pyretic/evaluations/scripts/nsdi16/init_settings.sh

declare -a OPT_FLAGS_ARR=("-d -l" "")
declare -a OPT_NAMES_ARR=("disjoint" "noopts")
declare -a TESTS=("stanford")
CNT=1
run_tests

declare -a OPT_FLAGS_ARR=("-d -l -i" "-d -l -i -a" "-d -l -i -a -c" "-d -l -i -a -c -b" "-d -l -i -a -c -b --use_fdd")
declare -a OPT_NAMES_ARR=("integration" "partition" "cache" "preddecomp" "fdd")
declare -a TESTS=("stanford")
CNT=5
run_tests
