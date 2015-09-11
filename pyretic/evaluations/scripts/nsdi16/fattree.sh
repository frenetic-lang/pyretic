#!/bin/sh

source pyretic/evaluations/scripts/nsdi16/run_fattree_tests.sh
source pyretic/evaluations/scripts/nsdi16/init_settings.sh

declare -a OPT_FLAGS_ARR=("-d -l -i -a -c -b --use_fdd")
declare -a OPT_NAMES_ARR=("fdd")
declare -a TESTS=("fattree")
declare -a POL_FLAGS_ARR=("-polargs k 4 fout 2 -s 20" "-polargs k 6 fout 3 -s 45" "-polargs k 8 fout 4 -s 80" "-polargs k 10 fout 5 -s 125" "-polargs k 12 fout 6 -s 180" "-polargs k 14 fout 7 -s 245" "-polargs k 16 fout 8 -s 320" "-polargs k 18 fout 9 -s 405" "-polargs k 20 fout 10 -s 500")
declare -a POL_NAMES_ARR=("k4" "k6" "k8" "k10" "k12" "k14" "k16" "k18" "k20")
CNT=2
run_tests
