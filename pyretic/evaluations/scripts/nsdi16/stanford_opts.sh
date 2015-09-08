#!/bin/sh

# declare -a OPT_FLAGS_ARR = ("-d -l" "-d -l -i" "-d -l -i -a" "-d -l -i -a -c" "-d -l -i -a -c -b" "-d -l -i -a -c -b --use_fdd")
declare -a OPT_FLAGS_ARR=("-d -l" "-d -l -i" "-d -l -i -a" "-d -l -i -a -c" "-d -l -i -a -c -b")
# declare -a OPT_NAMES_ARR=("disjoint" "integration" "partition" "cache" "preddecomp" "fdd")
declare -a OPT_NAMES_ARR=("disjoint" "integration" "partition" "cache" "preddecomp")

CNT=5
for j in $(seq 1 $CNT)
do

echo '*****' Starting run $j
TEST='stanford'
i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start time"
    date
    name=${OPT_NAMES_ARR[$i]}
    echo sudo /opt/pypy-2.4.0/bin/pypy pyretic/results/eval_compilation.py -t $TEST -u -r -s 16 $OPT_FLAGS -f evaluation_results/nsdi16/${TEST}_${name}_$j
    sudo /opt/pypy-2.4.0/bin/pypy pyretic/results/eval_compilation.py -t $TEST -u -r -s 16 $OPT_FLAGS -f evaluation_results/nsdi16/${TEST}_${name}_$j
    i=$((i + DCR))
done # end opts loop

done # end count loop
