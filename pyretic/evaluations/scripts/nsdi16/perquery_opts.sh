#!/bin/sh

declare -a OPT_FLAGS_ARR=("" "-d -l" "-d -l -i" "-d -l -i -a" "-d -l -i -a -c" "-d -l -i -a -c -b")
# declare -a OPT_NAMES_ARR=("disjoint" "integration" "partition" "cache" "preddecomp" "fdd")
declare -a OPT_NAMES_ARR=("noopts" "disjoint" "integration" "partition" "cache" "preddecomp")
declare -a TESTS=("ddos_stanford" "firewall_stanford" "path_loss_stanford" "slice_stanford")

SCRIPT_LOG="pyretic/evaluations/script-log.txt"
rm -f $SCRIPT_LOG

function run_tests {
CNT=5
for j in $(seq 1 $CNT)
do

echo '*****' Starting run $j | tee -a $SCRIPT_LOG
for TEST in "${TESTS[@]}";
do

echo '----' | tee -a $SCRIPT_LOG
echo "Running test" $TEST | tee -a $SCRIPT_LOG
i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo '-----' | tee -a $SCRIPT_LOG
    echo "Start time" | tee -a $SCRIPT_LOG
    date | tee -a $SCRIPT_LOG
    name=${OPT_NAMES_ARR[$i]}
    echo sudo /opt/pypy-2.4.0/bin/pypy pyretic/evaluations/eval_compilation.py -t $TEST -u -r -s 16 $OPT_FLAGS -f evaluation_results/nsdi16/${TEST}_${name}_$j | tee -a $SCRIPT_LOG
    sudo /opt/pypy-2.4.0/bin/pypy pyretic/evaluations/eval_compilation.py -t $TEST -u -r -s 16 $OPT_FLAGS -f evaluation_results/nsdi16/${TEST}_${name}_$j | tee -a $SCRIPT_LOG
    i=$((i + DCR))
done # end opts loop

done # end test loop

done # end count loop
}

run_tests

declare -a OPT_FLAGS_ARR=("-d -l -i" "-d -l -i -a" "-d -l -i -a -c" "-d -l -i -a -c -b")
declare -a OPT_NAMES_ARR=("integration" "partition" "cache" "preddecomp")
declare -a TESTS=("traffic_matrix_stanford" "congested_stanford" )

run_tests
