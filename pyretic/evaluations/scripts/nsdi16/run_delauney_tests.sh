TEST=igen_delauney
function run_tests {
cap_cmd="tee -a $SCRIPT_LOG"
for j in $(seq 1 $CNT)
do

nodeindex=0
INCR=1
echo '*****' Starting run $j | $cap_cmd
for NUM_NODES in "${NUM_NODES_ARR[@]}";
do

echo '----' | $cap_cmd
echo "Running test" $TEST | $cap_cmd
i=0
DCR=1
for QUERY_FLAGS in "${QUERY_FLAGS_ARR[@]}"
do
    echo '-----' | $cap_cmd
    echo "Start time" | $cap_cmd
    date | $cap_cmd
    name=${QUERY_NAMES_ARR[$i]}
    run_cmd="sudo timeout $RUN_TIMEOUT $PYCMD pyretic/evaluations/eval_compilation.py -t $TEST -u -r -s $NUM_NODES $OPT_FLAGS -polargs $QUERY_FLAGS n $NUM_NODES -f evaluation_results/nsdi16/${name}_${TEST}_${NUM_NODES}_${OPT_NAME}_$j"
    echo $run_cmd | $cap_cmd
    $run_cmd 2>&1 | $cap_cmd
    dmesg | tail -4 | $cap_cmd
    echo "Done with run" $TEST $name $j $NUM_NODES | $cap_cmd
    echo "End time" | $cap_cmd
    date | $cap_cmd
    i=$((i + DCR))
done # end per-query-combination loop

nodeindex=$((nodeindex + INCR))
done # end test loop

done # end count loop
}
