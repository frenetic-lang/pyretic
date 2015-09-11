function run_tests {
cap_cmd="tee -a $SCRIPT_LOG"
for j in $(seq 1 $CNT)
do

echo '*****' Starting run $j | $cap_cmd
for TEST in "${TESTS[@]}";
do

echo '----' | $cap_cmd
echo "Running test" $TEST | $cap_cmd
i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo '-----' | $cap_cmd
    echo "Start time" | $cap_cmd
    date | $cap_cmd
    name=${OPT_NAMES_ARR[$i]}
    run_cmd="sudo timeout $RUN_TIMEOUT $PYCMD pyretic/evaluations/eval_compilation.py -t $TEST -u -r -s 16 $OPT_FLAGS -f evaluation_results/nsdi16/${TEST}_${name}_$j"
    echo $run_cmd | $cap_cmd
    $run_cmd | $cap_cmd
    echo "Done with run" $TEST $name $j | $cap_cmd
    echo "End time" | $cap_cmd
    date | $cap_cmd
    i=$((i + DCR))
done # end opts loop

done # end test loop

done # end count loop
}
