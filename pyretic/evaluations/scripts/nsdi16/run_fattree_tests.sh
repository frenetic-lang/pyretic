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

k=0
INC=1
name=${OPT_NAMES_ARR[$i]}
for POL_FLAGS in "${POL_FLAGS_ARR[@]}"
do

    echo '-----' | $cap_cmd
    echo "Start time" | $cap_cmd
    date | $cap_cmd
    polflag=${POL_NAMES_ARR[$k]}
    run_cmd="sudo timeout $RUN_TIMEOUT $PYCMD pyretic/evaluations/eval_compilation.py -t $TEST -u -r $OPT_FLAGS $POL_FLAGS -f evaluation_results/nsdi16/${TEST}_${polflag}_${name}_$j"
    echo $run_cmd | $cap_cmd
    $run_cmd | $cap_cmd
    echo "Done with run" $TEST $name $polflag $j | $cap_cmd
    echo "End time" | $cap_cmd
    date | $cap_cmd
    k=$((k + INC))
done # end polargs loop

i=$((i + DCR))

done # end opts loop

done # end test loop

done # end count loop
}
