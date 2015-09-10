function run_tests {
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
    cmd="sudo timeout $RUN_TIMEOUT $PYCMD pyretic/evaluations/eval_compilation.py -t $TEST -u -r -s 16 $OPT_FLAGS -f evaluation_results/nsdi16/${TEST}_${name}_$j | tee -a $SCRIPT_LOG"
    echo $cmd
    $cmd
    echo "Done with run" $TEST $name $j | tee -a $SCRIPT_LOG
    echo "End time" | tee -a $SCRIPT_LOG
    date | tee -a $SCRIPT_LOG
    i=$((i + DCR))
done # end opts loop

done # end test loop

done # end count loop
}
