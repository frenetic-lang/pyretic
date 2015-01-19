#declare -a OPT_FLAGS_ARR=("-d -l -i -c" "-d -l -i" "-d -l" "-d" "-l" " ")

#TEST='path_loss_stanford'

#i=6
#DCR=1
#for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
#do
#    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford/path_loss/pl_$i/
#    i=$((i - DCR ))
#    sleep 10
#done


declare -a OPT_FLAGS_ARR=("-l" " ")

TEST='traffic_matrix_stanford'

i=2
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford/traffic_matrix/tm_$i/
    i=$((i - DCR ))
    sleep 10
done



