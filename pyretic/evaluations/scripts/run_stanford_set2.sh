declare -a OPT_FLAGS_ARR=("-d -l -i -s 16 -c -g" "-d -l -i -s 16 -c" "-d -l -i -s 16 -g" "-d -l -i -c -g" "-d -l -s 16 -c -g")
declare -a OPT_NAMES_ARR=("all" "edge_unification" "cache" "partition" "integration")

TEST='traffic_matrix_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start Time"
    date
    name=${OPT_NAMES_ARR[$i]}
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/traffic_matrix/$name/
    i=$((i + DCR ))
    sleep 10
done

TEST='congested_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start Time"
    date
    name=${OPT_NAMES_ARR[$i]}
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/congested_link/$name/
    i=$((i + DCR ))
    sleep 10
done




declare -a OPT_FLAGS_ARR=("-d -l -i -s 16 -c -g" "-d -l -i -s 16 -c" "-d -l -i -s 16 -g" "-d -l -i -c -g" "-d -l -s 16 -c -g" "-i -s 16 -c -g")
declare -a OPT_NAMES_ARR=("all" "edge_unification" "cache" "partition" "integration" "default_disjoint")

TEST='path_loss_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start Time"
    date
    name=${OPT_NAMES_ARR[$i]}
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/path_loss/$name/
    i=$((i + DCR ))
    sleep 10
done

TEST='firewall_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start Time"
    date
    name=${OPT_NAMES_ARR[$i]}
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/firewall/$name/
    i=$((i + DCR ))
    sleep 10
done

TEST='ddos_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start Time"
    date
    name=${OPT_NAMES_ARR[$i]}
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/ddos/$name/
    i=$((i + DCR ))
    sleep 10
done

TEST='slice_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start Time"
    date
    name=${OPT_NAMES_ARR[$i]}
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/slice_2/$name/
    i=$((i + DCR ))
    sleep 10
done





