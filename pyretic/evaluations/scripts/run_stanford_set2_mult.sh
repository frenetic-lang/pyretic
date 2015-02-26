:<<COMMENT1
CNT=100

declare -a OPT_FLAGS_ARR=("-d -l -i -s 16 -c -g" "-d -l -i -s 16 -c" "-d -l -i -s 16 -g" "-d -l -i -c -g" "-d -l -s 16 -c -g" "-i -s 16 -c -g")
declare -a OPT_NAMES_ARR=("all" "edge_unification" "cache" "partition" "integration" "default_disjoint")

for j in $(seq 1 $CNT)
do

TEST='path_loss_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
        echo "Start Time"
        date
        name=${OPT_NAMES_ARR[$i]}
        sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/path_loss/$name/$j
        i=$((i + DCR ))
done

TEST='firewall_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
        echo "Start Time"
        date
        name=${OPT_NAMES_ARR[$i]}
        sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/firewall/$name/$j
        i=$((i + DCR ))
done

TEST='ddos_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
        echo "Start Time"
        date
        name=${OPT_NAMES_ARR[$i]}
        sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/ddos/$name/$j
        i=$((i + DCR ))
done

TEST='slice_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
        echo "Start Time"
        date
        name=${OPT_NAMES_ARR[$i]}
        sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/slice_2/$name/$j
        i=$((i + DCR ))
done

done
COMMENT1

CNT=5
declare -a OPT_FLAGS_ARR=("-d -l -i -s 16 -c -g" "-d -l -i -s 16 -c" "-d -l -i -s 16 -g" "-d -l -i -c -g" "-d -l -s 16 -c -g")
declare -a OPT_NAMES_ARR=("all" "edge_unification" "cache" "partition" "integration")


for j in $(seq 2 $CNT)
do
TEST='traffic_matrix_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start Time"
    date
    name=${OPT_NAMES_ARR[$i]}
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/traffic_matrix/$name/$j
    i=$((i + DCR ))
done

TEST='congested_stanford'

i=0
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    echo "Start Time"
    date
    name=${OPT_NAMES_ARR[$i]}
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford_orth/congested_link/$name/$j
    i=$((i + DCR ))
done
done



