#declare -a OPT_FLAGS_ARR=("-d -l -i -s 16 -c -g" "-d -l -i -s 16 -c" "-d -l -i -s 16" "-d -l -i" "-d -l" "-d" " ")
OPT_FLAGS="-d -l -i -c -g"

TEST='firewall'
for i in $(seq 22 2 24)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./fattree_con/$TEST/$i
    sleep 10
done


:<<COMMENT

TEST='congested_link'
for i in $(seq 2 2 12)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./fattree_con/all_2/$i
    sleep 10
done

TEST='congested_link'
for i in $(seq 2 2 12)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout 2 -f ./fattree_con/all_k/$i
    sleep 10
done

sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s 16 $OPT_FLAGS -t traffic_matrix_stanford -a path_loss_stanford congested_stanford slice_stanford firewall_stanford ddos_stanford -f ./stanford_incremental/set8/inc/
COMMENT
