#declare -a OPT_FLAGS_ARR=("-d -l -i -s 16 -c -g" "-d -l -i -s 16 -c" "-d -l -i -s 16" "-d -l -i" "-d -l" "-d" " ")
OPT_FLAGS="-d -l -i -c -g"

for j in $(seq 3 1 3)
do

TEST='path_packet_loss'

for i in $(seq 2 2 38)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./fattree_$j/$TEST/all/$i
    sleep 5
done

:<<COMMENT1
TEST='traffic_matrix'

for i in $(seq 2 2 10)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./fattree_$j/$TEST/all/$i
    sleep 5
done

TEST='congested_link'
for i in $(seq 2 2 10)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./fattree_$j/$TEST/all/$i
    sleep 5
done

TEST='firewall'

for i in $(seq 2 2 20)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./fattree_$j/$TEST/all/$i
    sleep 5
done


TEST='ddos'

for i in $(seq 2 2 20)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./fattree_$j/$TEST/all/$i
    sleep 5
done


TEST='slice_isolation'

for i in $(seq 2 2 22)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./fattree_$j/$TEST/all/$i
    sleep 5
done
COMMENT1
done

