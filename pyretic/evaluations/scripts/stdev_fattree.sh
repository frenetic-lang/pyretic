#declare -a OPT_FLAGS_ARR=("-d -l -i -s 16 -c -g" "-d -l -i -s 16 -c" "-d -l -i -s 16" "-d -l -i" "-d -l" "-d" " ")
OPT_FLAGS="-d -l -i -c -g"

for j in $(seq 1 1 50)
do

TEST='path_packet_loss'

for i in $(seq 2 2 2)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./stdev_fattree/pl/$j
done

TEST='traffic_matrix'

for i in $(seq 2 2 2)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./stdev_fattree/tm/$j
done


TEST='ddos'

for i in $(seq 2 2 2)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    FOUT=$(($i/2))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout $FOUT -f ./stdev_fattree/dd/$j
done


done

