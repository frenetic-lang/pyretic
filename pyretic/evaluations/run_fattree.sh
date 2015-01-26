#declare -a OPT_FLAGS_ARR=("-d -l -i -s 16 -c -g" "-d -l -i -s 16 -c" "-d -l -i -s 16" "-d -l -i" "-d -l" "-d" " ")
OPT_FLAGS="-d -l -i -c -g"

TEST='congested_link'

for i in $(seq 2 2 20)
do
    echo "Start Time"
    date
    SW_CNT=$((5 * $i * $i / 4))
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -s $SW_CNT $OPT_FLAGS -t $TEST -polargs k $i fout 2 -f ./fattree/$TEST/all/$i
    sleep 10
done


