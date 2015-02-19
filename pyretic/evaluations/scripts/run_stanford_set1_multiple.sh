declare -a OPT_FLAGS_ARR=("-d -l -i -c 16" "-d -l -i" "-d" "-d -l" " ")

for num in {11..20} 
do
:<<COMMENT1

TEST='traffic_matrix_stanford'

i=2
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford/traffic_matrix/tm_$i/
    i=$((i - DCR ))
    sleep 10
done
COMMENT1

TEST='path_loss_stanford'

i=6
DCR=1

mkdir ./stanford/path_loss_$num
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford/path_loss_$num/pl_$i/
    i=$((i - DCR ))
    sleep 10
done



TEST='firewall_stanford'

i=6
DCR=1

mkdir ./stanford/firewall_$num
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford/firewall_$num/fl_$i/
    i=$((i - DCR ))
    sleep 10
done

:<<COMMENT3
TEST='ddos_stanford'

i=6
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford/ddos/dd_$i/
    i=$((i - DCR ))
    sleep 10
done

COMMENT3

TEST='slice_stanford'

i=6
DCR=1
mkdir ./stanford/slice_2_$num
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford/slice_2_$num/sl_$i/
    i=$((i - DCR ))
    sleep 10
done

:<<COMMENT2
TEST='congested_stanford'

i=6
DCR=1
for OPT_FLAGS in "${OPT_FLAGS_ARR[@]}"
do
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u $OPT_FLAGS -t $TEST -f ./stanford/congested_link/cl_$i/
    i=$((i - DCR ))
    sleep 10
done

COMMENT2
done
