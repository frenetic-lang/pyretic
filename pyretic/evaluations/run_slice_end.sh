for i in $(seq 3 1 5)
do
    mkdir stanford_incremental_stats/set$i
    mkdir stanford_incremental_stats/set$i/inc/
    sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -d -l -i -s 16 -c -g -t traffic_matrix_stanford -a path_loss_stanford congested_stanford firewall_stanford ddos_stanford slice_stanford -f stanford_incremental_stats/set$i/inc/

    sleep 10

done


