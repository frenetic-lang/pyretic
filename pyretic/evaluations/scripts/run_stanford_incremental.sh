i=13

mkdir stanford_incremental/set$i
mkdir stanford_incremental/set$i/inc
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -i -d -l -s 16 -c -g -t traffic_matrix_stanford -a path_loss_stanford congested_stanford firewall_stanford slice_stanford ddos_stanford -f stanford_incremental/set$i/inc/

i=$(($i + 1))
mkdir stanford_incremental/set$i
mkdir stanford_incremental/set$i/inc
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -i -d -l -s 16 -c -g -t traffic_matrix_stanford -a path_loss_stanford congested_stanford slice_stanford firewall_stanford ddos_stanford -f stanford_incremental/set$i/inc/

i=$(($i + 1))
mkdir stanford_incremental/set$i
mkdir stanford_incremental/set$i/inc
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -i -d -l -s 16 -c -g -t traffic_matrix_stanford -a slice_stanford path_loss_stanford congested_stanford firewall_stanford ddos_stanford -f stanford_incremental/set$i/inc/


