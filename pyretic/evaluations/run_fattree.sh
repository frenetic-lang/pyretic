TEST='traffic_matrix'

sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -d -l -u -i -c -t $TEST -f ./stanford/tm_5_2/
sleep 10
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -d -l -u -i -t $TEST -f ./stanford/tm_4/
sleep 10
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -d -l -u -t $TEST -f ./stanford/tm_3/
sleep 10
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -d -l -t $TEST  -f ./stanford/tm_2/
sleep 10
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -d -t $TEST -f ./stanford/tm_1/
sleep 10
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -l -t $TEST -f ./stanford/tm_1_default/
sleep 10
sudo /opt/pypy-2.4.0/bin/pypy eval_compilation.py -r -u -t $TEST -f ./stanford/tm_0/

