#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController
import os, shlex, subprocess, utils, time
from utils import init


### Module Parameters

def get_controller():
    return 'pyretic.modules.arp'

def run_mininet():
    mn = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../mininet.sh'))
    cmd = '%s --topo cycle,3,4 --mac --test=pingall' % mn
    subprocess.call(shlex.split(cmd))

def process_controller_output(oldf, newf):
    lines = oldf.readlines()
    lines.sort()
    keywords = ['TEST', 'ERROR', 'error']
    ## filter out lines that do not contain one of the keywords
    for line in lines:
        for kw in keywords:
            if line.find(kw) >= 0:
                newf.write(line)

def process_mininet_output(oldf, newf):
    lines = oldf.readlines()
    lines.sort()
    keywords = ['TEST', 'ERROR', 'error', 'received']
    ## filter out lines that do not contain one of the keywords
    for line in lines:
        for kw in keywords:
            if line.find(kw) >= 0:
                newf.write(line)


### Tests

test_arp = utils.TestModule( __name__, __file__, get_controller, run_mininet, process_controller_output, process_mininet_output)

def test_arp_i(init):
    utils.run_test(test_arp, init.test_dir, init.benchmark_dir, '-m i')
def test_arp_r0(init):
    utils.run_test(test_arp, init.test_dir, init.benchmark_dir, '-m r0')
def test_arp_p0(init):
    utils.run_test(test_arp, init.test_dir, init.benchmark_dir, '-m p0')
# def test_arp_p0_nx(init):
#     utils.run_test(test_arp, init.test_dir, init.benchmark_dir, '-m p0 --nx')

### Executing this file starts the mininet instance for this test.

if __name__ == "__main__":
    run_mininet()
