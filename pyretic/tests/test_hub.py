#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController
import os, shlex, subprocess, utils
from utils import init


### Module Parameters

def get_controller():
    return 'pyretic.modules.hub'

def run_mininet():
    # mn = Mininet()
    # mn.autoSetMacs = True
    # s1 = mn.addSwitch('s1')
    # h1 = mn.addHost('h1')
    # h2 = mn.addHost('h2')
    # h3 = mn.addHost('h3')
    # h4 = mn.addHost('h4')
    # mn.addLink(h1, s1)
    # mn.addLink(h2, s1)
    # mn.addLink(h3, s1)
    # mn.addLink(h4, s1)
    # mn.addController('c0', RemoteController)
    # mn.run(mn.pingAll)

    # Alternately, run mininet via the command line.  Note that we need to use
    # absolute path names because sudo mucks with the env.

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

test_hub = utils.TestModule( __name__, __file__, get_controller, run_mininet, process_controller_output, process_mininet_output)

def test_hub_i(init):
    utils.run_test(test_hub, init.test_dir, init.benchmark_dir, '-m i')
def test_hub_r0(init):
    utils.run_test(test_hub, init.test_dir, init.benchmark_dir, '-m r0')
def test_hub_p0(init):
    utils.run_test(test_hub, init.test_dir, init.benchmark_dir, '-m p0')
# def test_hub_p0_nx(init):
#     utils.run_test(test_hub, init.test_dir, init.benchmark_dir, '-m p0 --nx')

### Executing this file starts the mininet instance for this test.

if __name__ == "__main__":
    run_mininet()
