#!/usr/bin/python

from utils import (TestCase, main)
from mininet.net import Mininet
from mininet.node import RemoteController
import os, time

def get_controller():
    return 'pyretic.modules.mac_learner'

def run_mininet():
    mn = Mininet()
    s1 = mn.addSwitch('s1')
    s2 = mn.addSwitch('s2')
    s3 = mn.addSwitch('s3')
    h1 = mn.addHost('h1')
    h2 = mn.addHost('h2')
    h3 = mn.addHost('h3')
    mn.addLink(s1, s2)
    mn.addLink(s1, s3)
    mn.addLink(s2, s3)
    mn.addLink(h1, s1)
    mn.addLink(h2, s2)
    mn.addLink(h3, s3)
    mn.addController('c0', RemoteController)
    time.sleep(1)
    mn.run(mn.pingAll)

    # Alternately, run mininet via the command line.  Note that we need to use
    # absolute path names because sudo mucks with the env.

    # mn = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../mininet.sh'))
    # cmd = '%s --topo clique,4,4' % mn
    # subprocess.call(shlex.split(cmd))

def filter_mininet(line):
    return line

def filter_controller(line):
    if line.find('TEST') >= 0:
        return line
    else:
        return ''

if __name__ == "__main__":
    # Run the common main function from utils.py.
    main(run_mininet)
