#!/usr/bin/python

from utils import (TestCase, main)
from mininet.net import Mininet
from mininet.node import RemoteController
import os

def get_controller():
    return 'pyretic.modules.hub'

def run_mininet():
    mn = Mininet()
    s1 = mn.addSwitch('s1')
    h1 = mn.addHost('h1')
    h2 = mn.addHost('h2')
    mn.addLink(h1, s1)
    mn.addLink(h2, s1)
    mn.addController('c0', RemoteController)
    mn.run(mn.pingAll)

    # Alternately, run mininet via the command line.  Note that we need to use
    # absolute path names because sudo mucks with the env.

    # mn = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../mininet.sh'))
    # cmd = '%s --topo clique,4,4' % mn
    # subprocess.call(shlex.split(cmd))

if __name__ == "__main__":
    # Run the common main function from utils.py.
    main(run_mininet)
