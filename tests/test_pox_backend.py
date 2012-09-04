
import pytest

from pox.openflow.libopenflow_01 import *

from frenetic.net import *
from frenetic.netcore_helpers import *
from frenetic.pox_backend import *

act = mod(outport=10)

def test_compile_action():
  assert compile_action(drop) == []
  assert compile_action(act) == [ofp_action_output(port=10)]

def test_compile_bad_actions():
  with pytest.raises(Exception):
    compile_action(mod(blah=30, outport=10)) # fake header
  with pytest.raises(Exception):
    compile_action(mod(srcip="1.2.3.5")) # mod without outport
  with pytest.raises(Exception):
    compile_action(mod(srcip="1.2.3.5", outport=10) +
                   mod(dstport=12, outport=10)) # action without subset relationship
    
