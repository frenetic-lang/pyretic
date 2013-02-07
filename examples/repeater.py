
from frenetic.lib import *


repeater = main = match(inport=1)[fwd(2)] | match(inport=2)[fwd(1)]
