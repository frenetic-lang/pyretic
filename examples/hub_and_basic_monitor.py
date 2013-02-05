

from frenetic.lib import *

from examples.hub import hub
from examples.basic_monitor import monitor_packets

main = hub | monitor_packets()
    

