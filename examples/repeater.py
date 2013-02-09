
from frenetic.lib import *

repeater =  match(inport=1)[fwd(2)] | match(inport=2)[fwd(1)]

def main():
    return repeater
