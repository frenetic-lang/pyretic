################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Nick Feamster (feamster@cc.gatech.edu)                               #
# author: Joshua Reich  (jreich@cs.princeton.edu)                              #
################################################################################

from pox.lib.addresses import EthAddr

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner

class local_circuit_breaker(LocalDynamicPolicy):

    # tickers is a dictionary of tickers to prices, eg. SPY : 100.
    def __init__(self, safezone_port, output_port, tickers):
        # Initialize
        self.safezone_port = safezone_port
        self.firewall = {}
        self.query = match('inport' = safezone_port) >> FwdBucket()
        self.query.register_callback(self.monitor)
        super(local_circuit_breaker,self).__init__(self.query)

    def monitor(self, pkt):
        # TODO: need a way to extract payload
        payload = parse_payload(pkt)
        ticker_price = self.tickers[payload['ticker']]
        if abs(payload['price'] - ticker_price) < ticker_price / 2:
            # drop packet
            pass
        else:
            # TODO: need a way to inject packets
            pkt['outport'] = output_port
            inject(pkt)


def main ():
    # NOTE: we assume the topology is SAFE ZONE --- 1 SWITCH 2 --- INTERNET
    return local_circuit_breaker(1,2,{'SPY' : 100})
