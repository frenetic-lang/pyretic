from pyretic.core.language import *
from pyretic.core import util

# assuming that we're in the general base case
# TODO add lpm
def innerEval(filt,pkt):
    if filt is drop:
        return set()
    elif filt is identity:
        return pkt
    else:
        for field, pattern in filt.map.iteritems():
            try:
                if not field in ['srcip', 'dstip']:
                    v = pkt["header"][field]
                    if pattern is None or v != pattern:
                        return set()
                else:
                    v = util.string_to_IP(pkt['header'][field])
                    if pattern is None or v != pattern:
                        return set()
            except Exception, e:
                print e
                if pattern is not None:
                    return set()
        return pkt

def myEval(filt,pkt):
    if isinstance (filt,intersection):
        check = True
        for innerMatch in filt.policies:
            check = check and myEval(innerMatch,pkt)
        return pkt if check else set()
    elif isinstance (filt, union):
        check = False
        for innerMatch in filt.policies:
            check = check or myEval(innerMatch,pkt)
        return pkt if check else set()
    elif isinstance (filt, negate):
        innerMatch = filt.policies[0]
        return set() if myEval(innerMatch,pkt) else pkt
    else:
        return innerEval(filt,pkt)

