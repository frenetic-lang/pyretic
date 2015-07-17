from pyretic.core.language import *
from pyretic.core import util
from pyretic.lib.query import Query
import subprocess, shlex, threading, sys, logging, time

NFCAPD_PORT = 12345
SCRATCH_DATA_FOLDER = "pyretic/scratch/"
PROCESS_SCRIPT = "pyretic/lib/helpers/process_netflow.sh"

class NetflowBucket(Query):
    """
    Collect aggregated statistics from streams of Netflow records from
    network switches.
    """
    nfcapd_proc  = None

    def __init__(self):
        self.log = logging.getLogger('%s.NetflowBucket' % __name__)
        self.log.setLevel(logging.WARNING)
        self.start_nfcapd()
        super(NetflowBucket, self).__init__()

    def nfcapd_running(self):
        p = subprocess.Popen("ps ax | grep nfcapd | grep -v grep | wc -l",
                             shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.read()
        p.stdout.close()
        p.wait()
        lines = int(lines.strip())
        if lines > 0:
            return True
        else:
            return False

    def start_nfcapd(self):
        cls = self.__class__
        if not self.nfcapd_running():
            nfcapd_cmd  = "nfcapd -p %d -l %s -t 60 -x '%s %%d%%f'" % (
                NFCAPD_PORT, SCRATCH_DATA_FOLDER, PROCESS_SCRIPT)
            cls.nfcapd_proc = subprocess.Popen(shlex.split(nfcapd_cmd),
                                               stdout=subprocess.PIPE)
            self.log.info("Started new nfcapd daemon")
        else:
            self.log.info("nfcapd daemon already running")

    def kill_nfcapd(self):
        cls = self.__class__
        if cls.nfcapd_proc:
            cls.nfcapd_proc.terminate()
            self.log.info("Terminated process")
            cls.nfcapd_proc = None

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

