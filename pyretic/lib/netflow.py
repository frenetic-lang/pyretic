from pyretic.core.language import *
from pyretic.core import util
from pyretic.lib.query import Query
import subprocess, shlex, threading, sys, logging, time

NFCAPD_PORT = 12345
SFCAPD_PORT = 12346
NFCAPD_INTERVAL = 10 # period before producing a new output file
SCRATCH_DATA_FOLDER = "pyretic/scratch/"
PROCESS_SCRIPT = "pyretic/lib/helpers/process_netflow.sh"
DORMANT_SHELL = "pyretic/lib/helpers/dormant_shell.sh"
NETFLOW_OUTFILE = "pyretic/scratch/latest-dump.txt"

class NetflowBucket(Query):
    """
    Collect aggregated statistics from streams of Netflow records from
    network switches.
    """
    nfcapd_proc  = None
    sfcapd_proc  = None
    cls_counter  = 0
    callbacks = []

    def __init__(self, capd="netflow"):
        self.log = logging.getLogger('%s.NetflowBucket' % __name__)
        self.log.setLevel(logging.WARNING)
        assert capd in ["netflow", "sflow"]
        proc = "nfcapd" if capd == "netflow" else "sfcapd"
        self.start_fcapd(proc)
        super(NetflowBucket, self).__init__()
        t = threading.Thread(target=self.nf_callback, args=(self.handle_nf, 'test', True))
        t.daemon = True
        t.start()

    def fcapd_running(self, daemon_proc):
        p = subprocess.Popen("ps ax | grep %s | grep -v grep | wc -l" %
                             daemon_proc,
                             shell=True, stdout=subprocess.PIPE)
        lines = p.stdout.read()
        p.stdout.close()
        p.wait()
        lines = int(lines.strip())
        if lines > 0:
            return True
        else:
            return False

    def nfcapd_running(self):
        self.fcapd_running("nfcapd")

    def sfcapd_running(self):
        self.fcapd_running("sfcapd")

    def start_fcapd(self, daemon_proc):
        cls = self.__class__
        daemon_port = NFCAPD_PORT if daemon_proc == "nfcapd" else SFCAPD_PORT
        if not self.fcapd_running(daemon_proc):
            fcapd_cmd  = "%s -T all -p %d -l %s -t %d -x 'bash %s %%d%%f'" % (
                daemon_proc, daemon_port, SCRATCH_DATA_FOLDER, NFCAPD_INTERVAL,
                PROCESS_SCRIPT)
            if daemon_proc == "nfcapd":
                cls.nfcapd_proc = subprocess.Popen(fcapd_cmd, shell=True)
                self.log.info("Started new nfcapd daemon")
            else:
                cls.sfcapd_proc = subprocess.Popen(fcapd_cmd, shell=True)
                self.log.info("Started new sfcapd daemon")
        else:
            self.log.info("*fcapd daemon already running")

    def start_nfcapd(self):
        self.start_fcapd("nfcapd")

    def start_sfcapd(self):
        self.start_fcapd("sfcapd")

    def kill_fcapd(self, daemon_proc):
        cls = self.__class__
        assert daemon_proc in ["nfcapd", "sfcapd"]
        proc = cls.nfcapd_proc if daemon_proc == "nfcapd" else cls.sfcapd_proc
        if proc:
            proc.terminate()
            self.log.info("Terminated process")
            if daemon_proc == "nfcapd":
                cls.nfcapd_proc = None
            else:
                cls.sfcapd_proc = None

    def kill_nfcapd(self):
        self.kill_fcapd(self, "nfcapd")

    def kill_sfcapd(self):
        self.kill_fcapd(self, "sfcapd")

    def nf_callback(self, f, f_args, loop=False):
        p = subprocess.Popen(shlex.split('bash %s' % DORMANT_SHELL))
        self.log.info("Started dormant bash process")
        p.wait()
        """ when thread execution reaches here, the dormant shell process has
        been killed by nfcapd as it just produced a new file. We call the test
        callback function with its arguments. """
        f(f_args)
        """ If "loop" is True, we start a new Thread which will do the same
        thing that this function did. """
        if loop:
            self.log.debug("restarting a new thread for nf_callback")
            t = threading.Thread(target=self.nf_callback,
                                 args=(f, f_args, True))
            t.daemon = True
            t.start()
        return

    def process_results(self, fname):
        """ TODO(ngsrinivas): do some basic processing of the netflow results. """
        f = open(fname, 'r')
        res = f.read()
        f.close()
        return res

    def handle_nf(self, nf_args):
        """ A callback function which gets invoked whenever nfcapd produces an
        output file. nf_args is disregarded for now. """
        cls = self.__class__
        cls.cls_counter += 1
        self.log.debug("Calling handle_nf %d'th time" % cls.cls_counter)
        res = self.process_results(NETFLOW_OUTFILE)
        for f in cls.callbacks:
            f(res)

    def register_callback(self, fn):
        cls = self.__class__
        cls.callbacks.append(fn)

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

