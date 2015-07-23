################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################

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

class NetflowBucket(MatchingAggregateBucket):
    """
    Collect aggregated statistics from streams of Netflow records from
    network switches.
    """
    nfcapd_proc  = None
    sfcapd_proc  = None
    cls_counter  = 0
    callbacks = []

    def __init__(self, cap_type="netflow", start_fcapd=True):
        self.log = logging.getLogger('%s.NetflowBucket' % __name__)
        self.log.setLevel(logging.WARNING)
        self.runtime_sw_cnt_fun = None
        assert cap_type in ["netflow", "sflow"]
        proc = "nfcapd" if cap_type == "netflow" else "sfcapd"
        if start_fcapd:
            self.start_fcapd(proc)
        super(NetflowBucket, self).__init__()
        t = threading.Thread(target=self.nf_callback, args=(self.handle_nf, 'test', True))
        t.daemon = True
        t.start()
        self._classifier = self.generate_classifier()

    def generate_classifier(self):
        return Classifier([Rule(identity, {self}, [self])])

    def apply(self):
        with self.bucket_lock:
            for pkt in self.bucket:
                self.log.info("In NetflowBucket apply(): packet is:\n"
                              + str(pkt))
                self.log.info("NetflowBucket has no eval action.")
            self.bucket.clear()

    def set_sw_cnt_fun(self, fun):
        self.runtime_sw_cnt_fun = fun

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
        """ TODO(ngsrinivas): only call callbacks on results which match the
        packets specified in self.matches """
        for f in cls.callbacks:
            f(res)

    def register_callback(self, fn):
        cls = self.__class__
        cls.callbacks.append(fn)

    def __repr__(self):
        return "NetflowBucket %d" % id(self)

    def __eq__(self, other):
        return isinstance(other, NetflowBucket)

    def start_update(self):
        """This function sets a condition variable to note that the set of matches in
        the bucket is under update. We use a condition variable instead of locks
        for reasons described in the comment under `start_update` in the
        `CountBucket` class.
        """
        with self.in_update_cv:
            self.in_update = True
            self.runtime_switch_cnt_fun = None

    def finish_update(self):
        with self.in_update_cv:
            self.in_update = False
            self.in_update_cv.notify_all()

    def clear_matches(self):
        """ Delete all matches. Should always be called in the context of
        holding the in_update_cv for this bucket. """
        self.matches = {}

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

