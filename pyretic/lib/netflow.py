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
from pyretic.core.packet import Packet
from pyretic.core.network import IP, MAC
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
        self.cap_type = cap_type
        if start_fcapd:
            self.start_fcapd()
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

    def fcapd_running(self):
        """ Wrapper that detects whether the capture daemon is running
        independent of collector type. """
        fun_dict = {"netflow": self.nfcapd_running,
                    "sflow"  : self.sfcapd_running}
        return fun_dict[self.cap_type]()

    def _fcapd_running(self, daemon_proc):
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
        return self._fcapd_running("nfcapd")

    def sfcapd_running(self):
        return self._fcapd_running("sfcapd")

    def start_fcapd(self):
        """Wrapper that starts the capture daemon corresponds to the capture type
        (i.e. netflow vs sflow) of this bucket instance.
        """
        fun_dict = {"netflow": self.start_nfcapd,
                    "sflow"  : self.start_sfcapd}
        fun_dict[self.cap_type]()

    def __start_fcapd(self, daemon_proc, daemon_port):
        cls = self.__class__
        if not self.fcapd_running():
            fcapd_cmd  = "%s -T all -p %d -l %s -t %d -x 'bash %s %%d%%f'" % (
                daemon_proc, daemon_port, SCRATCH_DATA_FOLDER, NFCAPD_INTERVAL,
                PROCESS_SCRIPT)
            if daemon_proc == "nfcapd":
                cls.nfcapd_proc = subprocess.Popen(fcapd_cmd, shell=True,
                                                   stderr=subprocess.PIPE)
                self.log.info("Started new nfcapd daemon")
            else:
                cls.sfcapd_proc = subprocess.Popen(fcapd_cmd, shell=True,
                                                   stderr=subprocess.PIPE)
                self.log.info("Started new sfcapd daemon")
        else:
            self.log.info("*fcapd daemon already running")

    def start_nfcapd(self):
        self.__start_fcapd("nfcapd", NFCAPD_PORT)

    def start_sfcapd(self):
        self.__start_fcapd("sfcapd", SFCAPD_PORT)

    def kill_fcapd(self):
        """ Wrapper that kills the currently executing netflow/sflow collector
        daemon. """
        fun_dict = {"netflow": self.kill_nfcapd,
                    "sflow"  : self.kill_sfcapd}
        fun_dict[self.cap_type]()

    def __kill_fcapd(self, daemon_proc):
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
        self.__kill_fcapd("nfcapd")

    def kill_sfcapd(self):
        self.__kill_fcapd("sfcapd")

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

    def nf_to_pyretic(self, nf_line):
        """ Parse one line of netflow/sflow output and return a pyretic
        `Packet`-like structure for evaluation by pyretic policies.
        """
        def convert(h,val):
            if h in ['srcmac','dstmac']:
                return MAC(val)
            elif h in ['srcip','dstip']:
                return IP(val)
            elif h in ['packets', 'bytes', 'flows', 'port', 'vlan_id',
                       'srcport', 'dstport']:
                return int(float(val))
            elif h in ['protocol']:
                if val == 'ICMP':
                    return 2048
                else:
                    return val
            elif h in ['bps', 'Bpp']:
                return float(val)
            else:
                return val

        def parse_line(l):
            parts = l.split()[3:]
            order = ['switch', 'protocol', 'srcip', 'dstip', 'srcport',
                     'dstport', 'vlan_id', 'srcmac', 'dstmac', 'port',
                     'packets','bytes', 'bps', 'Bpp', 'flows']
            headers = {}
            for i in range(0, len(order)):
                headers[order[i]] = parts[i]
            return headers

        headers = parse_line(nf_line.strip())
        headers['raw'] = 'junk'
        pyretic_pkt = Packet(util.frozendict())
        d = { h : convert(h,v) for (h,v) in headers.items() }
        return pyretic_pkt.modifymany(d)

    def process_results(self, fname):
        f = open(fname, 'r')
        res = []
        for line in f:
            res.append(self.nf_to_pyretic(line))
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

    def get_sw_cnt(self):
        try:
            sw_cnt = self.runtime_sw_cnt_fun()
        except TypeError:
            self.log.error("Netflow's runtime_sw_cnt_fun not initialized")
            raise RuntimeError("Couldn't configure switches!")
        return sw_cnt

    def issue_ovs_cmd(self, cmd):
        try:
            out = subprocess.check_output(cmd, shell=True)
        except OSError:
            self.log.error("Error in calling ovs-vsctl!")
            raise RuntimeError("Couldn't find ovs-vsctl to configure switches!")
        except subprocess.CalledProcessError:
            self.log.error("Error while calling ovs-vsctl")
            raise RuntimeError("Switch configuration did not succeed")

    def config_ovs_flow(self):
        """Wrapper that configures ovs to send samples to a specific collector daemon
        depending on whether this is a netflow or sflow bucket instance.
        """
        fun_dict = {"netflow": self.config_ovs_netflow,
                    "sflow"  : self.config_ovs_sflow}
        fun_dict[self.cap_type]()

    def __config_ovs_flow(self, config_id, config_type, str_params,
                          target_port):
        sw_cnt = self.get_sw_cnt()
        cmd = 'sudo ovs-vsctl -- --id=@%s create %s \
               targets=\\"127.0.0.1:%d\\" %s ' % (config_id, config_type,
                                                  target_port, str_params)
        for s in range(1, sw_cnt+1):
            cmd += "-- set bridge s%d %s=@%s " % (s, config_type, config_id)
        self.log.info("Running switch configuration command %s" % cmd)
        self.issue_ovs_cmd(cmd)

    def config_ovs_netflow(self):
        self.__config_ovs_flow("nf", "netflow", "active_timeout=20",
                               NFCAPD_PORT)

    def config_ovs_sflow(self):
        self.__config_ovs_flow("sf", "sflow", "sampling=2 polling=10",
                               SFCAPD_PORT)

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

