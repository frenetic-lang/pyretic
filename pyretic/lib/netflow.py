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
import subprocess, shlex, threading, sys, logging, time, copy
from multiprocessing import Lock, Condition

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
    cls_shells   = 0
    callbacks = []
    shell = None # dormant shell process
    active_buckets = {}
    intfs_map = {}
    intfs_map_lock = Lock()

    def __init__(self, cap_type="sflow", start_fcapd=True):
        self.log = logging.getLogger('%s.NetflowBucket' % __name__)
        self.log.setLevel(logging.WARNING)
        self.runtime_sw_cnt_fun = None
        self.runtime_sw_port_ids_fun = None
        self.preproc_pol = {}
        assert cap_type in ["netflow", "sflow"]
        self.cap_type = cap_type
        super(NetflowBucket, self).__init__()
        cls = self.__class__
        if start_fcapd:
            capd_started = self.start_fcapd()
            if capd_started or cls.shell is None:
                ''' Every new capd instance must go with a dormant shell. Also
                start a new dormant child if there isn't already one. '''
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

    def set_sw_port_ids_fun(self, fun):
        self.runtime_sw_port_ids_fun = fun

    def set_preproc_pol(self, pol, table_id):
        """ The sflow records provided by switches correspond to how the packets
        looked at their ingress port into the device. To support compositional
        processing with Netflow buckets with multi-stage tables, it is necessary
        to evaluate packets by the sequential composition of the policies of all
        *prior* tables in the pipeline.
        """
        self.preproc_pol[table_id] = pol

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
        return fun_dict[self.cap_type]()

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
            return True
        else:
            self.log.info("*fcapd daemon already running")
            return False

    def start_nfcapd(self):
        return self.__start_fcapd("nfcapd", NFCAPD_PORT)

    def start_sfcapd(self):
        return self.__start_fcapd("sfcapd", SFCAPD_PORT)

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

    @classmethod
    def set_active_buckets(cls, blist, tab):
        cls.active_buckets[tab] = blist

    def nf_callback(self, f, f_args, loop=False):
        cls = self.__class__
        cls.cls_shells += 1
        cls.shell = subprocess.Popen(shlex.split('bash %s' % DORMANT_SHELL))
        self.log.info("Started dormant bash process")
        cls.shell.wait()
        """ when thread execution reaches here, the dormant shell process has
        been killed by nfcapd as it just produced a new file. We call the test
        callback function with its arguments. """
        cls.shell = None
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
        cls = self.__class__
        def convert(h,val):
            if h in ['srcmac','dstmac']:
                return MAC(val)
            elif h in ['srcip','dstip']:
                try:
                    return IP(val)
                except: # IPv6 packets are not processed well in the IP class
                    return val
            elif h in ['packets', 'bytes', 'flows', 'port', 'vlan_id',
                       'srcport', 'dstport']:
                return int(float(val))
            elif h in ['protocol']:
                return int(val)
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
            '''
            TODO(): There doesn't seem to be a way to figure out the ethertype
            of a packet from nfdump. The manpage doesn't give any hints, and it
            is documented that this was an issue as recently as 2014: see
            http://sourceforge.net/p/nfdump/mailman/message/33085997/ So we just
            set it automatically to IP.
            '''
            headers['ethtype'] = 2048
            return headers

        def adjust_location(headers):
            imap = cls.intfs_map
            if headers['port'] in cls.intfs_map:
                (sw, port, _) = cls.intfs_map[headers['port']]
                headers.update({'switch': sw, 'port': port})
            return headers

        def process_vlan(headers):
            '''The returned VLAN label from nfdump tools is actually a 2 byte
            combination of the VLAN id (12 bits), a CFI bit, and the VLAN
            priority (3 bits) which are arranged in that order from least
            to most significant bits (see [1-4] below).

            Given that netflow/IPFIX export this information, and that nfcapd
            output format remains consistent across netflow and sflow, I believe
            that sflow captures should be no different. @ngsrinivas

            [1] ipfix RFC. http://tools.ietf.org/html/rfc5102#section-5.6.3
            [2] Table 6, netflow V9 record format.
                http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
            [3] VLAN tag frame format https://wiki.wireshark.org/VLAN
            [4] libnfread: read netflow records from nfcapd output files.
                https://github.com/switch-ch/nfdump-libnfread/blob/master/bin/pcaproc.c#L416
                (see https://github.com/switch-ch/nfdump-libnfread)

            '''
            if 'vlan_id' in headers:
                tag = headers['vlan_id']
                headers.update({'vlan_id': tag & 0xfff,
                                'vlan_pcp': ((tag & 0xf000) >> 13) & 7,
                                'vlan_cfi': ((tag & 0xf000) >> 12) & 1})
            return headers

        h1 = parse_line(nf_line.strip())
        h2 = { h : convert(h,v) for (h,v) in h1.items() }
        h3 = adjust_location(h2)
        h4 = process_vlan(h3)
        h4['raw'] = 'junk'
        pyretic_pkt = Packet(util.frozendict())
        return pyretic_pkt.modifymany(h4)

    def process_results(self, fname):
        f = open(fname, 'r')
        res = []
        with self.__class__.intfs_map_lock:
            for line in f:
                res.append(self.nf_to_pyretic(line))
        f.close()
        return res

    def filter_pkts(self, pkts_list, table_id):
        filtered_pkts = []
        with self.in_update_cv:
            while self.in_update:
                self.in_update_cv.wait()
            for pkt in pkts_list:
                for entry in self.matches[table_id].keys():
                    mat = match(entry.match)
                    if len(mat.eval(pkt)) > 0:
                        filtered_pkts.append(pkt)
                        break
        return filtered_pkts

    def preproc_pkts(self, pkts_list, table_id):
        preprocd_pkts = set()
        with self.in_update_cv:
            while self.in_update:
                self.in_update_cv.wait()
            for pkt in pkts_list:
                preprocd_pkts |= self.preproc_pol[table_id].eval(pkt)
        return list(preprocd_pkts)

    def bucket_specific_cb(self, pkts_list):
        """Filter out results from packets don't match the stored matches for this
        bucket, and then call the bucket's callbacks.
        """
        assert set(self.preproc_pol.keys()) == set(self.matches.keys())
        result_pkts = []
        for table in self.preproc_pol.keys():
            preprocd_pkts = self.preproc_pkts(pkts_list, table)
            filtered_pkts = self.filter_pkts(preprocd_pkts, table)
            result_pkts += filtered_pkts
        ''' Call application callbacks on results. '''
        for f in self.callbacks:
            f(result_pkts)


    def handle_nf(self, nf_args):
        """ A callback function which gets invoked whenever nfcapd produces an
        output file. nf_args is disregarded for now. """
        cls = self.__class__
        cls.cls_counter += 1
        self.log.debug("Calling handle_nf %d'th time" % cls.cls_counter)
        pkts_list = self.process_results(NETFLOW_OUTFILE)
        map(lambda x: x.bucket_specific_cb(pkts_list),
            reduce(lambda acc, z: acc + z, cls.active_buckets.values(), []))

    def register_callback(self, fn):
        self.callbacks.append(fn)

    def __repr__(self):
        return "NetflowBucket %d" % id(self)

    def __eq__(self, other):
        return isinstance(other, NetflowBucket)

    def start_update(self, table_id):
        """This function sets a condition variable to note that the set of matches in
        the bucket is under update. We use a condition variable instead of locks
        for reasons described in the comment under `start_update` in the
        `CountBucket` class.
        """
        with self.in_update_cv:
            self.in_update = True
            self.runtime_switch_cnt_fun = None
            self.runtime_sw_port_ids_fun = None
            self.preproc_pol[table_id] = identity

    def finish_update(self):
        with self.in_update_cv:
            self.in_update = False
            self.in_update_cv.notify_all()

    def add_match(self, mat, prio, ver, table_id):
        ''' Add a match of packets going to the NetflowBucket into
        self.matches. '''
        new_mat = copy.copy(mat)
        # remove 'table_id' key from match, because packets from netflow won't
        # have this information to match, i.e., they are all from table 0 by
        # design.
        new_mat.pop('table_id', None)
        me = self.match_entry(new_mat, prio, ver)
        if not table_id in self.matches:
            self.matches[table_id] = {}
        self.matches[table_id][me] = self.match_status()

    def clear_matches(self, table_id):
        """ Delete all matches. Should always be called in the context of
        holding the in_update_cv for this bucket. """
        self.matches[table_id] = {}

    def get_runtime_info(self, fun, fun_text):
        try:
            val = fun()
        except TypeError:
            self.log.error("Netflow's %s not initialized" % fun_text)
            raise RuntimeError("Couldn't configure switches!")
        return val

    def issue_ovs_cmd(self, cmd):
        try:
            out = subprocess.check_output(cmd, shell=True)
        except OSError:
            self.log.error("Error in calling ovs-vsctl!")
            raise RuntimeError("Couldn't find ovs-vsctl to configure switches!")
        except subprocess.CalledProcessError:
            self.log.error("Error while calling ovs-vsctl")
            raise RuntimeError("Switch configuration did not succeed")
        return out

    def update_intf_numbers(self):
        """ Maintain most current map of OVS `ifindex` value and the switch
        interface as represented within mininet, i.e., of the form s<i>-eth<j>.
        """
        sw_ports = self.get_runtime_info(self.runtime_sw_port_ids_fun,
                                         "runtime switch port ids")
        ovs_intfs = []
        cls = self.__class__
        for (sw, ports_list) in sw_ports:
            for port in ports_list:
                ovs_intfs.append((sw, port, 's%d-eth%d' % (sw, port)))
        with cls.intfs_map_lock:
            self.intfs_map = {}
            for (sw, port, mn_intf) in ovs_intfs:
                cmd = "sudo ovs-vsctl list interface %s | grep ifindex \
                       | awk '{print $3}'" % mn_intf
                intf_index = int(self.issue_ovs_cmd(cmd).strip())
                cls.intfs_map[intf_index] = (sw, port, mn_intf)

    def config_ovs_flow(self):
        """Wrapper that configures ovs to send samples to a specific collector daemon
        depending on whether this is a netflow or sflow bucket instance.
        """
        self.update_intf_numbers()
        fun_dict = {"netflow": self.config_ovs_netflow,
                    "sflow"  : self.config_ovs_sflow}
        fun_dict[self.cap_type]()

    def __config_ovs_flow(self, config_id, config_type, str_params,
                          target_port):
        sw_cnt = self.get_runtime_info(self.runtime_sw_cnt_fun,
                                       "runtime switch count")
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

