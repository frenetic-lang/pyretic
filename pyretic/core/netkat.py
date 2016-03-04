
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
# author: Mina Tahmasbi (arashloo@cs.princeton.edu)                            #
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

import sys
import logging
import httplib
from ipaddr import IPv4Network
from pyretic.core.network import *
import copy

NETKAT_PORT = 9000
NETKAT_DOM  = "/compile"
NETKAT_TIME_HDR = "x-compile-time"
TEMP_INPUT = "/tmp/temp.in.json"
TEMP_HEADERS = "/tmp/temp.headers.txt"
TEMP_OUTPUT = "/tmp/temp.out.json"
NETKAT_DEBUG_BUILD = False
VLAN_LENGTH=15 # length of vlan field in bits
VLAN_NONE_VALUE=0xfff
VLAN_PCP_NONE_VALUE=0x7

class netkat_backend(object):
    """
    Backend component to communicate with the NetKAT compiler server through
    HTTP. This module does not actually do any compilation; it just communicates
    the policy to the NetKAT HTTP compiler server and receives the classifier in
    response. (Note that the Pyretic policy compilation routines are in
    pyretic/core/classifier.py.)
    """
    @classmethod
    def log(cls):
        try:
            return cls.log_writer
        except AttributeError:
            cls.log_writer = logging.getLogger('%s.netkat' % __name__)
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            cls.log_writer.addHandler(handler)
            cls.log_writer.setLevel(logging.INFO)
            return cls.log_writer

    @classmethod
    def generate_classifier(cls, pol, switch_cnt, multistage, print_json=False,
                            return_json=False, server_port=NETKAT_PORT):
        """ Generate JSON or classifier output from compiling an input policy. """
        def use_explicit_switches(pol):
            """ Ensure every switch in the network gets reflected in the policy
            sent to netkat. This is because netkat generates a separate copy of
            the policy per switch, and it is necessary for it to know that a switch
            appears in the policy through the policy itself."""
            from pyretic.core.language import match, identity
            pred_policy = None
            used_cnt = switch_cnt if switch_cnt else 0
            for i in range(1, used_cnt + 1):
                if pred_policy is None:
                    pred_policy = match(switch = i)
                else:
                    pred_policy |= match(switch = i)
            if pred_policy is None:
                pred_policy = identity
            return pred_policy >> pol

        def curl_channel_compilation(pol):
            """ Communicate with the netKAT compile server through curl. """
            import subprocess

            f = open('/tmp/in.json', 'w')
            if print_json:
                cls.log().error("The policy being compiled to netkat is:")
                cls.log().error(str(pol))
            f.write(compile_to_netkat(pol))
            f.close()

            try:
                output = subprocess.check_output(['curl', '-X', 'POST',
                                                  'localhost:%d/compile' %
                                                  server_port, '--data-binary',
                                                  '@/tmp/in.json', '-D',
                                                  '/tmp/header.txt'])
                f = open('/tmp/out.json', 'w')
                f.write(output)
                f.close()
            except subprocess.CalledProcessError:
                print "error in calling frenetic"

            if print_json:
                cls.log().error("This is the json output:")
                cls.log().error(str(output))
            f = open('/tmp/header.txt')
            time = 0
            for line in f.readlines():
                if line.startswith('x-compile-time:'):
                    time = float(line[line.index(":") + 1:-1])
                    break

            return (output, time)

        def httplib_channel_compilation(pol):
            json_input = compile_to_netkat(pol)
            write_to_file(json_input, TEMP_INPUT)
            if print_json:
                cls.log().error("This is the JSON input:")
                cls.log().error(str(json_input))
            headers = {"Content-Type": "application/x-www-form-urlencoded",
                       "Accept": "*/*"}
            ctime = '0'
            try:
                # TODO: make the connection persist across compilations
                conn = httplib.HTTPConnection("localhost", server_port)
                conn.request("POST", NETKAT_DOM, json_input, headers)
                resp = conn.getresponse()
                ctime = resp.getheader(NETKAT_TIME_HDR, "-1")
                netkat_out = resp.read()
                write_to_file(ctime, TEMP_HEADERS)
                write_to_file(netkat_out, TEMP_OUTPUT)
                if print_json:
                    cls.log().error("This is the JSON output:")
                    cls.log().error(netkat_out)
                conn.close()
            except Exception as e:
                cls.log().error(("Compiling with the netkat compilation" +
                                 " server failed. (%s, port %d") % (
                                     str(e), server_port))
                sys.exit(0)
            return (netkat_out, ctime)

        pol = use_explicit_switches(pol)
        qdict = {str(id(b)) : b for b in get_buckets_list(pol)}
        vlan_offset_nbits = vlan_preprocess(pol)
        # return curl_channel_compilation(pol)
        (cls_json, ctime) = httplib_channel_compilation(pol)
        if not return_json:
            classifier = json_to_classifier(cls_json, qdict, multistage, vlan_offset_nbits)
            return (classifier, ctime)
        else:
            return (cls_json, ctime)

##################### Helper functions #################

import json

def write_to_file(val, fname):
    f = open(fname, 'w')
    f.write(val)
    f.close()

def mk_filter(pred):
  return { "type": "filter", "pred": pred }

def mk_test(hv):
  return { "type": "test", "header": hv["header"], "value": hv["value"] }

def mk_mod(hv):

  return { "type": "mod", "header": hv["header"], "value": hv["value"] }

def mk_header(h, v):
  return { "header": h, "value": v }

def to_int(bytes):
  n = 0
  for b in bytes:
    n = (n << 8) + ord(b)
  # print "Ethernet: %s -> %s" % (bytes, n)
  return n

def unip(v):
  # if isinstance(v, IPAddr):
  #   bytes = v.bits
  #   n = 0
  #   for b in bytes:
  #     n = (n << 8) + ord(b)
  #   print "IPAddr: %s -> %s (len = %s) -> %s" % (v, bytes, len(bytes), n)
  #   return { "addr": n, "mask": 32 }
  if isinstance(v, IPv4Network):
    return { "addr": str(v.ip), "mask": v.prefixlen }   
  elif isinstance(v, str):
    return { "addr" : v, "mask" : 32}
  else:
    raise TypeError(type(v))

def stringip(v):
  if isinstance(v, IPv4Network):
    if v.prefixlen == 32:
      sip = str(v.network)
      return sip
    else:
      raise TypeError("%s: can't compress subnet into single IP" % type(v))
  elif isinstance(v, str):
    return '"%s"' % v
  else:
    raise TypeError(type(v))

def unethaddr(v):
  return repr(v)

def physical(n):
  return { "type": "physical", "port": n }

def header_val(h, v):
  if h == "switch":
    return mk_header("switch", v)
  elif h == "port":
    return mk_header("location", physical(v))
  elif h == "srcmac":
    return mk_header("ethsrc", unethaddr(v))
  elif h == "dstmac":
    return mk_header("ethdst", unethaddr(v))
  elif h == "vlan_id":
    """ `None` values can't be handled by NetKAT correctly. Instead we use some
    very high numeric values for these fields and reset `None` in the final
    classifier."""
    v = VLAN_NONE_VALUE if v is None else v
    return mk_header("vlan", v)
  elif h == "vlan_pcp":
    v = VLAN_PCP_NONE_VALUE if v is None else v
    return mk_header("vlanpcp", str(v)) if NETKAT_DEBUG_BUILD else mk_header("vlanpcp", v)
  elif h == "ethtype":
    return mk_header("ethtype", str(v)) if NETKAT_DEBUG_BUILD else mk_header("ethtype", v)
  elif h == "protocol":
    return mk_header("ipproto", str(v)) if NETKAT_DEBUG_BUILD else mk_header("ipproto", v)
  elif h == "srcip":
    return mk_header("ipSrc", stringip(v)) if NETKAT_DEBUG_BUILD else mk_header("ip4src", unip(v))
  elif h == "dstip":
    return mk_header("ipDst", stringip(v)) if NETKAT_DEBUG_BUILD else mk_header("ip4dst", unip(v))
  elif h == "srcport":
    return mk_header("tcpsrcport", str(v)) if NETKAT_DEBUG_BUILD else mk_header("tcpsrcport", v)
  elif h == "dstport":
    return mk_header("tcpdstport", str(v)) if NETKAT_DEBUG_BUILD else mk_header("tcpdstport", v)
  elif h in ["vlan_offset", "vlan_nbits", "vlan_total_stages"]:
    return {} # Stage information is captured globally and re-applied to the classifier
  else:
    raise TypeError("bad header %s" % h)

def match_to_pred(m):
  header_lst = [header_val(h, m[h]) for h in m]
  lst = [mk_test(hv) for hv in header_lst if hv]
  return mk_and(lst)

def mod_to_pred(m):
  header_lst = [header_val(h, m[h]) for h in m]
  lst = [mk_mod(hv) for hv in header_lst if hv]
  return mk_seq(lst)

def mk_updated_maps(fmap, fvlist):
    """update the map `fmap' by appending each (field,value) pair in fvlist in turn.
    Returns a total of (number of tuples in fvlist) output maps. """
    mlist = []
    for (f,v) in fvlist:
        new_map = copy.copy(fmap)
        new_map[f] = v
        mlist.append(new_map)
    return mlist

def check_tp_prereqs(fmap, iptype_list):
    if ('srcport' in fmap or 'dstport' in fmap) and not 'protocol' in fmap:
        return mk_updated_maps(fmap, iptype_list)
    else:
        return [fmap]

def check_ip_prereqs(fmap, ethtype_list):
    if (('srcport' in fmap or 'dstport' in fmap or 'srcip' in fmap or 'dstip' in
         fmap) and not ('ethtype' in fmap)):
        return mk_updated_maps(fmap, ethtype_list)
    else:
        return [fmap]

def check_ip_proto_prereq(fmap, iptype_list):
    if 'protocol' in fmap and not 'ethtype' in fmap:
        return mk_updated_maps(fmap, iptype_list)
    else:
        return [fmap]

def set_field_prereqs(p):
    """ Set pre-requisite fields for netkat/openflow in match dictionary. """
    from pyretic.core.language import _match, union
    iptype_list  = [('ethtype',  IP_TYPE)]
    ethtype_list = [('ethtype',  IP_TYPE), ('ethtype', ARP_TYPE)]
    ipproto_list = [('protocol', TCP_TYPE), ('protocol', UDP_TYPE)]
    ''' Check and set various pairs in the current list of field=value maps. '''
    fmaps = [copy.copy(dict(_match(**p.map).map))]
    fmaps = reduce(lambda acc, x: acc + x,
                    map(lambda m: check_tp_prereqs(m, iptype_list), fmaps),
                    [])
    fmaps = reduce(lambda acc, x: acc+ x,
                   map(lambda m: check_ip_proto_prereq(m, iptype_list), fmaps),
                   [])
    fmaps = reduce(lambda acc, x: acc + x,
                    map(lambda m: check_ip_prereqs(m, ethtype_list), fmaps),
                    [])
    assert len(fmaps) >= 1
    if len(fmaps) > 1:
        return to_pred(union([_match(m) for m in fmaps]))
    else:
        return match_to_pred(fmaps[0])

def to_pred(p):
  from pyretic.core.language import (match, identity, drop, negate, union,
                                     parallel, intersection, ingress_network,
                                     egress_network, _match, difference)
  if isinstance(p, match):
    return set_field_prereqs(p)
  elif p == identity:
    return { "type": "true" }
  elif p == drop:
    return { "type": "false" }
  elif isinstance(p, negate):
    # Only policies[0] is used in Pyretic
    return { "type": "neg", "pred": to_pred(p.policies[0]) }
  elif isinstance(p, union) or isinstance(p, parallel):
    return mk_or(map(to_pred, p.policies))
  elif isinstance(p, difference):
    # Here, p.policy is a Filter (e.g., f1 & ~f2), so convert that.
    return to_pred(p.policy)
  elif isinstance(p, intersection):
    return mk_and(map(to_pred, p.policies))
  elif isinstance(p, ingress_network) or isinstance(p, egress_network):
    return to_pred(p.policy)
  else:
    raise TypeError(p)

def get_buckets_list(p):
    from pyretic.core.language import (parallel, sequential, if_, DynamicPolicy,
                                     ingress_network, egress_network,
                                     DerivedPolicy, CountBucket)
    from pyretic.lib.netflow import NetflowBucket
    if isinstance(p, parallel) or isinstance(p, sequential):
        return reduce(lambda acc, x: acc | get_buckets_list(x), p.policies, set([]))
    elif isinstance(p, if_):
        return get_buckets_list(p.t_branch) | get_buckets_list(p.f_branch)
    elif ((isinstance(p, DynamicPolicy) or isinstance(p, DerivedPolicy)) and not
          (isinstance(p, ingress_network) or isinstance(p, egress_network))):
        return get_buckets_list(p.policy)
    elif isinstance(p, CountBucket) or isinstance(p, NetflowBucket):
        return set([p])
    else:
        return set([])

def get_vlan_info(p):
    """Collect vlan stage information from matches/modifications in the
    policy. Returns a set of tuples, where each tuple is of the form

    (offset, nbits, total_stages)

    that occurred in the policy. In general there should be at most one element
    in this set! """
    from pyretic.core.language import (parallel, sequential,
                                       DerivedPolicy, match, modify, _match,
                                       _modify)
    if isinstance(p, match) or isinstance(p, modify):
        fmap = (_match(**p.map).map if isinstance(p, match) else
                _modify(**p.map).map)
        if 'vlan_id' in fmap:
            if 'vlan_offset' not in fmap:
                print "Invalid fmap:", fmap
                print p
            return set([(fmap['vlan_offset'], fmap['vlan_nbits'],
                         fmap['vlan_total_stages'])])
        else:
            return set()
    elif isinstance(p, parallel) or isinstance(p, sequential):
        return reduce(lambda acc, x: acc | get_vlan_info(x), p.policies, set())
    elif isinstance(p, DerivedPolicy):
        return get_vlan_info(p.policy)
    else:
        return set()

def vlan_preprocess(pol):
    def extract_offset_nbits(info):
        if len(info) == 1:
            tup = list(info)[0]
            return {'vlan_offset': tup[0], 'vlan_nbits': tup[1],
                    'vlan_total_stages': tup[2]}
        else:
            return {'vlan_offset': 0, 'vlan_nbits': VLAN_LENGTH,
                    'vlan_total_stages': 1}
    vlan_stage_info = get_vlan_info(pol)
    if len(vlan_stage_info) > 1:
        if reduce(lambda acc, x: acc or x[2] != 1, vlan_stage_info, False):
            print "netkat: Here's the policy you're compiling:\n", pol
            raise RuntimeError("Incorrect usage of VLANs detected: are you only"
                               " compiling virtual fields from a single"
                               " 'stage'?")
    return extract_offset_nbits(vlan_stage_info)

# TODO(arjun): Consider using aspects to inject methods into each class. That
# would be better object-oriented style.
def to_pol(p):
  from pyretic.core.language import (match, modify, identity, drop, negate, union,
                                     parallel, intersection, ingress_network,
                                     egress_network, sequential, fwd, if_,
                                     FwdBucket, DynamicPolicy, DerivedPolicy,
                                     Controller, _modify, CountBucket)
  from pyretic.lib.path import QuerySwitch
  from pyretic.lib.netflow import NetflowBucket
  from pyretic.evaluations.Tests.common_modules.stanford_forwarding import StanfordForwarding
  if isinstance(p, match):
    return mk_filter(to_pred(p))
  elif p is identity:
    return mk_filter({ "type": "true" })
  elif p is drop:
    return mk_filter({ "type": "false" })
  elif isinstance(p, modify):
    return mod_to_pred(_modify(**p.map).map)
  elif isinstance(p, negate):
    return mk_filter(to_pred(p))
  elif isinstance(p, union):
    return mk_filter(to_pred(p))
  elif isinstance(p, parallel):
    return mk_union(map(to_pol, p.policies))
  #elif isinstance(p, disjoint):
    #return mk_disjoint(map(to_pol, p.policies))
  elif isinstance(p, intersection):
    return mk_filter(to_pred(p))
  elif isinstance(p, sequential):
    return mk_seq(map(to_pol, p.policies))
  elif isinstance(p, fwd):
    return mk_mod(mk_header("location", physical(p.outport)))
  elif isinstance(p, if_):
    c = to_pred(p.pred)
    return mk_union([mk_seq([mk_filter(c), to_pol(p.t_branch)]),
                     mk_seq([mk_filter({ "type": "neg", "pred": c }), to_pol(p.f_branch)])])    
  elif isinstance(p, FwdBucket) or p is Controller:
      return {"type" : "mod", "header" : "location", "value": {"type" : "pipe", "name" : str(id(p))}}
  elif isinstance(p, CountBucket) or isinstance(p, NetflowBucket):
      return {"type" : "mod", "header" : "location", "value": {"type" : "query", "name" : str(id(p))}}
  elif isinstance(p, ingress_network) or isinstance(p, egress_network) or isinstance(p, DynamicPolicy):
      return to_pol(p.policy)
  elif isinstance(p, DerivedPolicy):
      return to_pol(p.policy)
  elif isinstance(p, QuerySwitch):
      # TODO: is there a neater way of incorporating QuerySwitch?
      return to_pol(cls_to_pol(p.netkat_compile()[0]))
  elif isinstance(p, StanfordForwarding):
      return to_pol(cls_to_pol(p.compile()))
  else:
      raise TypeError("unknown policy %s %s" % (type(p), repr(p)))

def cls_to_pol(c):
    from pyretic.core.language import parallel
    p = None
    for rule in c.rules:
        if p:
            p += (rule.match >> parallel(rule.actions))
        else:
            p = (rule.match >> parallel(rule.actions))
    return p

def mk_union(pols):
  return { "type": "union", "pols": pols }

def mk_disjoint(pols):
  return { "type": "disjoint", "pols": pols }

def mk_seq(pols):
  return { "type": "seq", "pols": pols }

def mk_and(preds):
  return { "type": "and", "preds": preds }

def mk_or(preds):
  return { "type": "or", "preds": preds }

# Converts a Pyretic policy into NetKAT, represented
# as a JSON string.
def compile_to_netkat(pyretic_pol):
  return json.dumps(to_pol(pyretic_pol))


############## json to policy ###################

field_map = {'dlSrc' : 'srcmac', 'dlDst': 'dstmac', 'dlTyp': 'ethtype', 
                'dlVlan' : 'vlan_id', 'dlVlanPcp' : 'vlan_pcp',
                'nwSrc' : 'srcip', 'nwDst' : 'dstip', 'nwProto' : 'protocol',
                'tpSrc' : 'srcport', 'tpDst' : 'dstport', 'inPort' : 'port'}

def create_match(pattern, switch_id, vlan_offset_nbits):
    from pyretic.core.language import match
    def __reverse_mac__(m):
        return ':'.join(m.split(':')[::-1])
    if switch_id > 0:
        match_map = {'switch' : switch_id}
    else:
        match_map = {}
    vlan_processed = False
    for k,v in pattern.items():
        if v is not None:
            if k == 'dlSrc' or k == 'dlDst':
                """ TODO: NetKat returns MAC addresses reversed. """
                match_map[field_map[k]] = MAC(__reverse_mac__(v))
            elif k == 'dlVlan' or k == 'dlVlanPcp':
                """ Reset `None` value for VLAN matches, if any. """
                if not vlan_processed:
                    if (('dlVlan' in pattern and pattern['dlVlan'] == VLAN_NONE_VALUE) and
                        ('dlVlanPcp' in pattern and pattern['dlVlanPcp'] == VLAN_PCP_NONE_VALUE)):
                        match_map['vlan_id'] = None
                        match_map['vlan_pcp'] = None
                    else:
                        def get_num(v):
                            # HACK! Sometimes, one of the fields has a value
                            # `None`. TODO: Must understand why this happens,
                            # because the compiler/runtime always set vlan_id
                            # and vlan_pcp together. May well lead to bugs in
                            # future!
                            return v if not v is None else 0
                        match_map['vlan_id'] = get_num(pattern['dlVlan'])
                        match_map['vlan_pcp'] = get_num(pattern['dlVlanPcp'])
                    vlan_processed = True
            else:
                match_map[field_map[k]] = v

    # HACK! NetKat doesn't return vlan_pcp with vlan_id sometimes.
    if 'vlan_id' in match_map and not 'vlan_pcp' in match_map:
        match_map['vlan_pcp'] = 0
    # Add auxiliary information for VLAN matches
    if 'vlan_id' in match_map:
        match_map['vlan_offset'] = vlan_offset_nbits['vlan_offset']
        match_map['vlan_nbits'] = vlan_offset_nbits['vlan_nbits']
        match_map['vlan_total_stages'] = vlan_offset_nbits['vlan_total_stages']
    # Ensure both id and pcp are set by the time we return match.
    assert (not 'vlan_id' in match_map) or 'vlan_pcp' in match_map
    assert (not 'vlan_pcp' in match_map) or 'vlan_id' in match_map
    return match(**match_map)

def create_action(action, multistage, vlan_offset_nbits):
    """ Return value: (action list, suspicious_vlan_bool) """
    from pyretic.core.language import (modify, Controller, identity)
    if len(action) == 0:
        return (set(), False)
    else:
        res = set()
        suspicious_vlan = False

        for act_list in action:
            mod_dict = {}
            vlan_processed = False
            vlans_processed = False
            for act in act_list:
                if act[0] == "Modify":
                    hdr_field = act[1][0][3:]
                    if hdr_field == "Vlan" or hdr_field == "VlanPcp":
                        hdr_field = 'dl' + hdr_field
                    else:
                        hdr_field = hdr_field[0].lower() + hdr_field[1:]
                    hdr_field = field_map[hdr_field]
                    value = act[1][1]
                    if hdr_field == 'srcmac' or hdr_field == 'dstmac':
                        value = MAC(value)
                        mod_dict[hdr_field] = value
                    elif hdr_field == 'vlan_id' or hdr_field == 'vlan_pcp':
                        mod_dict[hdr_field] = value
                        if vlan_processed:
                            """ Only write both values to None if *both* vlan id and
                            pcp fields contain respective None values. """
                            if (mod_dict['vlan_pcp'] == VLAN_PCP_NONE_VALUE and
                                mod_dict['vlan_id'] == VLAN_NONE_VALUE):
                                mod_dict['vlan_pcp'] = None
                                mod_dict['vlan_id'] = None
                            vlans_processed = True
                        vlan_processed = True
                    else:
                        mod_dict[hdr_field] = value
                    # Add auxiliary information for VLAN modifications
                    if hdr_field == 'vlan_id' or hdr_field == 'vlan_pcp':
                        mod_dict['vlan_offset'] = vlan_offset_nbits['vlan_offset']
                        mod_dict['vlan_nbits'] = vlan_offset_nbits['vlan_nbits']
                        mod_dict['vlan_total_stages'] = vlan_offset_nbits['vlan_total_stages']
                elif act[0] == "Output":
                    outout_seen = True
                    out_info = act[1]
                    if out_info['type'] == 'physical':
                        mod_dict['port'] = out_info['port']
                    elif out_info['type'] == 'controller':
                        res.add(Controller)
                    elif out_info['type'] == 'inport' and not multistage:
                        mod_dict['port'] = OFPP_IN_PORT
            
            if len(mod_dict) > 0:
                if (((not 'vlan_id' in mod_dict) and 'vlan_pcp' in mod_dict) or
                    ((not 'vlan_pcp' in mod_dict) and 'vlan_id' in mod_dict)):
                    suspicious_vlan = True
                res.add(modify(**mod_dict))
        if len(res) == 0:
            res.add(identity)
    return (res, suspicious_vlan)

def get_queries_from_names(qnames, qdict):
    return set([qdict[x] for x in qnames])

def adjust_vlan_fields(mat, acts):
    """Since netKAT is lazy about adding modifications whenever there is a
    match on the same value, we add the matched value again whenever exactly one
    of the vlan ID or PCP fields is missing.

    Setting both ID and PCP is required by the pox_client to ensure simple and
    correct operation of the metadata register.
    """
    from pyretic.core.language import modify
    new_acts = []
    for act in acts:
        new_act = act
        if isinstance(act, modify):
            m = copy.copy(act.map)
            if 'vlan_id' in m and not 'vlan_pcp' in m:
                assert 'vlan_pcp' in mat.map
                m['vlan_pcp'] = mat.map['vlan_pcp']
                new_act = modify(**m)
            elif 'vlan_pcp' in m and not 'vlan_id' in m:
                assert 'vlan_id' in mat.map
                m['vlan_id'] = mat.map['vlan_id']
                new_act = modify(**m)
        new_acts.append(new_act)
    return set(new_acts)
        
def json_to_classifier(fname, qdict, multistage, vlan_offset_nbits):
    from pyretic.core.classifier import Rule, Classifier
    data = json.loads(fname)
    rules = []
    for sw_tbl in data:
        switch_id = sw_tbl['switch_id']
        for rule in sw_tbl['tbl']:
            prio = rule['priority']
            m = create_match(rule['pattern'], switch_id, vlan_offset_nbits)
            (action, susp_vlan) = create_action(rule['action'], multistage, vlan_offset_nbits)
            if susp_vlan:
                action = adjust_vlan_fields(m, action)
            # This check allows classifier construction to proceed whether or
            # not there's a "queries" field in the rule.
            if 'queries' in rule and rule['queries']:
                queries = get_queries_from_names(rule['queries'], qdict)
                pyrule = Rule(m, queries | action, [None], "netkat_query")
            else:
                pyrule = Rule(m, action, [None], "netkat")
            rules.append((prio, pyrule))
    #rules.sort()
    rules = [v for (k,v) in rules]
    return Classifier(rules)
