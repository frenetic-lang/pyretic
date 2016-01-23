import struct, re
import pyretic.vendor

from ryu.lib.packet import *
from ryu.lib        import addrconv

from pyretic.core import util
from pyretic.core.network import IPAddr, EthAddr

__all__ = ['of_field', 'of_fields', 'get_packet_processor', 'Packet']
_field_list = dict()

IPV4 = 0x0800
IPV6 = 0x86dd
VLAN = 0x8100
ARP  = 0x0806

ICMP_PROTO = 1
TCP_PROTO  = 6
UDP_PROTO  = 17

##################################################
# EMPTY TEMPLATE PACKETS FOR DIFFERENT PROTCOLS 
##################################################
def arp_packet_gen():
    pkt = packet.Packet()
    pkt.protocols.append(ethernet.ethernet("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", ARP))
    pkt.protocols.append(arp.arp())

    return pkt

def ipv6_packet_gen():
    pkt = packet.Packet()
    pkt.protocols.append(ethernet.ethernet("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", IPV6))
    pkt.protocols.append(ipv6.ipv6(6, 0, 0, 0, 0, 0, '0:0:0:0:0:0:0:0', '0:0:0:0:0:0:0:0'))

    return pkt

def udp_packet_gen():
    pkt = packet.Packet()
    pkt.protocols.append(ethernet.ethernet("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", IPV4))
    pkt.protocols.append(ipv4.ipv4(proto=UDP_PROTO))
    pkt.protocols.append(udp.udp(0, 0))

    return pkt

def tcp_packet_gen():
    pkt = packet.Packet()
    pkt.protocols.append(ethernet.ethernet("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", IPV4))
    pkt.protocols.append(ipv4.ipv4(proto=TCP_PROTO))
    pkt.protocols.append(tcp.tcp(0, 0, 0, 0, 0, 0, 0, 0, 0))

    return pkt
def icmp_packet_gen():
    pkt = packet.Packet()
    pkt.protocols.append(ethernet.ethernet("ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", IPV4))
    pkt.protocols.append(ipv4.ipv4(proto=ICMP_PROTO))
    pkt.protocols.append(icmp.icmp(0, 0, 0))

    return pkt

ethertype_packets = {
    IPV4: {
        ICMP_PROTO: icmp_packet_gen,
        TCP_PROTO : tcp_packet_gen,
        UDP_PROTO : udp_packet_gen
    },
    IPV6: ipv6_packet_gen,
    ARP: arp_packet_gen
}

def build_empty_packet(ethertype, proto=None):
    if ethertype:
        pkt = ethertype_packets[ethertype]
        if proto is not None and not callable(pkt): pkt = pkt[proto]


        return pkt()

    return packet.Packet()


def of_fields(version="1.0"):
    return _field_list[version]

def get_protocol(ryu_pkt, protocol):
    for idx, i in enumerate(ryu_pkt.protocols):
        if hasattr(i, "protocol_name") and i.protocol_name==protocol:
            return idx

    return None

################################################################################
# Processor
################################################################################
class Processor(object):
    def __init__(self):
        pass

    def compile(self):
        fields = of_fields()
        fields = [field() for _, field in fields.items()]

        validators         = { field.validator.__class__.__name__: dict() for field in fields }

        for field in fields:
            exclusive_validators = validators[field.validator.__class__.__name__]
            exclusive_validators.setdefault(field.validator, set())
            exclusive_validators[field.validator].add(field)

        def extract_exclusive_headers(ryu_pkt, exclusive_groups):
                headers = {}
                for validator, fields in exclusive_groups.items():
                    if not iter(fields).next().is_valid(ryu_pkt):
                        continue

                    for field in fields:
                        headers[field.pyretic_field] = field.decode(ryu_pkt)

                    break

                return headers

        def pack_pyretic_headers(pyr_pkt, tmp_pkt, exclusive_groups):
                headers = {}
                for validator, fields in exclusive_groups.items():
                    if not iter(fields).next().is_valid(pyr_pkt):
                        continue

                    for field in fields:
                        field.encode_in_place(pyr_pkt, tmp_pkt)

                    break

                return pyr_pkt

        def expand(ryu_pkt):
            if not isinstance(ryu_pkt, packet.Packet):
                ryu_pkt = packet.Packet(ryu_pkt)

            headers = {}

            for key, exclusive_groups in validators.items():
                headers.update( extract_exclusive_headers(ryu_pkt, exclusive_groups) )

            return headers

        def contract(pyr_pkt):
            pkt = packet.Packet(pyr_pkt['raw'])

            if len(pyr_pkt['raw']) == 0:
                pkt = build_empty_packet(pyr_pkt.get('ethtype', None), pyr_pkt.get('protocol', None))

            def convert(h, v):
                if isinstance(v, IPAddr):
                    return str(v)
                elif isinstance(v, EthAddr):
                    return str(v)
                else:
                    return v

            pyr_pkt = { h : convert(h, v) for h,v in pyr_pkt.items() }


            for key, exclusive_groups in validators.items():
                pack_pyretic_headers(pyr_pkt, pkt, exclusive_groups)

            pkt.serialize()
            pyr_pkt['raw'] = str(pkt.data)

            return str(pkt.data)


        setattr(self, 'unpack', expand)
        setattr(self, 'pack', contract)

        # Build the packet processor pipeline
        return self

def get_packet_processor():
    try:
        return get_packet_processor.processor   
    except AttributeError:
        get_packet_processor.processor = Processor().compile()
        return get_packet_processor.processor

################################################################################
# Field Validators
################################################################################
class Validator(object):
    __slots__ = ['value']

    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.value == other.value

    def __repr__(self):
        return "%s: %s" % (self.__class__.__name__, self.value)

    def __hash__(self):
        return hash("%s_%s" % (self.__class__.__name__, self.value))

    def __call__(self, obj, pkt):
        if isinstance(pkt, packet.Packet):
            return self.validate_ryu_packet(obj, pkt)

        return self.validate_pyretic_packet(obj, pkt)

class ProtocolValidator(Validator):
    def validate_ryu_packet(self, obj, ryu_pkt):
        try:
            return obj.protocol(ryu_pkt, "ipv4").proto == self.value
        except:
            return False

    def validate_pyretic_packet(self, obj, pkt):
        try:
            return pkt["protocol"] == self.value
        except:
            return False



class EthertypeValidator(Validator):
    def validate_ryu_packet(self, obj, ryu_pkt):
        try:
            layer = obj.protocol(ryu_pkt, "vlan")
            if layer is None: layer = obj.protocol(ryu_pkt, "ethernet")
            return layer.ethertype == self.value
        except:
            return False

    def validate_pyretic_packet(self, obj, pkt):
        try:
            return pkt["ethtype"] == self.value
        except:
            return False

class VlanValidator(Validator):
    def __init__(self):
        self.value = VLAN


    def validate_ryu_packet(self, obj, ryu_pkt):
        try:
            return obj.protocol(ryu_pkt, "ethernet").ethertype == VLAN
        except:
            return False

    def validate_pyretic_packet(self, obj, pkt):
        if (not 'vlan_id' in pkt) and (not 'vlan_pcp' in pkt):
            return True

        try: return 'vlan_id' in pkt
        except: return False

        try: return 'vlan_pcp' in pkt
        except: return False


class TrueValidator(Validator):
    def validate_ryu_packet(self, obj, ryu_pkt):
        return True

    def validate_pyretic_packet(self, obj, pkt):
        return True

def proto_validator(value):
    return ProtocolValidator(value)

def ether_validator(value):
    return EthertypeValidator(value)

def true_validator(*args, **kwargs):
    return TrueValidator(True)

def vlan_validator(*args, **kwargs):
    return VlanValidator()


################################################################################
# Field Decorator
################################################################################
def of_field(match="", pyretic_field="", validator=true_validator(), version="1.0"):
    matches = match.split(".")

    def _of_field(cls):
        if len(matches) == 2: protocol, field = matches

        def get_protocol(ryu_pkt, protocol):
            for idx, i in enumerate(ryu_pkt.protocols):
                if hasattr(i, "protocol_name") and i.protocol_name==protocol:
                    return idx

            return None

        def _get_protocol(self, ryu_pkt, _protocol = None):
            if _protocol is None:
                _protocol = protocol

            idx = get_protocol(ryu_pkt, _protocol)
            if idx is None: return None

            return ryu_pkt.protocols[idx]

        def field_decode(self, ryu_pkt):
            #if not self.is_valid(ryu_pkt): return None

            layer = self.protocol(ryu_pkt)
            if layer is None: return None

            return getattr(layer, field)

        def field_encode(self, pyretic_pkt):
            pkt = packet.Packet(pyretic_pkt['raw'])

            field_encode_in_place(self, pyretic_pkt, pkt)

            pkt.serialize()
            pyretic_pkt['raw'] = pkt.data

            return pyretic_pkt

        def field_encode_in_place(self, pyretic_pkt, pkt):
            if not pyretic_field in pyretic_pkt: return pyretic_pkt

            layer = self.protocol(pkt)
            # Try to create the layer if it's not found
            if layer is None: raise ValueError

            setattr(layer, field, pyretic_pkt[pyretic_field])

            return pyretic_pkt


        def is_valid(self, ryu_pkt):
            return self.validator(self, ryu_pkt)

        # Add this field as an available field
        _field_list.setdefault(version, dict())
        _field_list[version][cls.__name__] = cls

        # Augment field clss with proper attributes and methods
        if not hasattr(cls, "protocol"): setattr(cls, "protocol", _get_protocol)
        if not hasattr(cls, "validator"): setattr(cls, "validator", validator)
        if not hasattr(cls, "is_valid"): setattr(cls, "is_valid", is_valid)
        if not hasattr(cls, "decode"): setattr(cls, "decode", field_decode)
        if not hasattr(cls, "encode"): setattr(cls, "encode", field_encode)
        if not hasattr(cls, "encode_in_place"): setattr(cls, "encode_in_place", field_encode_in_place)
        if not hasattr(cls, "pyretic_field"): setattr(cls, "pyretic_field", pyretic_field)

        return cls

    return _of_field

#######################
# OPENFLOW 1.0 FIELDS
#######################
@of_field("udp.dst_port", "dstport", proto_validator(UDP_PROTO), "1.0")
class UdpDstPort(object): pass

@of_field("udp.src_port", "srcport", proto_validator(UDP_PROTO), "1.0")
class UdpSrcPort(object): pass

@of_field("tcp.dst_port", "dstport", proto_validator(TCP_PROTO), "1.0")
class TcpDstPort(object): pass

@of_field("tcp.src_port", "srcport", proto_validator(TCP_PROTO), "1.0")
class TcpSrcPort(object): pass

@of_field("vlan.pcp", "vlan_pcp", vlan_validator(), "1.0")
class VlanPcp(object):
    def encode_in_place(self, pyr, pkt):
        if (not 'vlan_id' in pyr and not 'vlan_pcp' in pyr and vlan.vlan in pkt):
            for idx, proto in enumerate(pkt.protocols):
                if isinstance(proto, vlan.vlan):
                    pkt.protocols.pop(idx)

            return pyr

        if not 'vlan_pcp' in pyr:
            return pyr

        if not vlan.vlan in pkt:
            pkt.protocols.insert(1, vlan.vlan(ethertype=pkt.protocols[0].ethertype))

        gen = (protocol for protocol in pkt.protocols if protocol.__class__ == vlan.vlan)
        vl = gen.next()
        vl.pcp = pyr['vlan_pcp']
        pkt.protocols[0].ethertype = VLAN

        return pyr

@of_field("vlan.vid", "vlan_id", vlan_validator(), "1.0")
class VlanID(object):
    def encode_in_place(self, pyr, pkt):
        if (not 'vlan_id' in pyr and not 'vlan_pcp' in pyr and vlan.vlan in pkt):
            for idx, proto in enumerate(pkt.protocols):
                if isinstance(proto, vlan.vlan):
                    pkt.protocols.pop(idx)

            return pyr

        if not 'vlan_id' in pyr:
            return pyr

        if not vlan.vlan in pkt:
            pkt.protocols.insert(1, vlan.vlan(ethertype=pkt.protocols[0].ethertype))

        gen = (protocol for protocol in pkt.protocols if protocol.__class__ == vlan.vlan)
        vl = gen.next()
        vl.vid = pyr['vlan_id']
        pkt.protocols[0].ethertype = VLAN

        return pyr

@of_field("ethernet.src", "srcmac", version="1.0")
class SrcMac(object): pass

@of_field("ethernet.dst", "dstmac", version="1.0")
class DstMac(object): pass

@of_field("", "header_len", version="1.0")
class HeaderLength(object):
    def decode(self, ryu_pkt):
        return len(ryu_pkt.protocols[0])

    def encode_in_place(self, pyr, pkt):
        return pyr

@of_field("", "payload_len", version="1.0")
class PayloadLength(object):
    def decode(self, ryu_pkt):
        return len(ryu_pkt.data)

    def encode_in_place(self, pyr, pkt):
        return pyr


@of_field("ethernet.ethertype", "ethtype", version="1.0")
class EthType(object):
    def decode(self, ryu_pkt):
        try:
            layer = self.protocol(ryu_pkt, 'vlan')
            if layer is None: layer = self.protocol(ryu_pkt, 'ethernet')

            return layer.ethertype
        except:
            return None

@of_field("ipv6.srcip", "srcip", ether_validator(IPV6), version="1.0")
class Ipv6SrcIp(object): pass

@of_field("ipv6.dstip", "dstip", ether_validator(IPV6), version="1.0")
class Ipv6DstIp(object): pass

@of_field("ipv4.src", "srcip", ether_validator(IPV4), version="1.0")
class Ipv4SrcIp(object): pass

@of_field("ipv4.dst", "dstip", ether_validator(IPV4), version="1.0")
class Ipv4DstIp(object): pass

@of_field("ipv4.proto", "protocol", ether_validator(IPV4), version="1.0")
class Protocol(object): pass

@of_field("ipv4.tos", "tos", ether_validator(IPV4), version="1.0")
class TOS(object): pass

@of_field("icmp.type", "srcport", proto_validator(ICMP_PROTO), version="1.0")
class IcmpType(object): pass

@of_field("icmp.code", "dstport", proto_validator(ICMP_PROTO), version="1.0")
class IcmpCode(object): pass

@of_field("arp.opcode", "protocol", ether_validator(ARP), version="1.0")
class ArpOpcode(object): pass

@of_field("arp.src_ip", "srcip", ether_validator(ARP), version="1.0")
class ArpSrcIp(object): pass

@of_field("arp.dst_ip", "dstip", ether_validator(ARP), version="1.0")
class ArpDstIp(object): pass

################################################################################
# Packet 
################################################################################
class Packet(object):
    __slots__ = ["header"]
    
    def __init__(self, state={}):
        self.header = util.frozendict(state)

    def available_fields(self):
        return self.header.keys()

    def __eq__(self, other):
        return ( id(self) == id(other)
                 or ( isinstance(other, self.__class__)
                      and self.header == other.header ) )

    def __ne__(self, other):
        return not (self == other)
    
    def modifymany(self, d):
        add = {}
        delete = []
        for k, v in d.items():
            if v is None:
                delete.append(k)
            else:
                add[k] = v
        return Packet(self.header.update(add).remove(delete))


    def modify(self, **kwargs):
        return self.modifymany(kwargs)

    def virtual(self, layer, item):
        v = self.header.get(('v_%s_%s' % (layer, item)), None)

        if v is None:
            raise KeyError(item)

        return v

    def __getitem__(self, item):
        return self.header[item]

    def __hash__(self):
        return hash(self.header)
        
    def __repr__(self):
        import hashlib
        fixed_fields = {}
        fixed_fields['location'] = ['switch', 'port']
        fixed_fields['vlocation'] = ['vswitch', 'vinport', 'voutport']
        fixed_fields['source']   = ['srcip', 'srcmac']
        fixed_fields['dest']     = ['dstip', 'dstmac']
        order = ['location','vlocation','source','dest']
        tagging_helper_headers = ['vlan_offset', 'vlan_nbits',
                                  'vlan_total_stages']
        all_fields = self.header.keys()
        outer = []
        size = max(map(len, self.header) or map(len, order) or [len('md5'),0]) + 3
        ### LOCATION, VLOCATION, SOURCE, and DEST - EACH ON ONE LINE
        for fields in order:
            inner = ["%s:%s" % (fields, " " * (size - len(fields)))]
            all_none = True
            for field in fixed_fields[fields]:
                try:             
                    all_fields.remove(field)
                except:          
                    pass
                try:             
                    inner.append(repr(self.header[field])) 
                    all_none = False
                except KeyError: 
                    inner.append('None')
            if not all_none:
                outer.append('\t'.join(inner))
        ### MD5 OF PAYLOAD
        field = 'raw'
        outer.append("%s:%s%s" % ('md5',
                                    " " * (size - len(field)),
                                    hashlib.md5(self.header[field]).hexdigest()))
        all_fields.remove(field)
        ### ANY ADDITIONAL FIELDS
        for field in sorted(all_fields):
            try:             
                if self.header[field] and not field in tagging_helper_headers:
                    outer.append("%s:%s\t%s" % (field,
                                                " " * (size - len(field)),
                                                repr(self.header[field])))
            except KeyError: 
                pass
        return "\n".join(outer)
