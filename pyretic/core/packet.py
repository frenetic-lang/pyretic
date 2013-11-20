import pyretic.vendor
from ryu.lib.packet import *

import struct
import re

from bitarray import bitarray

from pyretic.core.network import IPAddr, EthAddr
from pyretic.core import util

from ryu.lib import addrconv

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
        fixed_fields['location'] = ['switch', 'inport', 'outport']
        fixed_fields['vlocation'] = ['vswitch', 'vinport', 'voutport']
        fixed_fields['source']   = ['srcip', 'srcmac']
        fixed_fields['dest']     = ['dstip', 'dstmac']
        order = ['location','vlocation','source','dest']
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
                if self.header[field]:
                    outer.append("%s:%s\t%s" % (field,
                                                " " * (size - len(field)),
                                                repr(self.header[field])))
            except KeyError: 
                pass
        return "\n".join(outer)

################################################################################
# Packet Processor
################################################################################
class PacketProcessor(object):
    def __init__(self):
        _mappers = {}
        pass

    """ Gets a raw located packet on the network, and returns
    headers that pyretic understands. """
    def unpack(self, raw_located_pkt):
        headers = raw_located_pkt
        pkt    = packet.Packet(raw_located_pkt['raw'])

        # For each protocol extract pyretic headers
        for protocol in pkt.protocols:
            # Order matters, higher layer protocols override lower levels
            headers = dict(self.headers_of(protocol).items() + headers.items())

        headers["payload_len"] = len(raw_located_pkt['raw'])
        headers["header_len"]  = 14

        return headers

    def headers_of(self, layer):
        if layer.__class__ == 'str':
            return layer

        return self.mapper_for(layer.protocol_name).to_headers(layer)

    def mapper_for(self, protocol):
        return globals().get(protocol.capitalize() + "Mapper", Mapper)

    def mapper_list(self):
        return Mapper.__subclasses__()

    def pack(self, pyretic_pkt):
        pkt = packet.Packet()

        #TODO: I believe right now we only support "one" vlan tag.
        #      I am not sure whether we support sets for vlan_ids or not
        protocols = map( lambda mapper: mapper.pack(pyretic_pkt), self.mapper_list() )
        protocols = filter( lambda x: x, protocols )

        # TODO: Serious issue here if the ordering of layers is wrong
        #       Should be fixed...
        #
        # protocols = sorted(protocols, key=lambda protocol: protocol[1])

        for p in protocols:
            if p:
                pkt.add_protocol( p )

        pkt.serialize()
        return str(pkt.data)

class Mapper(object):
    _header   = {}
    _vheader  = {}
    _name     = None
    _ryu_class= None

    @classmethod
    def to_headers(cls, layer):
        header = {}

        # Add pyretic headers
        for h, v in cls._header.iteritems():
            method = None
            if isinstance(v, tuple):
                method, v = v

            res = getattr(layer, v)
            if method:
                res = method(res)

            #TODO: is this required?
            if callable(res):
                res=res()

            header[h] = res

        # Add the virtual headers
        of_headers = cls._header.values()
        for k, v in layer.stringify_attrs():
            if k not in of_headers and v is not None:
                header["v_%s_%s" % (layer.protocol_name, k)] = v

        return header

    @classmethod
    def protocol_name(cls):
        if not cls._name:
            cls._name = cls.__name__.split("Mapper")[0].lower()
        return cls._name

    @classmethod
    def protocol_class(cls):
        if not cls._ryu_class:
            kls = cls.protocol_name()
            cls._ryu_class = getattr(globals()[kls], kls)

        return cls._ryu_class

    @classmethod
    def pack_headers(cls,pkt):
        headers = {}
        for k, v in pkt.iteritems():
            if k[0] == 'v' and k.split("_")[1] == cls.protocol_name():
                headers[str.join("_",k.split("_")[2:])] = v

        for k, v in cls._header.iteritems():
            value = v
            if isinstance( v, tuple ):
                value = v[1]

            if k in pkt:
                if isinstance(pkt[k], IPAddr) or isinstance(pkt[k], EthAddr):
                    headers[value] = str(pkt[k])
                else:
                    headers[value] = pkt[k]

        return headers


    @classmethod
    def pack(cls, pkt):
        headers = cls.pack_headers(pkt)

        try:
            return cls.protool_class()(**headers)
        except:
            return None



class EthernetMapper(Mapper):
    _header = {
       "srcmac"      : (addrconv.mac.text_to_bin, "src"),
       "dstmac"      : (addrconv.mac.text_to_bin, "dst"),
       "ethtype"     : "ethertype" 
    }

    @classmethod
    def pack(cls, pkt):
        headers = cls.pack_headers(pkt)
        if pkt.get('vlan_id'):
            headers['ethertype'] = 0x8100

        return cls.protocol_class()(**headers)


class VlanMapper(Mapper):
    _header = {
        'vlan_id' : "vid",
        'vlan_pcp': "pcp",
        'ethtype' : "ethertype"
    }

    @classmethod
    def pack(cls, pkt):
        if not 'vlan_id' in pkt:
            return None

        headers = cls.pack_headers(pkt)
        return cls.protocol_class()(**headers)


class Ipv4Mapper(Mapper):
    _header = {
        'srcip'   : (addrconv.ipv4.text_to_bin, "src"),
        'dstip'   : (addrconv.ipv4.text_to_bin, "dst"),
        'protocol': "proto",
        'tos': "tos"
    }

    @classmethod
    def pack(cls, pkt):
        if pkt['ethtype'] == 0x0800:
            headers = cls.pack_headers(pkt)
            return cls.protocol_class()(**headers)
        return None

class Ipv6Mapper(Mapper):
    _header = {
        'srcip'   : (addrconv.ipv6.text_to_bin, "src"),
        'dstip'   : (addrconv.ipv6.text_to_bin, "dst"),
        'protocol': "nxt",
        'tos'     : "traffic_class"
    }

    @classmethod
    def pack(cls, pkt):
        if pkt['ethtype'] == 0x86DD:
            headers = cls.pack_headers(pkt)
            return cls.protocol_class()(**headers)
        return None

class UdpMapper(Mapper):
    _header = {
        'srcport': "src_port",
        'dstport': "dst_port"
    }

    @classmethod
    def pack(cls, pkt):
        if pkt['protocol'] == 0x11:
            headers = cls.pack_headers(pkt)
            return cls.protocol_class()(**headers)
        return None

class TcpMapper(Mapper):
    _header = {
        'srcport': "src_port",
        'dstport': "dst_port"
    }

    @classmethod
    def pack(cls, pkt):
        if pkt['protocol'] == 0x06:
            headers = cls.pack_headers(pkt)
            return cls.protocol_class()(**headers)
        return None

class DhcpMapper(Mapper):
    @classmethod
    def pack(cls, pkt):
        pass

class IcmpMapper(Mapper):
    _header = {
        'srcport': "type",
        'dstport': "code"
    }

    @classmethod
    def pack(cls, pkt):
        if not 'v_icmp_data' in pkt:
            return None

        headers = cls.pack_headers(pkt)
        # type is reserved so it should be fed as type_ into the
        # __init__ method of ICMP class
        headers["type_"] = headers["type"]
        del headers["type"]

        return cls.protocol_class()(**headers)

class ArpMapper(Mapper):
    _header = {
        "protocol": "opcode",
        "srcip"   : (addrconv.ipv4.text_to_bin, "src_ip"),
        "dstip"   : (addrconv.ipv4.text_to_bin, "dst_ip"),
    }
    
    @classmethod
    def pack(cls, pkt):
        if pkt['ethtype'] == 0x0806:
            headers = cls.pack_headers(pkt)
            return cls.protocol_class()(**headers)
        return None

def get_packet_processor():
    return PacketProcessor()
