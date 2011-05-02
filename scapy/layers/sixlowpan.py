## Copyright (C) Cesar A. Bernardini <mesarpe@gmail.com>
## Intern at INRIA Grand Nancy Est
## This program is published under a GPLv2 license
"""

6LoWPAN Protocol Stacks
=======================

                            |-----------------------|
Application                 | Application Protocols |
                            |-----------------------|
Transport                   |   UDP      |   TCP    |
                            |-----------------------|
Network                     |          IPv6         | (Only IPv6)
                            |-----------------------|
                            |         LoWPAN        | (in the middle betwen network and data link layer)
                            |-----------------------|
Data Link Layer             |   IEEE 802.15.4 MAC   |
                            |-----------------------|
Physical                    |   IEEE 802.15.4 PHY   |
                            |-----------------------|

The Internet C ontrol Message protocol v6 (ICMPv6) is used for control
messaging.

Adaptation between full IPv6 and the LoWPAN format is performed by routers at
the edge  of 6LoWPAN islands.

A LoWPAN support addressing; a direct mapping between the link-layer address
and the IPv6 address is used for achieving compression.

"""

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, XBitField, LEShortField, LEIntField, StrLenField, HiddenField, BitEnumField, Field, ShortField, BitFieldLenField, XShortField

from scapy.layers.inet6 import IPv6
import socket

from dot15d4 import Dot15d4, Dot15d4Data
from scapy.utils import lhex

from scapy.volatile import RandString, RandByte
import socket
import struct
from scapy.utils6 import in6_or, in6_and

from scapy.fields import Field, ConditionalField, PadField
from scapy.layers.l2 import mac2str

class SixLoWPANAddrField(Field):
    """Special field to store 6LoWPAN fields
    """
    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        self.adjust=adjust
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        return lhex(self.i2h(pkt,x))
    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.length_of(pkt) == 8:
            return s + struct.pack(self.fmt[0]+"B", val)
        if self.length_of(pkt) == 16:
            return s + struct.pack(self.fmt[0]+"H", val)
        if self.length_of(pkt) == 32:
            return s + struct.pack(self.fmt[0]+"2H", val)
        if self.length_of(pkt) == 48:
            return s + struct.pack(self.fmt[0]+"3H", val)
        elif self.length_of(pkt) == 64:
            return s + struct.pack(self.fmt[0]+"Q", val)
        elif self.length_of(pkt) == 128:
            return s + struct.pack(self.fmt[0]+"2Q", val)
        else:
            return s
    def getfield(self, pkt, s):
        if self.length_of(pkt) == 8:
            return s[1:], self.m2i(pkt, struct.unpack(self.fmt[0]+"B", s[:1])[0])
        elif self.length_of(pkt) == 16:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0]+"H", s[:2])[0])
        elif self.length_of(pkt) == 32:
            return s[4:], self.m2i(pkt, struct.unpack(self.fmt[0]+"2H", s[:2], s[2:4])[0])
        elif self.length_of(pkt) == 48:
            return s[6:], self.m2i(pkt, struct.unpack(self.fmt[0]+"3H", s[:2], s[2:4], s[4:6])[0])
        elif self.length_of(pkt) == 64:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0]+"Q", s[:8])[0])
        elif self.length_of(pkt) == 128:
            return s[16:], self.m2i(pkt, struct.unpack(self.fmt[0]+"2Q", s[:8], s[8:16])[0])



class LoWPANUncompressedIPv6(Packet):
    fields_desc = [
        BitField("__type", 0x0, 8)
    ]
    
    def guess_payload_class(self, payload):
        # super SWITCH depending on reserved and type
        if self.__type == LOWPAN_IPv6Uncompressed:
            return IPv6(payload)

class LoWPANMesh(Packet):
    name = "6LoWPAN Mesh Packet"
    fields_desc = [
        HiddenField(BitField("__reserved", 0x2, 2)),
        BitEnumField("__v", 0x0, 1, [False, True]),
        BitEnumField("__f", 0x0, 1, [False, True]),
        BitField("__hopsLeft", 0x0, 4),
        ConditionalField(
            SixLoWPANAddrField("_sourceAddr", 0x0, length_of=lambda pkt: pkt.__v and 2 or 8),
            lambda pkt: source_addr_mode(pkt) != 0
        ),
        ConditionalField(
            SixLoWPANAddrField("_destinyAddr", 0x0, length_of=lambda pkt: pkt.__f and 2 or 8),
            lambda pkt: destiny_addr_mode(pkt) != 0
        ),
    ]

    def guess_payload_class(self, payload):
        # check first 2 bytes if they are ZERO it's not a 6LoWPAN packet
        pass
        


class LoWPANFragmentationFirst(Packet):
    name = "6LoWPAN First Fragmentation Packet"
    fields_desc = [
        HiddenField(BitField("__reserved", 0x18, 5)),
        BitField("__datagramSize", 0x0, 11),
        ShortField("__datagramTag", 0x0),
    ]
    
    def guess_payload_class(self, payload):
        return LoWPAN_IPHC

class LoWPANFragmentationSubsequent(Packet):
    name = "6LoWPAN Subsequent Fragmentation Packet"
    fields_desc = [
        HiddenField(BitField("__reserved", 0x1C, 5)),
        BitField("__datagramSize", 0x0, 11),
        XShortField("__datagramTag", 0x0), #TODO: change default value, should be a random one
        ByteField("__datagramOffset", 0x0), #VALUE PRINTED IN OCTETS, wireshark does in bits (128 bits == 16 octets)
    ]

    def guess_payload_class(self, payload):
        return LoWPAN_IPHC

#class LoWPANBroadcast(Packet):
    # page 23. Section 11.1
#    fields_desc = [
#        HiddenField(BitField("__reserved", 0x01, 2)),
#        BitField("__lowpanBC0", 0x0, 6),
#        ByteField("__seqNumber", 0x0)
#    ]

class LoWPANHC1CompressedIPv6(Packet):
    # Page 19
    """Other non-compressed fields MUST follow the
       Hop Limit as implied by the "HC1 encoding" in the exact same order as
       shown above (Section 10.1): source address prefix (64 bits) and/or
       interface identifier (64 bits), destination address prefix (64 bits)
       and/or interface identifier (64 bits), Traffic Class (8 bits), Flow
       Label (20 bits) and Next Header (8 bits)
    """
    name = "6LoWPAN Compressed IPv6 packet"
    fields_desc = [
        HiddenField(BitField("__reserved", 0x1, 2)),
        BitField("__type", 0x2, 6),
        BitField("__ipv6SourceAddr", 0x0, 2),
        BitField("__ipv6TargetAddr", 0x0, 2),
        BitEnumField("__tc_fl", 0x0, 1, [False, True]),
        BitField("__nh", 0x0, 2),
        BitEnumField("__hc2enc", 0x0, 1, [False, True]),
        # The Hop Limit (8 bits) MUST always follow the encoding fields ("HC1 encoding" as show in figure 9)
        ByteField("__hopLimit", 0x0),
        ConditionalField(
            BitField("__sourceAddrPrefix", 0x0, 64),
            lambda pkt: pkt.__ipv6SourceAddr >> 1 == 0
        ),
        ConditionalField(
            BitField("__sourceInterfaceIdentifier", 0x0, 64),
            lambda pkt: bool(pkt.__ipv6SourceAddr & 0x01)
        ),
        ConditionalField(
            BitField("__targetAddrPrefix", 0x0, 64),
            lambda pkt: pkt.__ipv6TargetAddr >> 1 == 0
        ),
        ConditionalField(
            BitField("__targetInterfaceIdentifier", 0x0, 64),
            lambda pkt: bool(pkt.__ipv6TargetAddr & 0x01)
        ),
        ConditionalField(
            ByteField("__trafficClass", 0x0),
            lambda pkt: bool(pkt.__tc_fl & 0x1)
        ),
        ConditionalField(
            BitField("__flowLabel", 0x0, 20),
            lambda pkt: bool(pkt.__tc_fl & 0x1)
        ),
        ConditionalField(
            BitField("__nextHeader", 0x0, 20),
            lambda pkt: bool(pkt.__tc_fl | 0x0)
        ),
        #
    ]
    pass

    def guess_payload_class(self, payload):
        # TODO: improve!
        # using enc hc2 or not
        if bool(self.__hc2enc) and self.__nh == 0x1:
            return LoWPANHC2_UDP(payload)
        else:
            return payload


def LoWPANHC2_UDP(Packet):
    name = "6LoWPAN compressed UDP packets"
    fields_desc = [
        BitField("__udpSourcePort", 0x0, 1),
        BitField("__udpTargetPort", 0x0, 1),
        BitField("__len", 0x0, 2),
        BitField("__reserved", 0x0, 4),
        ConditionalField(
            BitField("__udpCompressedSourcePort", 0x0, 4),
            lambda pkt: bool(pkt.__udpSourcePort)
        ),
        ConditionalField(
            BitField("__udpUncompressedSourcePort", 0x0, 16),
            lambda pkt: not bool(pkt.__udpSourcePort)
        ),
        ConditionalField(
            BitField("__udpCompressedTargetPort", 0x0, 4),
            lambda pkt: bool(pkt.__udpTargetPort)
        ),
        ConditionalField(
            BitField("__udpUncompressedTargetPort", 0x0, 16),
            lambda pkt: not bool(pkt.__udpTargetPort)
        ),
        ConditionalField(
            BitField("__len", 0x0, 8), #TODO: I can't find out the exact length for this value
            lambda pkt: not bool(pkt.__udpTargetPort)
        ),
    ]

    def guess_payload_class(self, payload):
        return UDP(payload)

IPHC_DEFAULT_VERSION = 6
IPHC_DEFAULT_TF = 0
IPHC_DEFAULT_FL = 0

def source_addr_mode(pkt):
    if pkt.sac:
        if pkt.sam == 0x0:      return 128
        elif pkt.sam == 0x1:    return 64
        elif pkt.sam == 0x2:    return 16
        elif pkt.sam == 0x3:    return 0
    else:
        if pkt.sam == 0x0:      return 0
        elif pkt.sam == 0x1:    return 64
        elif pkt.sam == 0x2:    return 16
        elif pkt.sam == 0x3:    return 0

def destiny_addr_mode(pkt):
    if pkt.m == 0 and pkt.dac == 0:
        if pkt.dam == 0x0:      return 128
        elif pkt.dam == 0x1:    return 64
        elif pkt.dam == 0x2:    return 16
        else:                   return 0
    elif pkt.m == 0 and pkt.dac == 1:
        if pkt.dam == 0x0:      raise Exception('reserved')
        elif pkt.dam == 0x1:    return 64
        elif pkt.dam == 0x2:    return 16
        else:                   return 0
    elif pkt.m == 1 and pkt.dac == 0:
        if pkt.dam == 0x0:      return 128
        elif pkt.dam == 0x1:    return 48
        elif pkt.dam == 0x2:    return 32
        elif pkt.dam == 0x3:    return 8
    elif pkt.m == 1 and pkt.dac == 1:
        if pkt.dam == 0x0:      return 48
        elif pkt.dam == 0x1:    raise Exception('reserved')
        elif pkt.dam == 0x2:    raise Exception('reserved')
        elif pkt.dam == 0x3:    raise Exception('reserved')

def pad_trafficclass(pkt):
    if pkt._tf == 0x0:          return 4
    elif pkt._tf == 0x1:        return 2
    elif pkt._tf == 0x2:        return 2
    else:                       return 0

def flowlabel_len(pkt):
    if pkt._tf == 0x0:          return 4*8
    elif pkt._tf == 0x0:        return 3*8
    else:                       return 0

class LoWPAN_IPHC(Packet):
    # the LOWPAN_IPHC encoding utilizes 13 bits, 5 dispatch type
    name = "LoWPAN IP Header Compression Packet"
    fields_desc = [
        #dispatch
        HiddenField(BitField("__reserved", 0x03, 3)),
        BitField("_tf", 0x0, 2),
        BitEnumField("nh", 0x0, 1, [False, True]),
        BitField("hlim", 0x0, 2),
        BitEnumField("cid", 0x0, 1, [False, True]),
        BitEnumField("sac", 0x0, 1, [False, True]),
        BitField("sam", 0x0, 2),
        BitEnumField("m", 0x0, 1, [False, True]),
        BitEnumField("dac", 0x0, 1, [False, True]),
        BitField("dam", 0x0, 2),
        ConditionalField(
            ByteField("__contextIdentifierExtension", 0x0), #
            lambda pkt: pkt.cid == 0x1
        ),
        
        # TF: traffic class and flowlabel, 00 case
        ConditionalField(
            BitField("tc_ecn", 0x0, 2), # TODO: I think there is an error in here
            lambda pkt: pkt._tf != 0x03
        ),
        ConditionalField(
            BitField("tc_dscp", 0x0, 6),
            lambda pkt: pkt._tf in [0x0, 0x2]
        ),
        ConditionalField(
            HiddenField(BitFieldLenField("__padd", 0x0, 2, length_of = pad_trafficclass)), #
            lambda pkt: pkt._tf in [0x0, 0x1]
        ),
        ConditionalField(
            BitFieldLenField("fl_flowLabel", 0x0, 8, length_of = flowlabel_len), #
            lambda pkt: pkt._tf in [0x0, 0x1]
        ),

        #NH
        ConditionalField(
            ByteField("_nhField", 0x0), #
            lambda pkt: pkt.nh == 0x0
        ),
        #TODO: next header is using LOWPAN_NHC when pkt.__nh == 0x1
        #HLIM: Hop Limit: if it's 0
        ConditionalField(
            ByteField("_hopLimit", 0x0),
            lambda pkt: pkt.hlim == 0x0
        ),
        ConditionalField(
            SixLoWPANAddrField("_sourceAddr", 0x0, length_of=source_addr_mode),
            lambda pkt: source_addr_mode(pkt) != 0
        ),
        ConditionalField(
            SixLoWPANAddrField("_destinyAddr", 0x0, length_of=destiny_addr_mode),
            lambda pkt: destiny_addr_mode(pkt) != 0
        ),
    ]

    def build_payload(self):
        packet = IPv6()
        packet.payload = self.payload
        packet.version = IPHC_DEFAULT_VERSION
        packet.tc, packet.fl = self._getTrafficClassAndFlowLabel()
        packet.plen = 0 #TODO: Payload length can be inferred from lower layers from either the 6LoWPAN Fragmentation header or the IEEE802.15.4 header
        packet.nh = self._getNextHeader()
        packet.hlim = self._hopLimit
        packet.src = self._getSourceAddr()
        packet.dst= self._getDestinyAddr()
        return str(packet)

    def guess_payload_class(self, payload):
        #if self._nhField == 0x0:
        return IPv6
        #elif self.nhField == 0x1:
        #    return LoWPAN_NHC

    def default_payload_class(self):
        return IPv6

    def _getSourceAddr(self): #TODO: implement!!
        link_local_prefix = "fe80:0000:0000:0000:0000:0000:0000:0000"
        
        if self.sac == 0:
            if self.sam == 0x0: #128 bits full-addr
                return self._sourceAddr
            elif self.sam == 0x1:
                tmp_ip = "\x00"*8 + struct.pack("4H", self._sourceAddr)
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
            elif self.sam == 0x2:
                prefix_64 = "0000:0000:0000:0000:0000:00ff:fe00:0000" #0000:00ff:fe00:XXXX
                tmp_ip = "\x00"*8 + "\x00"*6 + struct.pack("H", self._sourceAddr)
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, prefix_64))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
            elif self.sam == 0x3:
                # 0 bits. The first 64 bits of the address are the link-local prefix padded with zeros. The remaining 64 bits are computed from the encapsulating header (802.15.4 or IPv6 source addr).
                raise Exception('unimplmemented')
        elif self.sac == 0x1:
            
            if self.sam == 0x3:
                # 0 bits. The address is fully elided and is derived using context information and the encapsulating header.
                pass
        raise Exception('Unimplemented')
    def _getDestinyAddr(self): #TODO: implement!!
        if self.m == 0 and self.dac == 0:
            if self.dam == 0x0: #128 bits full-addr
                return self._destinyAddr
            elif self.sam == 0x1:
                tmp_ip = "\x00"*8 + struct.pack("4H", self._destinyAddr)
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
            elif self.sam == 0x2:
                prefix_64 = "0000:0000:0000:0000:0000:00ff:fe00:0000" #0000:00ff:fe00:XXXX
                tmp_ip = "\x00"*8 + "\x00"*6 + struct.pack("H", self._destinyAddr)
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, prefix_64))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
            elif self.sam == 0x3:
                # 0 bits. The first 64 bits of the address are the link-local prefix padded with zeros. The remaining 64 bits are computed from the encapsulating header (802.15.4 or IPv6 source addr).
                raise Exception('unimplmemented')
        elif self.m == 0 and self.dac == 1:
            if self.dam == 0:
                raise Exception('reserved address')
            #elif self.dam == 1:
                
        raise Exception('unimplmemented')
        return "2002:db8::ff:fe00:1"

    def _getTrafficClassAndFlowLabel(self):
        if self._tf == 0x0:
            return (self.tc_ecn << 6) + self.tc_dscp, self.fl_flowlabel
        elif self._tf == 0x1:
            return (self.tc_ecn << 6), self.fl_flowlabel
        elif self._tf == 0x2:
            return (self.tc_ecn << 6) + self.tc_dscp, 0
        else:
            return 0, 0
    
    def _getNextHeader(self):
        if self.nh == 0x0:
            return self._nhField
        else:
            raise Exception('Unimplemented')

    def _getHopLimit(self):
        if self.hlim == 0x0:
            return self._hopLimit
        elif self.hlim == 0x1:
            return 1
        elif self.hlim == 0x2:
            return 64
        elif self.hlim == 0x3:
            return 255

class SixLoWPAN(Packet):
    name = "SixLoWPAN(Packet)"

    def guess_payload_class(self, payload):
        if ord(payload[0]) >> 3 == 0x18:
            return LoWPANFragmentationFirst
        elif ord(payload[0]) >> 3 == 0x1C:
            return LoWPANFragmentationSubsequent
        elif ord(payload[0]) >> 6 == 0x02:
            return LoWPANMesh
        elif ord(payload[0]) >> 6 == 0x01:
            return LoWPAN_IPHC
        else:
            return payload

bind_layers( SixLoWPAN,         LoWPANUncompressedIPv6,             )
bind_layers( SixLoWPAN,         LoWPANHC1CompressedIPv6,            )
bind_layers( SixLoWPAN,         LoWPANFragmentationFirst,           )
bind_layers( SixLoWPAN,         LoWPANFragmentationSubsequent,      )
bind_layers( SixLoWPAN,         LoWPANMesh,                         )
bind_layers( SixLoWPAN,         LoWPAN_IPHC,                        )
#bind_layers( SixLoWPAN,         LoWPANBroadcast,                    )
#bind_layers( LoWPANMesh,        LoWPANBroadcast,                    )
#bind_layers( LoWPANBroadcast,   LoWPANFragmentationFirst,           )
#bind_layers( LoWPANBroadcast,   LoWPANFragmentationSubsequent,      )
bind_layers( LoWPANMesh,        LoWPANFragmentationFirst,           )
bind_layers( LoWPANMesh,        LoWPANFragmentationSubsequent,      )
bind_layers( LoWPANMesh,        LoWPANHC1CompressedIPv6,            )
#bind_layers( LoWPANBroadcast,   LoWPANHC1CompressedIPv6,            )
bind_layers( LoWPANFragmentationFirst, LoWPANHC1CompressedIPv6,     )
bind_layers( LoWPANFragmentationSubsequent, LoWPANHC1CompressedIPv6,  )
bind_layers( LoWPANFragmentationFirst, LoWPAN_IPHC, )
bind_layers( LoWPANFragmentationSubsequent, LoWPAN_IPHC             )


bind_layers( Dot15d4Data,         SixLoWPAN,             )


if __name__ == '__main__':
    #p = LoWPAN()
    #print "lowpan", 1
    #print p.show()
    #p.show2()
    from scapy.utils import hexdump
    #print hexdump(p)

    #ip6_packet = LoWPANIPv6UncompressField(Reserved=0x1, Type=0x1) / \
    #    IPv6(src="AAAA:BBBB:CCCC:DDDD:EEEE:FFFF:0000:1111")
    #ip6_packet.show()
    #ip6_packet.show2()
    #print str(ip6_packet)


    # some sample packet extracted
    icmp_string = "\x60\x00\x00\x00\x00\x08\x3a\x80\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x11\x22\xff\xfe\xfe\x33\x44\x55"
    

    lowpan_frag_first = "\xc3\x42\x00\x23\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xf9\x00\x00\x02\x12\x77\x9b\x1a\x9a\x50\x18\x04\xc4\x12\xd5\x00\x00\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x34\x2e\x30\x31\x20\x54\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x61\x6c\x2f\x2f\x45\x4e\x22\x20\x22\x68\x74\x74\x70"

    #lowpan_frag_first_packet = SixLoWPAN(lowpan_frag_first)
    #lowpan_frag_first_packet.show2()

    lowpan_frag_second = "\xe3\x42\x00\x23\x10\x3a\x2f\x2f\x77\x77\x77\x2e\x77\x33\x2e\x6f\x72\x67\x2f\x54\x52\x2f\x68\x74\x6d\x6c\x34\x2f\x6c\x6f\x6f\x73\x65\x2e\x64\x74\x64\x22\x3e\x0a\x3c\x68\x74\x6d\x6c\x3e\x3c\x68\x65\x61\x64\x3e\x3c\x74\x69\x74\x6c\x65\x3e\x57\x65\x6c\x63\x6f\x6d\x65\x20\x74\x6f\x20\x74\x68\x65\x20\x43\x6f\x6e\x74\x69\x6b\x69\x2d\x64\x65\x6d\x6f\x20\x73\x65\x72\x76\x65\x72\x21\x3c\x2f\x74\x69\x74\x6c\x65"

    #print
    #print

    #lowpan_frag_sec_packet = SixLoWPAN(lowpan_frag_second)
    #lowpan_frag_sec_packet.show2()

    lowpan_iphc = "\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xf9\x00\x00\x02\x12\x77\x9b\x1a\x9a\x50\x18\x04\xc4\x12\xd5\x00\x00\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x34\x2e\x30\x31\x20\x54\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x61\x6c\x2f\x2f\x45\x4e\x22\x20\x22\x68\x74\x74\x70"

    #lowpan_frag_iphc = LoWPAN_IPHC(lowpan_iphc)
    #lowpan_frag_iphc.show2()

    #print
    #print

    #from scapy.layers.inet6 import IPv6
    #ip6 = IPv6(src="2002:db8::11:22ff:fe33:4455", dst="2002:db8::ff:fe00:1")
    #from scapy.utils import hexdump
    #hexdump(ip6)

    # SAMPLE PACKETSS!!! IEEE 802.15.4 containing   
    
    ieee802_firstfrag = "\x41\xcc\xa3\xcd\xab\x16\x15\x14\xfe\xff\x13\x12\x02\x55\x44\x33\xfe\xff\x22\x11\x02\xc3\x42\x00\x23\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xf9\x00\x00\x02\x12\x77\x9b\x1a\x9a\x50\x18\x04\xc4\x12\xd5\x00\x00\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x34\x2e\x30\x31\x20\x54\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x61\x6c\x2f\x2f\x45\x4e\x22\x20\x22\x68\x74\x74\x70\x39\xb5"

    #ieee = Dot15d4(ieee802_firstfrag)
    #ieee.show2()

    ieee802_secfrag = "\x41\xcc\x4d\xcd\xab\x55\x44\x33\xfe\xff\x22\x11\x02\x16\x15\x14\xfe\xff\x13\x12\x02\xe2\x39\x00\x17\x10\x69\x76\x65\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x5b\x61\x61\x61\x61\x3a\x3a\x31\x31\x3a\x32\x32\x66\x66\x3a\x66\x65\x33\x33\x3a\x34\x34\x35\x35\x5d\x2f\x73\x65\x6e\x73\x6f\x72\x2e\x73\x68\x74\x6d\x6c\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x55\x3b\x20\x4c\x69\x66\xac"

    #ieee = Dot15d4(ieee802_secfrag)
    #ieee.show2()

    ieee802_iphc = "\x41\xcc\xb5\xcd\xab\x16\x15\x14\xfe\xff\x13\x12\x02\x55\x44\x33\xfe\xff\x22\x11\x02\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xfa\x00\x00\x01\xf7\x89\xf3\x02\x5f\x50\x18\x04\xc4\x48\x28\x00\x00\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x74\x79\x70\x65\x3a\x20\x74\x65\x78\x74\x2f\x63\x73\x73\x0d\x0a\x0d\x0a\xc1\x16"

    #ieee = Dot15d4(ieee802_iphc)
    #ieee.show2()

    #from scapy.utils import hexdump

    #hexdump(ieee)

    #print
    #print
    #p = AuxiliarySecurityHeaderIEEE802_15_4("\x04\x05\x00\x00\x00")
    #p.show2()

    #print
    #print

    #p = AuxiliarySecurityHeaderIEEE802_15_4("\x18\x05\x00\x00\x00\xff\xee\xdd\xcc\xbb\xaa\x00\x99\x88\x77")
    #p.show2()
    
