## Copyright (C) Cesar A. Bernardini <mesarpe@gmail.com>
## Intern at INRIA Grand Nancy Est
## This program is published under a GPLv2 license
"""

This implementation follows the next documents:
    * Transmission of IPv6 Packets over IEEE 802.15.4 Networks
    * Compression Format for IPv6 Datagrams in Low Power and Lossy
      networks (6LoWPAN): draft-ietf-6lowpan-hc-15
    * RFC 4291

6LoWPAN Protocol Stack
======================

                            |-----------------------|
Application                 | Application Protocols |
                            |-----------------------|
Transport                   |   UDP      |   TCP    |
                            |-----------------------|
Network                     |          IPv6         | (Only IPv6)
                            |-----------------------|
                            |         LoWPAN        | (in the middle between network and data link layer)
                            |-----------------------|
Data Link Layer             |   IEEE 802.15.4 MAC   |
                            |-----------------------|
Physical                    |   IEEE 802.15.4 PHY   |
                            |-----------------------|

The Internet Control Message protocol v6 (ICMPv6) is used for control
messaging.

Adaptation between full IPv6 and the LoWPAN format is performed by routers at
the edge of 6LoWPAN islands.

A LoWPAN support addressing; a direct mapping between the link-layer address
and the IPv6 address is used for achieving compression.



Known Issues:
    * Problem resolving IPv6 addresses source and address
        * Not implemented yet, source and address depending on the
          underlayer (Dot15d4)
    * Broadcast, Mesh packets have never been tested.

"""

from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, ByteField, XBitField, LEShortField, LEIntField, StrLenField, HiddenField, BitEnumField, Field, ShortField, BitFieldLenField, XShortField

from scapy.layers.inet6 import IPv6, IP6Field
from scapy.utils6 import in6_or, in6_and, in6_xor

from dot15d4 import Dot15d4, Dot15d4Data, Dot15d4FCS
from scapy.utils import lhex

from scapy.fields import Field, ConditionalField, FieldLenField
from scapy.route6 import *

import socket
import struct

class IP6FieldLenField(IP6Field):
    def __init__(self, name, default, size, length_of=None, count_of=None, adjust=lambda pkt,x:x):
        IP6Field.__init__(self, name, default)
        self.length_of=length_of
        self.count_of=count_of
        self.adjust=adjust
    def getfield(self, pkt, s):
        l = self.length_of(pkt)
        if l <= 0:
            return s,""
        return s[l:], self.m2i(pkt,s[:l])

class SixLoWPANAddrField(Field):
    """Special field to store 6LoWPAN addresses

    6LoWPAN Addresses have a variable length depending on other parameters.
    This special field allows to save them, and encode/decode no matter which
    encoding parameters they have.
    """
    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        self.adjust=adjust
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        return lhex(self.i2h(pkt,x))
    def h2i(self, pkt, x):
        """Convert human value to internal value"""
        if type(x) == int:
            return 0
        elif type(x) == str:
            print "h2i", len(x), x
            return Field.h2i(self, pkt, x)
    def i2h(self, pkt, x):
        """Convert internal value to human value"""
        print "I2H"
        Field.i2h(self, pkt, x)
    def m2i(self, pkt, x):
        """Convert machine value to internal value"""
        print "m2i"
        return Field.m2i(self, pkt, x)
    def i2m(self, pkt, x):
        """Convert internal value to machine value"""
        print "I2M"
        return Field.i2m(self, pkt, x)
    def any2i(self, pkt, x):
        """Try to understand the most input values possible and make an internal value from them"""
        return self.h2i(pkt, x)
    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.length_of(pkt) == 8:
            return s + struct.pack(self.fmt[0]+"B", val)
        if self.length_of(pkt) == 16:
            return s + struct.pack(self.fmt[0]+"H", val)
        if self.length_of(pkt) == 32:
            return s + struct.pack(self.fmt[0]+"2H", val) #TODO: fix!
        if self.length_of(pkt) == 48:
            return s + struct.pack(self.fmt[0]+"3H", val) #TODO: fix!
        elif self.length_of(pkt) == 64:
            return s + struct.pack(self.fmt[0]+"Q", val)
        elif self.length_of(pkt) == 128:
            #TODO: FIX THE PACKING!!
            return s + struct.pack(self.fmt[0]+"16s", str(val))
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
            print "TUU"
            return s[16:], self.m2i(pkt, struct.unpack(self.fmt[0]+"16s", s[:16])[0])



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
        
###############################################################################
# Fragmentation
#
# Section 5.3 - September 2007
###############################################################################

class LoWPANFragmentationFirst(Packet):
    name = "6LoWPAN First Fragmentation Packet"
    fields_desc = [
        HiddenField(BitField("__reserved", 0x18, 5)),
        BitField("__datagramSize", 0x0, 11),
        XShortField("__datagramTag", 0x0),
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
    #TODO: DOUBT! Apparently, this is not longer used in the draft
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

    #TODO: constructs the payload!

    def guess_payload_class(self, payload):
        return UDP(payload)

IPHC_DEFAULT_VERSION = 6
IPHC_DEFAULT_TF = 0
IPHC_DEFAULT_FL = 0

def source_addr_mode(pkt):
    """source_addr_mode

    This function depending on the arguments returns the amount of bits to be
    used by the source address.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.sac == 0x0:
        if pkt.sam == 0x0:      return 128
        elif pkt.sam == 0x1:    return 64
        elif pkt.sam == 0x2:    return 16
        elif pkt.sam == 0x3:    return 0
    else:
        if pkt.sam == 0x0:      return 0
        elif pkt.sam == 0x1:    return 64
        elif pkt.sam == 0x2:    return 16
        elif pkt.sam == 0x3:    return 0

def source_addr_mode2(pkt):
    """source_addr_mode

    This function depending on the arguments returns the amount of bits to be
    used by the source address.

    Keyword arguments:
    pkt -- packet object instance
    """
    print "LA USAMOS"
    if pkt.sac == 0x0:
        if pkt.sam == 0x0:      return 16
        elif pkt.sam == 0x1:    return 8
        elif pkt.sam == 0x2:    return 2
        elif pkt.sam == 0x3:    return 0
    else:
        if pkt.sam == 0x0:      return 0
        elif pkt.sam == 0x1:    return 8
        elif pkt.sam == 0x2:    return 2
        elif pkt.sam == 0x3:    return 0

def destiny_addr_mode(pkt):
    """destiny_addr_mode

    This function depending on the arguments returns the amount of bits to be
    used by the destiny address.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.m == 0 and pkt.dac == 0:
        if pkt.dam == 0x0:      return 16
        elif pkt.dam == 0x1:    return 8
        elif pkt.dam == 0x2:    return 2
        else:                   return 0
    elif pkt.m == 0 and pkt.dac == 1:
        if pkt.dam == 0x0:      raise Exception('reserved')
        elif pkt.dam == 0x1:    return 8
        elif pkt.dam == 0x2:    return 2
        else:                   return 0
    elif pkt.m == 1 and pkt.dac == 0:
        if pkt.dam == 0x0:      return 16
        elif pkt.dam == 0x1:    return 6
        elif pkt.dam == 0x2:    return 4
        elif pkt.dam == 0x3:    return 1
    elif pkt.m == 1 and pkt.dac == 1:
        if pkt.dam == 0x0:      return 6
        elif pkt.dam == 0x1:    raise Exception('reserved')
        elif pkt.dam == 0x2:    raise Exception('reserved')
        elif pkt.dam == 0x3:    raise Exception('reserved')

def pad_trafficclass(pkt):
    """
    This function depending on the arguments returns the amount of bits to be
    used by the padding of the traffic class.

    Keyword arguments:
    pkt -- packet object instance
    """
    print "VAL", pkt.tf
    if pkt.tf == 0x0:          return 4
    elif pkt.tf == 0x1:        return 2
    elif pkt.tf == 0x2:        return 0
    else:                       return 0

def flowlabel_len(pkt):
    """
    This function depending on the arguments returns the amount of bits to be
    used by the padding of the traffic class.

    Keyword arguments:
    pkt -- packet object instance
    """
    if pkt.tf == 0x0:          return 20
    elif pkt.tf == 0x1:        return 20
    else:                       return 0

class LoWPAN_IPHC(Packet):
    """6LoWPAN IPv6 header compressed packets

    It follows the implementation of draft-ietf-6lowpan-hc-15.
    """
    # the LOWPAN_IPHC encoding utilizes 13 bits, 5 dispatch type
    name = "LoWPAN IP Header Compression Packet"
    fields_desc = [
        #dispatch
        HiddenField(BitField("__reserved", 0x03, 3)),
        BitField("tf", 0x0, 2),
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
            BitField("tc_ecn", 0x0, 2),
            lambda pkt: pkt.tf != 0x03
        ),
        ConditionalField(
            BitField("tc_dscp", 0x0, 6),
            lambda pkt: pkt.tf in [0x0, 0x2]
        ),
        ConditionalField(
            HiddenField(BitFieldLenField("__padd", 0x0, 4, length_of = pad_trafficclass)), #
            lambda pkt: pkt.tf in [0x0, 0x1]
        ),
        ConditionalField(
            BitField("fl_flowLabel", 0x0, 20), #
            lambda pkt: pkt.tf in [0x0, 0x1]
        ),

        #NH
        ConditionalField(
            ByteField("_nhField", 0x0), #
            lambda pkt: not pkt.nh
        ),
        #TODO: next header is using LOWPAN_NHC when pkt.__nh == 0x1
        #HLIM: Hop Limit: if it's 0
        ConditionalField(
            ByteField("_hopLimit", 0x0),
            lambda pkt: pkt.hlim == 0x0
        ),
        ConditionalField(
            IP6FieldLenField("sourceAddr", "::", 0, length_of=source_addr_mode2),
            #SixLoWPANAddrField("sourceAddr", 0x0, length_of=source_addr_mode),
            lambda pkt: source_addr_mode(pkt) != 0
        ),
        ConditionalField(
            IP6FieldLenField("destinyAddr", "::", 0, length_of=destiny_addr_mode), #problem when it's 0
            lambda pkt: destiny_addr_mode(pkt) != 0 
        ),
    ]

    def post_disect(self, data):
        """disect the IPv6 package compressed into this IPHC packet.

        The packet payload needs to be decompressed and depending on the
        arguments, several convertions should be done.
        """
        packet = IPv6(self.payload)
        packet.version = IPHC_DEFAULT_VERSION
        packet.tc, packet.fl = self._getTrafficClassAndFlowLabel()
        #TODO: Payload length can be inferred from lower layers from either the
        #6LoWPAN Fragmentation header or the IEEE802.15.4 header
        #packet.plen = 0
        packet.nh = self._getNextHeader()
        packet.hlim = self._hopLimit
        packet.src = self._getSourceAddr2()
        packet.dst= self._getDestinyAddr()
        return str(packet)
        

    def guess_payload_class(self, payload):
        return IPv6

    def do_build(self):
        assert type(self.payload) == IPv6
        self.sourceAddr = self.payload.src
        self.destinyAddr = self.payload.dst
        #print "B", self.sourceAddr
        #self.destinyAddr = ipv6_packet.dst
        #payload = self.payload.payload
        return Packet.do_build(self)
    
    def do_build_payload(self):
        print "do_build_payload"
        #self.payload = self.payload.payload
        return Packet.do_build_payload(self)
    def post_build(self, pkt, pay):
        # remove IPv6 header
        return pkt + pay[40:]
        
    def _getSourceAddr(self, packet_ipv6): #TODO: implement!!
        """Builds the source IPv6 address for the IPv6 compressed packet. """
        link_local_prefix = "fe80:0000:0000:0000:0000:0000:0000:0000"
        
        if self.sac == 0:
            if self.sam == 0x0: #128 bits full-addr
                return self.sourceAddr
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
                underlayer = self.underlayer
                while underlayer != None and isinstance(underlayer, Dot15d4Data):
                    underlayer = underlayer.underlayer
                if underlayer.adjust(underlayer, None) == 2:    tmp_ip = "\x00"*14 + underlayer.src_addr
                elif underlayer.adjust(underlayer, None) == 8:  tmp_ip = "\x00"*8 + underlayer.src_addr #TODO: aplicarle in6_xor con la mascara para apagar el bit 7 segun RFC 4291, appendix A
                
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
        elif self.sac == 0x1:
            
            if self.sam == 0x3:
                underlayer = self
                while not isinstance(underlayer, Dot15d4Data):
                    underlayer = underlayer.underlayer

                tmp_ip = "\x00"*8 + struct.pack(">Q", underlayer.src_addr)
                tmp_ip = in6_xor(tmp_ip, "\x00"*8 + "\x02" + "\x00"*7)
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
                # 0 bits. The address is fully elided and is derived using context information and the encapsulating header.
                pass
        raise Exception('Unimplemented')
    def _getDestinyAddr(self): #TODO: implement!!
        """Builds the destiny IPv6 address for the IPv6 compressed packet. """
        link_local_prefix = "fe80:0000:0000:0000:0000:0000:0000:0000"
        prefix_64 =         "0000:0000:0000:0000:0000:00ff:fe00:0000" #0000:00ff:fe00:XXXX
        
        if self.m == 0 and self.dac == 0:
            if self.dam == 0x0: #128 bits full-addr
                return self._destinyAddr
            elif self.sam == 0x1:
                tmp_ip = "\x00"*8 + struct.pack("4H", self._destinyAddr)
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
            elif self.sam == 0x2:
                tmp_ip = "\x00"*8 + "\x00"*6 + struct.pack("H", self._destinyAddr)
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, prefix_64))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
            elif self.sam == 0x3:
                underlayer = self.underlayer
                while underlayer != None and isinstance(underlayer, Dot15d4Data):
                    underlayer = underlayer.underlayer
                if underlayer.adjust(underlayer, None) == 2:    tmp_ip = "\x00"*14 + underlayer.dest_addr
                elif underlayer.adjust(underlayer, None) == 8:  tmp_ip = "\x00"*8 + underlayer.dest_addr
                
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
        elif self.m == 0 and self.dac == 1:
            if self.dam == 0:
                raise Exception('reserved address')
            elif self.dam == 0x2:
                tmp_ip = "\x00"*8 + "\x00"*6 + struct.pack("<H", self._destinyAddr)
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, link_local_prefix))
                tmp_ip = in6_or(tmp_ip, socket.inet_pton(socket.AF_INET6, prefix_64))
                return socket.inet_ntop(socket.AF_INET6, tmp_ip)
                
        raise Exception('unimplmemented')

    def _getTrafficClassAndFlowLabel(self):
        """Page 6, draft feb 2011 """
        if self.tf == 0x0:
            return (self.tc_ecn << 6) + self.tc_dscp, self.fl_flowlabel
        elif self.tf == 0x1:
            return (self.tc_ecn << 6), self.fl_flowlabel
        elif self.tf == 0x2:
            return (self.tc_ecn << 6) + self.tc_dscp, 0
        else:
            return 0, 0
    
    def _getNextHeader(self):
        #TODO: Finish it!!
        """Next Header!!!!"""
        if self.nh == 0x0:
            return self._nhField
        else:
            raise Exception('Unimplemented')

    def _getHopLimit(self):
        """Returns the hop limit value.Page 7. draft Feb 2011"""
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
        """Depending on the payload content, the frame type we should interpretate"""
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
bind_layers( LoWPANMesh,        LoWPANFragmentationFirst,           )
bind_layers( LoWPANMesh,        LoWPANFragmentationSubsequent,      )
bind_layers( LoWPANMesh,        LoWPANHC1CompressedIPv6,            )
#TODO: I have several doubts about the Broadcast LoWPAN
#bind_layers( LoWPANBroadcast,   LoWPANHC1CompressedIPv6,            )
#bind_layers( SixLoWPAN,         LoWPANBroadcast,                    )
#bind_layers( LoWPANMesh,        LoWPANBroadcast,                    )
#bind_layers( LoWPANBroadcast,   LoWPANFragmentationFirst,           )
#bind_layers( LoWPANBroadcast,   LoWPANFragmentationSubsequent,      )
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

    #lowpan_iphc = "\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xf9\x00\x00\x02\x12\x77\x9b\x1a\x9a\x50\x18\x04\xc4\x12\xd5\x00\x00\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x34\x2e\x30\x31\x20\x54\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x61\x6c\x2f\x2f\x45\x4e\x22\x20\x22\x68\x74\x74\x70"

    #lowpan_frag_iphc = LoWPAN_IPHC(lowpan_iphc)
    #lowpan_frag_iphc.show2()
    from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
    p = LoWPAN_IPHC(tf=0x0, fl_flowLabel=0x8, _nhField=0x3a, _hopLimit=64)/IPv6(dst="aaaa::11:22ff:fe33:4455", src="aaaa::1")/ICMPv6EchoRequest()
    p.show2()
    print hexdump(p)

    #q = LoWPAN_IPHC(tf=0x0)
    #print hexdump(q)

    #print
    #print

    #from scapy.layers.inet6 import IPv6
    #ip6 = IPv6(src="2002:db8::11:22ff:fe33:4455", dst="2002:db8::ff:fe00:1")
    #from scapy.utils import hexdump
    #hexdump(ip6)

    # SAMPLE PACKETSS!!! IEEE 802.15.4 containing   
    
    ieee802_firstfrag = "\x41\xcc\xa3\xcd\xab\x16\x15\x14\xfe\xff\x13\x12\x02\x55\x44\x33\xfe\xff\x22\x11\x02\xc3\x42\x00\x23\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xf9\x00\x00\x02\x12\x77\x9b\x1a\x9a\x50\x18\x04\xc4\x12\xd5\x00\x00\x3c\x21\x44\x4f\x43\x54\x59\x50\x45\x20\x48\x54\x4d\x4c\x20\x50\x55\x42\x4c\x49\x43\x20\x22\x2d\x2f\x2f\x57\x33\x43\x2f\x2f\x44\x54\x44\x20\x48\x54\x4d\x4c\x20\x34\x2e\x30\x31\x20\x54\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x61\x6c\x2f\x2f\x45\x4e\x22\x20\x22\x68\x74\x74\x70\x39\xb5"

    #ieee = Dot15d4FCS(ieee802_firstfrag)
    #ieee.show2()
    #send(ieee)

    ieee802_secfrag = "\x41\xcc\x4d\xcd\xab\x55\x44\x33\xfe\xff\x22\x11\x02\x16\x15\x14\xfe\xff\x13\x12\x02\xe2\x39\x00\x17\x10\x69\x76\x65\x0d\x0a\x52\x65\x66\x65\x72\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x5b\x61\x61\x61\x61\x3a\x3a\x31\x31\x3a\x32\x32\x66\x66\x3a\x66\x65\x33\x33\x3a\x34\x34\x35\x35\x5d\x2f\x73\x65\x6e\x73\x6f\x72\x2e\x73\x68\x74\x6d\x6c\x0d\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x55\x3b\x20\x4c\x69\x66\xac"

    #ieee = Dot15d4FCS(ieee802_secfrag)
    #ieee.show2()

    ieee802_iphc = "\x41\xcc\xb5\xcd\xab\x16\x15\x14\xfe\xff\x13\x12\x02\x55\x44\x33\xfe\xff\x22\x11\x02\x78\xf6\x00\x06\x80\x00\x01\x00\x50\xc4\xfa\x00\x00\x01\xf7\x89\xf3\x02\x5f\x50\x18\x04\xc4\x48\x28\x00\x00\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x74\x79\x70\x65\x3a\x20\x74\x65\x78\x74\x2f\x63\x73\x73\x0d\x0a\x0d\x0a\xc1\x16"

    #ieee = Dot15d4FCS(ieee802_iphc)
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
    
