## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
ISAKMP (Internet Security Association and Key Management Protocol).
"""

import struct
from scapy.packet import *
from scapy.fields import *
from scapy.ansmachine import *
from scapy.layers.inet import IP,UDP
from scapy.sendrecv import sr
from scapy.layers.inet6 import IP6Field


# see http://www.iana.org/assignments/ipsec-registry for details
ISAKMPAttributeTypes= { "Encryption":    (1, { "DES-CBC"  : 1,
                                                "IDEA-CBC" : 2,
                                                "Blowfish-CBC" : 3,
                                                "RC5-R16-B64-CBC" : 4,
                                                "3DES-CBC" : 5, 
                                                "CAST-CBC" : 6, 
                                                "AES-CBC" : 7, 
                                                "CAMELLIA-CBC" : 8, }, 0),
                         "Hash":          (2, { "MD5": 1,
                                                "SHA": 2,
                                                "Tiger": 3,
                                                "SHA2-256": 4,
                                                "SHA2-384": 5,
                                                "SHA2-512": 6,}, 0),
                         "Authentication":(3, { "PSK": 1, 
                                                "DSS": 2,
                                                "RSA Sig": 3,
                                                "RSA Encryption": 4,
                                                "RSA Encryption Revised": 5,
                                                "ElGamal Encryption": 6,
                                                "ElGamal Encryption Revised": 7,
                                                "ECDSA Sig": 8,
                                                "HybridInitRSA": 64221,
                                                "HybridRespRSA": 64222,
                                                "HybridInitDSS": 64223,
                                                "HybridRespDSS": 64224,
                                                "XAUTHInitPreShared": 65001,
                                                "XAUTHRespPreShared": 65002,
                                                "XAUTHInitDSS": 65003,
                                                "XAUTHRespDSS": 65004,
                                                "XAUTHInitRSA": 65005,
                                                "XAUTHRespRSA": 65006,
                                                "XAUTHInitRSAEncryption": 65007,
                                                "XAUTHRespRSAEncryption": 65008,
                                                "XAUTHInitRSARevisedEncryption": 65009,
                                                "XAUTHRespRSARevisedEncryptio": 65010, }, 0),
                         "GroupDesc":     (4, { "768MODPgr"  : 1,
                                                "1024MODPgr" : 2, 
                                                "EC2Ngr155"  : 3,
                                                "EC2Ngr185"  : 4,
                                                "1536MODPgr" : 5, 
                                                "2048MODPgr" : 14, 
                                                "3072MODPgr" : 15, 
                                                "4096MODPgr" : 16, 
                                                "6144MODPgr" : 17, 
                                                "8192MODPgr" : 18, }, 0),
                         "GroupType":      (5,  {"MODP":       1,
                                                 "ECP":        2,
                                                 "EC2N":       3}, 0),
                         "GroupPrime":     (6,  {}, 1),
                         "GroupGenerator1":(7,  {}, 1),
                         "GroupGenerator2":(8,  {}, 1),
                         "GroupCurveA":    (9,  {}, 1),
                         "GroupCurveB":    (10, {}, 1),
                         "LifeType":       (11, {"Seconds":     1,
                                                 "Kilobytes":   2,  }, 0),
                         "LifeDuration":   (12, {}, 1),
                         "PRF":            (13, {}, 0),
                         "KeyLength":      (14, {}, 0),
                         "FieldSize":      (15, {}, 0),
                         "GroupOrder":     (16, {}, 1),
                         }

# the name 'ISAKMPTransformTypes' is actually a misnomer (since the table 
# holds info for all ISAKMP Attribute types, not just transforms, but we'll 
# keep it for backwards compatibility... for now at least
ISAKMPTransformTypes = ISAKMPAttributeTypes

ISAKMPTransformNum = {}
for n in ISAKMPTransformTypes:
    val = ISAKMPTransformTypes[n]
    tmp = {}
    for e in val[1]:
        tmp[val[1][e]] = e
    ISAKMPTransformNum[val[0]] = (n,tmp, val[2])
del(n)
del(e)
del(tmp)
del(val)


class ISAKMPTransformSetField(StrLenField):
    islist=1
    def type2num(self, (typ,val)):
        type_val,enc_dict,tlv = ISAKMPTransformTypes.get(typ, (typ,{},0))
        val = enc_dict.get(val, val)
        s = ""
        if (val & ~0xffff):
            if not tlv:
                warning("%r should not be TLV but is too big => using TLV encoding" % typ)
            n = 0
            while val:
                s = chr(val&0xff)+s
                val >>= 8
                n += 1
            val = n
        else:
            type_val |= 0x8000
        return struct.pack("!HH",type_val, val)+s
    def num2type(self, typ, enc):
        val = ISAKMPTransformNum.get(typ,(typ,{}))
        enc = val[1].get(enc,enc)
        return (val[0],enc)
    def i2m(self, pkt, i):
        if i is None:
            return ""
        i = map(self.type2num, i)
        return "".join(i)
    def m2i(self, pkt, m):
        # I try to ensure that we don't read off the end of our packet based
        # on bad length fields we're provided in the packet. There are still
        # conditions where struct.unpack() may not get enough packet data, but
        # worst case that should result in broken attributes (which would
        # be expected). (wam)
        lst = []
        while len(m) >= 4:
            trans_type, = struct.unpack("!H", m[:2])
            is_tlv = not (trans_type & 0x8000)
            if is_tlv:
                # We should probably check to make sure the attribute type we
                # are looking at is allowed to have a TLV format and issue a 
                # warning if we're given an TLV on a basic attribute.
                value_len, = struct.unpack("!H", m[2:4])
                if value_len+4 > len(m):
                    warning("Bad length for ISAKMP tranform type=%#6x" % trans_type)
                value = m[4:4+value_len]
                value = reduce(lambda x,y: (x<<8L)|y, struct.unpack("!%s" % ("B"*len(value),), value),0)
            else:
                trans_type &= 0x7fff
                value_len=0
                value, = struct.unpack("!H", m[2:4])
            m=m[4+value_len:]
            lst.append(self.num2type(trans_type, value))
        if len(m) > 0:
            warning("Extra bytes after ISAKMP transform dissection [%r]" % m)
        return lst


ISAKMP_payload_type = ["None","SA","Proposal","Transform","KE","ID","CERT","CR","Hash",
                       "SIG","Nonce","Notification","Delete","VendorID",
                       "reserved","SAK","SAT","KD","SEQ","POP","NAT_D","NAT_OA"]

ISAKMP_exchange_type = {  0:"None",
                          1:"base",
                          2:"identity prot.",
                          3:"auth only",
                          4:"aggressive",
                          5:"info",
                         32:"quick mode",
                         33:"new group mode" }


class ISAKMP(Packet): # rfc2408
    name = "ISAKMP"
    fields_desc = [
        StrFixedLenField("init_cookie","",8),
        StrFixedLenField("resp_cookie","",8),
        ByteEnumField("next_payload",0,ISAKMP_payload_type),
        XByteField("version",0x10),
        ByteEnumField("exch_type",0,ISAKMP_exchange_type),
        FlagsField("flags",0, 8, ["encryption","commit","auth_only","res3","res4","res5","res6","res7"]),
        IntField("id",0),
        IntField("length",None)
        ]

    def guess_payload_class(self, payload):
        if self.flags & 1:
            return Raw # encrypted payload
        else:
            return Packet.guess_payload_class(self, payload)
    def default_payload_class(self, payload):
        return ISAKMP_payload

    def answers(self, other):
        if isinstance(other, ISAKMP):
            if other.init_cookie == self.init_cookie:
                return 1
        return 0
    def post_build(self, p, pay):
        p += pay
        if self.length is None:
            p = p[:24]+struct.pack("!I",len(p))+p[28:]
        return p
       

# http://www.iana.org/assignments/isakmp-registry
ISAKMP_proto_ID = { 1: "PROTO_ISAKMP",
                    2: "PROTO_IPSEC_AH",
                    3: "PROTO_IPSEC_ESP",
                    4: "PROTO_IPCOMP",
                    5: "PROTO_GIGABEAM_RADIO" }

# http://www.iana.org/assignments/isakmp-registry
ISAKMP_ID_type = {  1: "IPV4_ADDR",
                    2: "FQDN",
                    3: "USER_FQDN",
                    4: "IPV4_ADDR_SUBNET",
                    5: "IPV6_ADDR",
                    6: "IPV6_ADDR_SUBNET",
                    7: "IPV4_ADDR_RANGE",
                    8: "IPV6_ADDR_RANGE",
                    9: "DER_ASN1_DN",
                   10: "DER_ASN1_GN",
                   11: "KEY_ID",
                   12: "LIST" }

# RFC2408, http://www.iana.org/assignments/ikev2-parameters
ISAKMP_cert_encoding = {  0: "NONE",
                          1: "PKCS #7 wrapped X.509 certificate",
                          2: "PGP Certificate",
                          3: "DNS Signed Key",
                          4: "X.509 Certificate - Signature",
                          5: "X.509 Certificate - Key Exchange",
                          6: "Kerberos Token",
                          7: "Certificate Revocation List (CRL)",
                          8: "Authority Revocation List (ARL)",
                          9: "SPKI Certificate",
                         10: "X.509 Certificate - Attribute",
                         11: "Raw RSA Key",
                         12: "Hash and URL of X.509 certificate",
                         13: "Hash and URL of X.509 bundle",
                         14: "OCSP Content" }

# http://www.iana.org/assignments/isakmp-registry
ISAKMP_DOI = { 0: "ISAKMP",
               1: "IPSEC",
               2: "GDOI" }

# RFC2408, http://www.iana.org/assignments/isakmp-registry
ISAKMP_notify_message = {     1: "INVALID-PAYLOAD-TYPE",
                              2: "DOI-NOT-SUPPORTED",
                              3: "SITUATION-NOT-SUPPORTED",
                              4: "INVALID-COOKIE",
                              5: "INVALID-MAJOR-VERSION",
                              6: "INVALID-MINOR-VERSION",
                              7: "INVALID-EXCHANGE-TYPE",
                              8: "INVALID-FLAGS",
                              9: "INVALID-MESSAGE-ID",
                             10: "INVALID-PROTOCOL-ID",
                             11: "INVALID-SPI",
                             12: "INVALID-TRANSFORM-ID",
                             13: "ATTRIBUTES-NOT-SUPPORTED",
                             14: "NO-PROPOSAL-CHOSEN",
                             15: "BAD-PROPOSAL-SYNTAX",
                             16: "PAYLOAD-MALFORMED",
                             17: "INVALID-KEY-INFORMATION",
                             18: "INVALID-ID-INFORMATION",
                             19: "INVALID-CERT-ENCODING",
                             20: "INVALID-CERTIFICATE",
                             21: "CERT-TYPE-UNSUPPORTED",
                             22: "INVALID-CERT-AUTHORITY",
                             23: "INVALID-HASH-INFORMATION",
                             24: "AUTHENTICATION-FAILED",
                             25: "INVALID-SIGNATURE",
                             26: "ADDRESS-NOTIFICATION",
                             27: "NOTIFY-SA-LIFETIME",
                             28: "CERTIFICATE-UNAVAILABLE",
                             29: "UNSUPPORTED-EXCHANGE-TYPE",
                             30: "UNEQUAL-PAYLOAD-LENGTHS",
                          24576: "RESPONDER-LIFETIME",
                          24577: "REPLAY-STATUS",
                          24578: "INITIAL-CONTACT" }


class _ISAKMP_payload_HDR(Packet):
    name = "Abstract ISAKMP payload header"
    fields_desc = [
        ByteEnumField("next_payload",0,ISAKMP_payload_type),
        ByteField("res",0),
        ShortField("length",None),
        ]


class ISAKMP_payload(Packet):
    name = "ISAKMP unknown payload"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("load","",length_from=lambda x:x.length-4),
        ]
    def default_payload_class(self, payload):
        return ISAKMP_payload
    def post_build(self, p, pay):
        if self.length is None:
            l = len(p)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        p += pay
        return p


class ISAKMP_payload_Transform(ISAKMP_payload):
    name = "ISAKMP Transform"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteField("num",None),
        ByteEnumField("id",1,{1:"KEY_IKE"}),
        ShortField("res2",0),
        ISAKMPTransformSetField("transforms",None,length_from=lambda x:x.length-8)
        ]


        
class ISAKMP_payload_Proposal(ISAKMP_payload):
    name = "ISAKMP Proposal"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteField("proposal",1),
        ByteEnumField("proto",1,ISAKMP_proto_ID),
        FieldLenField("SPIsize",None,"SPI","B"),
        ByteField("trans_nb",None),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        PacketLenField("trans",Raw(),ISAKMP_payload_Transform,length_from=lambda x:x.length-8),
        ]
    def post_build(self, p, pay):
        if self.length is None:
            l = len(p)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        if self.trans_nb is None:
            num = 0
            t = self.trans
            while t:
                num += 1
                t = t.payload
            p = p[:7]+chr(num&0xff)+p[8:]
        p += pay
        return p


class ISAKMP_payload_VendorID(ISAKMP_payload):
    name = "ISAKMP Vendor ID"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("vendorID","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_SA(ISAKMP_payload):
    name = "ISAKMP SA"
    fields_desc = [
        _ISAKMP_payload_HDR,
        IntEnumField("DOI",1,ISAKMP_DOI),
        FlagsField("situation",1,32,["SIT_IDENTITY_ONLY","SIT_SECRECY","SIT_INTEGRITY"]),
        PacketLenField("prop",Raw(),ISAKMP_payload_Proposal,length_from=lambda x:x.length-12),
        ]

class ISAKMP_payload_Nonce(ISAKMP_payload):
    name = "ISAKMP Nonce"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("nonce","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_KE(ISAKMP_payload):
    name = "ISAKMP Key Exchange"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("keyexch","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_ID(ISAKMP_payload):
    name = "ISAKMP Identification"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("IDtype",1,ISAKMP_ID_type),
        ByteEnumField("proto",0,{0:"Unused"}),
        ShortEnumField("port",0,{0:"Unused"}),
        ConditionalField(IPField("addr4","127.0.0.1"),
                         lambda pkt:pkt.IDtype in [1,4,7]),
        ConditionalField(IPField("addr4sub","255.255.255.0"),
                         lambda pkt:pkt.IDtype == 4),
        ConditionalField(IPField("addr4end","127.0.0.1"),
                         lambda pkt:pkt.IDtype == 7),
        ConditionalField(IP6Field("addr6","::1"),
                         lambda pkt:pkt.IDtype in [5,6,8]),
        ConditionalField(IP6Field("addr6sub","ffff:ffff:ffff:ffff::"),
                         lambda pkt:pkt.IDtype == 6),
        ConditionalField(IP6Field("addr6end","::1"),
                         lambda pkt:pkt.IDtype == 8),
        ConditionalField(StrLenField("domain","",length_from=lambda x:x.length-8),
                         lambda pkt:pkt.IDtype in [2,3]),
        ConditionalField(StrLenField("load","",length_from=lambda x:x.length-8),
                         lambda pkt:pkt.IDtype in [9,10,11] or pkt.IDtype > 12),
        #ConditionalField(PacketListField("IDlist",... # self-reference, can't define here
        ]
ISAKMP_payload_ID.fields_desc.append(
    ConditionalField(PacketListField("IDlist",[],ISAKMP_payload_ID,length_from=lambda x:x.length-8),
                     lambda pkt:pkt.IDtype == 12)) # class must be defined first

class ISAKMP_payload_Hash(ISAKMP_payload):
    name = "ISAKMP Hash"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("hash","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_CERT(ISAKMP_payload):
    name = "ISAKMP Certificate"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("encoding",0,ISAKMP_cert_encoding),
        StrLenField("cert","",length_from=lambda x:x.length-5),
        ]

class ISAKMP_payload_CR(ISAKMP_payload_CERT):
    name = "ISAKMP Certificate Request"

class ISAKMP_payload_SIG(ISAKMP_payload):
    name = "ISAKMP Signature"
    fields_desc = [
        _ISAKMP_payload_HDR,
        StrLenField("sig","",length_from=lambda x:x.length-4),
        ]

class ISAKMP_payload_Notification(ISAKMP_payload):
    name = "ISAKMP Notification"
    fields_desc = [
        _ISAKMP_payload_HDR,
        IntEnumField("DOI",0,ISAKMP_DOI),
        ByteEnumField("proto",1,ISAKMP_proto_ID),
        FieldLenField("SPIsize",None,"SPI","B"),
        ShortEnumField("message",0,ISAKMP_notify_message),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        StrLenField("data","",length_from=lambda x:x.length-12),
        ]

class ISAKMP_payload_Delete(ISAKMP_payload):
    name = "ISAKMP Delete"
    fields_desc = [
        _ISAKMP_payload_HDR,
        IntEnumField("DOI",0,ISAKMP_DOI),
        ByteEnumField("proto",1,ISAKMP_proto_ID),
        ByteField("SPIsize",16),
        FieldLenField("SPI_nb",None,count_of="SPIs",fmt="H"),
        FieldListField("SPIs", [], StrLenField("SPI","",length_from=lambda x:x.SPIsize),
                       count_from=lambda x:x.SPI_nb)
        ]

class ISAKMP_payload_SAK(ISAKMP_payload):
    name = "ISAKMP SA KEK"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("proto",0,IP_PROTOS),
        ByteEnumField("stype",1,ISAKMP_ID_type),
        ShortEnumField("sport",80,TCP_SERVICES),
        FieldLenField("slen",None,"sdata","B"),
        StrLenField("sdata","",length_from=lambda x:x.slen),
        ByteEnumField("dtype",1,ISAKMP_ID_type), #XXX: is there a "DST ID Prot" field?
        ShortEnumField("dport",80,TCP_SERVICES),
        FieldLenField("dlen",None,"ddata","B"),
        StrLenField("ddata","",length_from=lambda x:x.dlen),
        StrFixedLenField("SPI","\x00"*16,16),
        ShortEnumField("pop_algo",0,{1:"RSA",2:"DSS",3:"ECDSS"}),
        ShortField("pop_key_len",0), #XXX: FieldLenField?
        StrLenField("kek","",length_from=lambda x:x.length-33),
        ]

class ISAKMP_payload_SAT(ISAKMP_payload):
    name = "ISAKMP SA TEK"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("id",1,{1:"IPSEC_ESP"}),
        ByteEnumField("proto",0,IP_PROTOS),
        ByteEnumField("stype",1,ISAKMP_ID_type),
        ShortEnumField("sport",80,TCP_SERVICES),
        FieldLenField("slen",None,"sdata","B"),
        StrLenField("sdata","",length_from=lambda x:x.slen),
        ByteEnumField("dtype",1,ISAKMP_ID_type), #XXX: is there a "DST ID Prot" field?
        ShortEnumField("dport",80,TCP_SERVICES),
        FieldLenField("dlen",None,"ddata","B"),
        StrLenField("ddata","",length_from=lambda x:x.dlen),
        ByteEnumField("trans_id",1,{1:"KEY_IKE"}),
        StrFixedLenField("SPI","\x00"*4,4),
        StrLenField("attrs","",length_from=lambda x:x.length-19),
        ]

class ISAKMP_key(Packet):
    name = "ISAKMP Key Packet for KD"
    fields_desc = [
        ByteEnumField("type",0,{1:"TEK",2:"KEK",3:"LKH"}),
        ByteField("res",0),
        ShortField("length",None),
        FieldLenField("SPIsize",None,"SPI","B"),
        StrLenField("SPI","",length_from=lambda x:x.SPIsize),
        StrLenField("attrs","",length_from=lambda x:x.length-8), #TODO: key attributes
        ]
    def post_build(self, p, pay):
        if self.length is None:
            l = len(p)
            p = p[:2]+chr((l>>8)&0xff)+chr(l&0xff)+p[4:]
        p += pay
        return p

class ISAKMP_payload_KD(ISAKMP_payload):
    name = "ISAKMP Key Download"
    fields_desc = [
        _ISAKMP_payload_HDR,
        FieldLenField("num",None,count_of="keys",fmt="H"),
        ShortField("res2",0),
        PacketListField("keys",[],ISAKMP_key,length_from=lambda x:x.length-8),
        ]

class ISAKMP_payload_SEQ(ISAKMP_payload):
    name = "ISAKMP Sequence Number"
    fields_desc = [
        _ISAKMP_payload_HDR,
        IntField("seq",0),
        ]

class ISAKMP_payload_POP(ISAKMP_payload_SIG):
    name = "ISAKMP Proof of Possession"

class ISAKMP_payload_NAT_D(ISAKMP_payload_Hash):
    name = "ISAKMP NAT Discovery"

class ISAKMP_payload_NAT_OA(ISAKMP_payload):
    name = "ISAKMP NAT Original Address"
    fields_desc = [
        _ISAKMP_payload_HDR,
        ByteEnumField("IDtype",1,ISAKMP_ID_type),
        ByteField("res2",0),
        ShortField("res3",0),
        ConditionalField(IPField("addr4","127.0.0.1"),lambda pkt:pkt.IDtype==1),
        ConditionalField(IP6Field("addr6","::1"),lambda pkt:pkt.IDtype==5),
        ConditionalField(StrLenField("load","",length_from=lambda x:x.length-8),
                         lambda pkt:pkt.IDtype not in [1,5]),
        ]


_ISAKMP_payload_layers = {}
for i in range(len(ISAKMP_payload_type)):
    n = "ISAKMP_payload_%s" % ISAKMP_payload_type[i]
    if n in globals():
        _ISAKMP_payload_layers[i] = globals()[n]
_ISAKMP_layers = [ISAKMP,ISAKMP_payload] + _ISAKMP_payload_layers.values()

for i in _ISAKMP_layers:
    for k,v in _ISAKMP_payload_layers.iteritems():
        bind_layers(i, v, next_payload=k)
    bind_layers(i, ISAKMP_payload)
del(i,n,k,v)

bind_layers( UDP,           ISAKMP,        sport=500)
bind_layers( UDP,           ISAKMP,        dport=500)
bind_layers( UDP,           ISAKMP,        dport=500, sport=500)


def ikescan(ip):
    return sr(IP(dst=ip)/UDP()/ISAKMP(init_cookie=RandString(8),
                                      exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal()))

