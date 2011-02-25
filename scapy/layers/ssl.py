## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
TLS Transport Layer Security RFC 2246

Spencer McIntyre
SecureState R&D Team
"""

from scapy.fields import *
from scapy.packet import *
from scapy.layers.l2 import *

cipher_suites = {
        0x0003:"TLS RSA EXPORT WITH RC4 40 MD5",
        0x0004:"TLS RSA WITH RC4 128 MD5",
        0x0005:"TLS RSA WITH RC4 128 SHA",
        0x0006:"TLS RSA EXPORT WITH RC2 CBC 40 MD5",
        0x0009:"TLS RSA WITH DES CBC SHA",
        0x000a:"TLS RSA WITH 3DES EDE CBC SHA",
        0x0012:"TLS DHE DSS WITH DES CBC SHA",
        0x0013:"TLS DHE DSS WITH 3DES EDE CBC SHA",
        0x0034:"TLS DH anon WITH AES 128 CBC SHA",
        0x0062:"TLS RSA EXPORT1024 WITH DES CBC SHA",
        0x0063:"TLS DHE DSS EXPORT1024 WITH DES CBC SHA",
        0x0064:"TLS RSA EXPORT1024 WITH RC4 56 SHA"
    }

tls_handshake_types = {
		0:"HELLO REQUEST",
        1:"CLIENT HELLO",
        2:"SERVER HELLO",
        11:"CERTIFICATE",
        12:"SERVER KEY EXCHANGE",
        13:"CERTIFICATE REQUEST",
        14:"SERVER HELLO DONE",
        15:"CERTIFICATE VERIFY",
        16:"CLIENT KEY EXCHANGE",
        20:"FINISHED"
    }

class TLSv1RecordLayer(Packet):
    name = "TLS v1.0 Record Layer"
    fields_desc = [ ByteEnumField("code", 22, {20:"CHANGE CIPHER SPEC", 21:"ALERT", 22:"HANDSHAKE", 23:"APPLICATION DATA"}),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1), 
                    FieldLenField("length", None, length_of="data", fmt="H"),
                    ConditionalField(StrLenField("data", None, length_from=lambda pkt:pkt.length), lambda pkt:pkt.code != 22),
                    ConditionalField(ByteEnumField("hs_type", 1, tls_handshake_types), lambda pkt:pkt.code == 22),
                    ConditionalField(StrLenField("data", None, length_from=lambda pkt:pkt.length - 1), lambda pkt:pkt.code == 22 and pkt.hs_type not in tls_handshake_types),
                ]
                
    def guess_payload_class(self, payload):
        if self.code != 22:
            return TLSv1RecordLayer
        elif self.hs_type in [1, 2, 12, 14, 16]:
			return {1:TLSv1ClientHello, 2:TLSv1ServerHello, 12:TLSv1KeyExchange, 14:TLSv1ServerHelloDone, 16:TLSv1KeyExchange}[self.hs_type]
        else:
            return TLSv1RecordLayer

class TLSv1ClientHello(Packet):
    name = "TLSv1 Client Hello"
    fields_desc = [ ByteField("nop", 0),
                    FieldLenField("length", 36, fmt="H", length_of=lambda pkt:pkt.session_id_length + pkt.cipher_suites_length + pkt.compression_methods_length + 36),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1),
                    
                    UTCTimeField("unix_time", None),
                    StrFixedLenField("random_bytes", 0x00, length=28),
                    FieldLenField("session_id_length", 0, length_of="session_id", fmt="B"),
                    StrLenField("session_id", "", length_from=lambda pkt:pkt.session_id_length),
                    
                    FieldLenField("cipher_suites_length", 2, length_of="cipher_suites", fmt="H"),
                    FieldListField("cipher_suites", ["\x00\x34"], ShortEnumField("cipher_suite", 0x0000, cipher_suites), count_from = lambda pkt:pkt.cipher_suites_length / 2),
                    
                    FieldLenField("compression_methods_length", 1, length_of="compression_methods", fmt="B"),
                    FieldListField("compression_methods", ["\x00"], ByteEnumField("compression_method", 0x00, {0x00:"NONE"}), count_from = lambda pkt:pkt.compression_methods_length)
                ]
                
    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
        
class TLSv1ServerHello(Packet):
    name = "TLSv1 Server Hello"
    fields_desc = [ ByteField("nop", 0),
                    FieldLenField("length", None, fmt="H", length_of=lambda pkt:pkt.session_id_length + 40),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1),
                    
                    UTCTimeField("unix_time", None),
                    StrFixedLenField("random_bytes", 0x00, length=28),
                    FieldLenField("session_id_length", 0, length_of="session_id", fmt="B"),
                    ConditionalField(StrLenField("session_id", "", length_from=lambda pkt:pkt.session_id_length), lambda pkt:pkt.session_id_length),
                    ShortEnumField("cipher_suite", 0x0000, cipher_suites),
                    ByteEnumField("compression_method", 0x00, {0x00:"NONE"})
                ]
                
    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
        
class TLSv1ServerHelloDone(Packet):
    name = "TLSv1 Server Hello Done"
    fields_desc = [ ByteField("nop", 0),
                    FieldLenField("length", None, length_of="server_cert", fmt="H", adjust=lambda pkt,x:len(pkt.data) + 2),
                    StrLenField("data", "", length_from="length")
                ]

    def guess_payload_class(self, payload):
        return TLSv1RecordLayer

class TLSv1KeyExchange(Packet):
    name = "TLSv1 Key Exchange"
    fields_desc = [ ByteField("nop", 0),
                    FieldLenField("length", None, fmt="H", length_of=lambda pkt:pkt.server_cert),
                    StrLenField("server_cert", "", length_from=lambda pkt:pkt.length),
                ]

    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
