## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
TLS Transport Layer Security RFC 2246
"""

from scapy.fields import *
from scapy.packet import *
from scapy.layers.l2 import *

class TLSv1RecordLayer(Packet):
    name = "TLS v1.0 Record Layer"
    fields_desc = [ ByteEnumField("code", 22, {20:"CHANGE CIPHER SPEC", 21:"ALERT", 22:"HANDSHAKE", 23:"APPLICATION DATA"}),
                    ByteField("major_version", 3),
                    ByteField("minor_version", 1), 
                    FieldLenField("length", None, length_of="data", fmt="H"),
					StrLenField("data", "", length_from=lambda pkt:pkt.length),
                ]
                
    def guess_payload_class(self, payload):
        return TLSv1RecordLayer
