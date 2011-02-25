## This file is for use with Scapy
## See http://www.secdev.org/projects/scapy for more information
## Copyright (C) Ryan Speers <ryan@rmspeers.com> 2011
## This program is published under a GPLv2 license

"""
Wireless MAC according to IEEE 802.15.4.
"""

import re, struct

from scapy.packet import *
from scapy.fields import *
from scapy.layers.l2 import *

### Fields ###

class dot15d4AddressField(Field):
    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        if adjust != None:  self.adjust=adjust
        else:               self.adjust=lambda pkt,x:self.lengthFromAddrMode(pkt, x)
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        return lhex(self.i2h(pkt,x))
    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + struct.pack(self.fmt[0]+"H", int(val, 16) if type(val)==str else val)
        elif self.adjust(pkt,self.length_of) == 8:
            return s + struct.pack(self.fmt[0]+"Q", int(val, 16) if type(val)==str else val)
        else:
            return s
    def lengthFromAddrMode(self, pkt, x):
        pkttop = pkt
        while pkttop.underlayer != None: pkttop = pkttop.underlayer
        addrmode = pkttop.getfieldval(x)
        #print "Underlayer field value of", x, "is", addrmode
        if addrmode == 2: return 2
        elif addrmode == 3: return 8
        else: return 0

### Layers ###

class Dot15d4(Packet):
    name = "802.15.4"
    fields_desc = [
                    BitField("fcf_reserved_1", 0, 1), #fcf p1 b1
                    BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
                    BitEnumField("fcf_ackreq", 0, 1, [False, True]),
                    BitEnumField("fcf_pending", 0, 1, [False, True]),
                    BitEnumField("fcf_security", 0, 1, [False, True]), #fcf p1 b2
                    BitEnumField("fcf_frametype", 0, 3, {0:"Beacon", 1:"Data", 2:"Ack", 3:"Command"}),
                    BitEnumField("fcf_srcaddrmode", 0, 2, {0:"None", 2:"Short", 1:"Long"}),  #fcf p2 b1
                    BitField("fcf_framever", 0, 2),
                    BitEnumField("fcf_destaddrmode", 2, 2, {0:"None", 2:"Short", 1:"Long"}), #fcf p2 b2
                    BitField("fcf_reserved_2", 0, 2),
                    ByteField("seqnum", 1) #sequence number
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 %Dot15d4.fcf_frametype% ackreq(%Dot15d4.fcf_ackreq%) ( %Dot15d4.fcf_destaddrmode% -> %Dot15d4.fcf_srcaddrmode% ) Seq#%Dot15d4.seqnum%")

    def guess_payload_class(self, payload):
        if self.fcf_frametype == 0x00:      return Dot15d4Beacon
        elif self.fcf_frametype == 0x01:    return Dot15d4Data
        elif self.fcf_frametype == 0x02:    return Dot15d4Ack
        elif self.fcf_frametype == 0x03:    return Dot15d4Cmd
        else:                               return Packet.guess_payload_class(self, payload)

    def answers(self, other):
        if isinstance(other, Dot15d4):
            if self.fcf_frametype == 2: #ack
                if self.seqnum != other.seqnum: #check for seqnum matching
                    return 0
                elif other.fcf_ackreq == 1: #check that an ack was indeed requested
                    return 1
        return 0

class Dot15d4Ack(Packet):
    name = "802.15.4 Ack"
    fields_desc = [
                    XLEShortField("fcs", 0)
                    ]

class Dot15d4AuxSecurityHeader(Packet):
    name = "802.15.4 Auxillary Security Header"
    fields_desc = [
                    BitEnumField("sec_sc_seclevel", 0, 3, {0:"None", 1:"MIC-32"}),
                    BitEnumField("sec_sc_keyidmode", 0, 2, {0:"Implicit", 1:"KeyIndex"}),
                    BitField("sec_sc_reserved", 0, 3),
                    XLEIntField("sec_framecounter", 0x00000000),
                    #TODO KeyId field only appears if sec_sc_keyidmode != 0
                    #TODO length of sec_keyid_keysource varies btwn 0, 4, and 8 bytes depending on sec_sc_keyidmode
                    #XLEIntField("sec_keyid_keysource", 0x00000000),
                    ConditionalField(XByteField("sec_keyid_keyindex", 0xFF), lambda pkt:pkt.getfieldval("sec_sc_keyidmode") != 0),
                    ]

class Dot15d4Data(Packet):
    name = "802.15.4 Data"
    fields_desc = [
                    XLEShortField("dest_panid", 0xFFFF),
                    dot15d4AddressField("dest_addr", 0xFFFF, length_of="fcf_destaddrmode"),
                    ConditionalField(XLEShortField("src_panid", 0x0), \
                                        lambda pkt:util_srcpanid_present(pkt)),
                    ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"), \
                                        lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),
                    # Security field present if fcf_security == True
                    ConditionalField(PacketField("aux_sec_header", Dot15d4AuxSecurityHeader(), Dot15d4AuxSecurityHeader),
                                        lambda pkt:pkt.underlayer.getfieldval("fcf_security") == True),
                    #TODO data payload
                    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Data ( %Dot15d4Data.src_panid%:%Dot15d4Data.src_addr% -> %Dot15d4Data.dest_panid%:%Dot15d4Data.dest_addr% )")

class Dot15d4Beacon(Packet):
    name = "802.15.4 Beacon"
    fields_desc = [
                    XLEShortField("src_panid", 0x0),
                    dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"),

                    # Superframe spec field:
                    BitField("sf_beaconorder", 15, 4),  #not used by ZigBee
                    BitField("sf_sforder", 15, 4),      #not used by ZigBee
                    BitField("sf_finalcapslot", 15, 4), #not used by ZigBee
                    BitEnumField("sf_battlifeextend", 0, 1, [False, True]), #not used by ZigBee
                    BitField("sf_reserved", 0, 1),      #not used by ZigBee
                    BitEnumField("sf_pancoord", 0, 1, [False, True]),
                    BitEnumField("sf_assocpermit", 0, 1, [False, True]),

                    # GTS Fields:
                    #  GTS Specification (1 byte)
                    BitField("gts_spec_desccount", 0, 3), #GTS spec bits 0-2
                    BitField("gts_spec_reserved", 0, 4),  #GTS spec bits 3-6
                    BitEnumField("gts_spec_permit", 1, 1, [False, True]), #GTS spec bit 7, true=1 iff PAN cord is accepting GTS requests
                    #  GTS Directions (0 or 1 byte)
                    ConditionalField(BitField("gts_dir_mask", 0, 7), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),
                    ConditionalField(BitField("gts_dir_reserved", 0, 1), lambda pkt:pkt.getfieldval("gts_spec_desccount") != 0),
                    #  GTS List
                    #TODO add a Packet/FieldListField tied to 3bytes per count in gts_spec_desccount

                    # Pending Address Fields:
                    #  Pending Address Specification (1 byte)
                    BitField("pa_num_short", 0, 3), #number of short addresses pending
                    BitField("pa_reserved_1", 0, 1),
                    BitField("pa_num_long", 0, 3), #number of long addresses pending
                    BitField("pa_reserved_2", 0, 1),
                    #  Address List (var length)
                    #TODO add a FieldListField of the pending short addresses, followed by the pending long addresses, with max 7 addresses

                    #TODO beacon payload
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Beacon ( %Dot15d4Beacon.src_panid%:%Dot15d4Beacon.src_addr% ) assocPermit(%Dot15d4Beacon.sf_assocpermit%) panCoord(%Dot15d4Beacon.sf_pancoord%) ")

class Dot15d4Cmd(Packet):
    name = "802.15.4 Command"
    fields_desc = [
                    XLEShortField("dest_panid", 0xFFFF),
                    dot15d4AddressField("dest_addr", None, length_of="fcf_destaddrmode"),
                    ConditionalField(XLEShortField("src_panid", 0x0), \
                                        lambda pkt:util_srcpanid_present(pkt)),
                    ConditionalField(dot15d4AddressField("src_addr", None, length_of="fcf_srcaddrmode"), \
                                        lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),
                    ByteEnumField("cmd_id", 0, {1:"AssocReq", 2:"AssocResp", 4:"DataReq", 5:"PANIDConflictNotify", 6:"OrphanNotify", 7:"BeaconReq", 8:"CoordRealgin"}),
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Command %Dot15d4Cmd.commandid% ( %Dot15dCmd.src_panid%:%Dot15d4Cmd.src_addr% -> %Dot15d4Cmd.dest_panid%:%Dot15d4Cmd.dest_addr% )")

    def guess_payload_class(self, payload):
        if self.cmd_id == "CoordRealign":   return Dot15d4CmdCoordRealign
        else:                               return Packet.guess_payload_class(self, payload)

class Dot15d4CmdCoordRealign(Packet):
    name = "802.15.4 Coordinator Realign Payload"
    fields_desc = [
                    XLEShortField("pan_id", 0xFFFF),
                    XLEShortField("coord_addr", None),
                    ByteField("channel", 11),
                    XLEShortField("dev_addr", None),
                    #ConditionalField(XShortField("channel_page", 0), lambda pkt:pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0),
                    ]
    def mysummary(self):
        return self.sprintf("802.15.4 Coordinator Realign Payload ( %Dot15dCmdCoordRealign.pan_id% : chan %Dot15d4CmdCoordRealign.channel% )")

### Utility Functions ###
def util_srcpanid_present(pkt):
    '''A source PAN ID is included if and only if both src addr mode != 0 and PAN ID Compression in FCF == 0'''
    if (pkt.underlayer.getfieldval("fcf_srcaddrmode") != 0) and (pkt.underlayer.getfieldval("fcf_panidcompress") == 0): return True
    else: return False

### Bindings ###
bind_layers( Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4, Dot15d4Cmd,  fcf_frametype=3)

