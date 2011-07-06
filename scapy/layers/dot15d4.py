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

### Fields ###

class dot15d4AddressField(Field):
    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of=length_of
        if adjust != None:  self.adjust=adjust
        else:               self.adjust=lambda pkt,x:self.lengthFromAddrMode(pkt, x)
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        x = hex(self.i2h(pkt,x))[2:-1]
        x = len(x) %2 != 0 and "0" + x or x
        return ":".join(["%s%s" % (x[i], x[i+1]) for i in range(0,len(x),2)])
    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + struct.pack(self.fmt[0]+"H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + struct.pack(self.fmt[0]+"Q", val)
        else:
            return s
    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, struct.unpack(self.fmt[0]+"H", s[:2])[0])
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, struct.unpack(self.fmt[0]+"Q", s[:8])[0])
        else:
            raise Exception('impossible case')
    def lengthFromAddrMode(self, pkt, x):
        pkttop = pkt
        while pkttop.underlayer != None: pkttop = pkttop.underlayer
        addrmode = pkttop.getfieldval(x)
        #print "Underlayer field value of", x, "is", addrmode
        if addrmode == 2: return 2
        elif addrmode == 3: return 8
        else: return 0


#class dot15d4Checksum(LEShortField,XShortField):
#    def i2repr(self, pkt, x):
#        return XShortField.i2repr(self, pkt, x)
#    def addfield(self, pkt, s, val):
#        return s
#    def getfield(self, pkt, s):
#        return s


### Layers ###

class Dot15d4(Packet):
    name = "802.15.4"
    fields_desc = [
                    HiddenField(BitField("fcf_reserved_1", 0, 1), True), #fcf p1 b1
                    BitEnumField("fcf_panidcompress", 0, 1, [False, True]),
                    BitEnumField("fcf_ackreq", 0, 1, [False, True]),
                    BitEnumField("fcf_pending", 0, 1, [False, True]),
                    BitEnumField("fcf_security", 0, 1, [False, True]), #fcf p1 b2
                    Emph(BitEnumField("fcf_frametype", 0, 3, {0:"Beacon", 1:"Data", 2:"Ack", 3:"Command"})),
                    BitEnumField("fcf_srcaddrmode", 0, 2, {0:"None", 1:"Reserved", 2:"Short", 3:"Long"}),  #fcf p2 b1
                    BitField("fcf_framever", 0, 2),
                    BitEnumField("fcf_destaddrmode", 2, 2, {0:"None", 1:"Reserved", 2:"Short", 3:"Long"}), #fcf p2 b2
                    HiddenField(BitField("fcf_reserved_2", 0, 2), True),
                    Emph(ByteField("seqnum", 1)) #sequence number
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

    def post_build(self, p, pay):
        #This just forces destaddrmode to None for Ack frames.
        #TODO find a more elegant way to do this
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return str(self)
        else:
            return p + pay


class Dot15d4FCS(Dot15d4, Packet):
    '''
    This class is a drop-in replacement for the Dot15d4 class above, except
    it expects a FCS/checksum in the input, and produces one in the output.
    This provides the user flexibility, as many 802.15.4 interfaces will have an AUTO_CRC setting
    that will validate the FCS/CRC in firmware, and add it automatically when transmitting.
    '''
    def pre_dissect(self, s):
        """Called right before the current layer is dissected"""
        if (makeFCS(s[:-2]) != s[-2:]): #validate the FCS given
            warning("FCS on this packet is invalid or is not present in provided bytes.")
            return s                    #if not valid, pretend there was no FCS present
        return s[:-2]                   #otherwise just disect the non-FCS section of the pkt

    def post_build(self, p, pay):
        #This just forces destaddrmode to None for Ack frames.
        #TODO find a more elegant way to do this
        if self.fcf_frametype == 2 and self.fcf_destaddrmode != 0:
            self.fcf_destaddrmode = 0
            return str(self)
        else:
            return p + pay + makeFCS(p+pay) #construct the packet with the FCS at the end


class Dot15d4Ack(Packet):
    name = "802.15.4 Ack"
    fields_desc = [ ]


class Dot15d4AuxSecurityHeader(Packet):
    name = "802.15.4 Auxillary Security Header"
    fields_desc = [
                    BitEnumField("sec_sc_seclevel", 0, 3, {0:"None", 1:"MIC-32", 2:"MIC-64", 3:"MIC-128",          \
                                                          4:"ENC", 5:"ENC-MIC-32", 6:"ENC-MIC-64", 7:"ENC-MIC-128"}),
                    BitEnumField("sec_sc_keyidmode", 0, 2, {0:"Implicit", 1:"KeyIndex"}),
                    HiddenField(BitField("sec_sc_reserved", 0, 3), True),
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
                    #TODO command payload
                    ]

    def mysummary(self):
        return self.sprintf("802.15.4 Command %Dot15d4Cmd.commandid% ( %Dot15dCmd.src_panid%:%Dot15d4Cmd.src_addr% -> %Dot15d4Cmd.dest_panid%:%Dot15d4Cmd.dest_addr% )")

    #TODO implement more command frame payloads
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

# Do a CRC-CCITT Kermit 16bit on the data given
# Returns a CRC that is the FCS for the frame
#  Implemented using pseudocode from: June 1986, Kermit Protocol Manual
#  See also: http://regregex.bbcmicro.net/crc-catalogue.htm#crc.cat.kermit
def makeFCS(data):
    crc = 0
    for i in range(0, len(data)):
        c = ord(data[i])
        q = (crc ^ c) & 15				#Do low-order 4 bits
        crc = (crc // 16) ^ (q * 4225)
        q = (crc ^ (c // 16)) & 15		#And high 4 bits
        crc = (crc // 16) ^ (q * 4225)
    return struct.pack('<H', crc) #return as bytes in little endian order


### Bindings ###
bind_layers( Dot15d4, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4, Dot15d4Cmd,  fcf_frametype=3)
bind_layers( Dot15d4FCS, Dot15d4Beacon, fcf_frametype=0)
bind_layers( Dot15d4FCS, Dot15d4Data, fcf_frametype=1)
bind_layers( Dot15d4FCS, Dot15d4Ack,  fcf_frametype=2)
bind_layers( Dot15d4FCS, Dot15d4Cmd,  fcf_frametype=3)


### DLT Types ###
conf.l2types.register(195, Dot15d4FCS)
conf.l2types.register(230, Dot15d4)
