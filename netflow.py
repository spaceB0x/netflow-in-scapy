## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license
## Netflow V5 appended by spaceB0x


from scapy.fields import *
from scapy.packet import *
from scapy.layers.inet import UDP,TCP
import time

class NetflowHeader(Packet):
    name = "Netflow Header"
    fields_desc = [ ShortField("version", 1) ]




###########################################
### Version 1 stuff
###########################################
"""
Cisco NetFlow protocol v1
"""




class NetflowHeaderV1(Packet):
    name = "Netflow Header V1"
    fields_desc = [ ShortField("count", 0),
                    IntField("sysUptime", 0),
                    IntField("unixSecs", 0),
                    IntField("unixNanoSeconds", 0) ]


class NetflowRecordV1(Packet):
    name = "Netflow Record"
    fields_desc = [ IPField("ipsrc", "0.0.0.0"),
                    IPField("ipdst", "0.0.0.0"),
                    IPField("nexthop", "0.0.0.0"),
                    ShortField("inputIfIndex", 0),
                    ShortField("outpuIfIndex", 0),
                    IntField("dpkts", 0),
                    IntField("dbytes", 0),
                    IntField("starttime", 0),
                    IntField("endtime", 0),
                    ShortField("srcport", 0),
                    ShortField("dstport", 0),
                    ShortField("padding", 0),
                    ByteField("proto", 0),
                    ByteField("tos", 0),
                    IntField("padding1", 0),
                    IntField("padding2", 0) ]


bind_layers( NetflowHeader,   NetflowHeaderV1, version=1)
bind_layers( NetflowHeaderV1, NetflowRecordV1, )


#########################################
###Netflow Version 5
#########################################
"""
Cisco NetFlow protocol v5
"""


class NetflowV5Header(Packet):
    name = "Netflow Header V5"
    fields_desc = [ShortField("version", 5),
                   ShortField("count", 1),
                   IntField("sysUptime", 290270),
                   IntField("unixSecs", 1432663908),
                   IntField("unixNanoSeconds", 0),
                   IntField("flowSequence",1),
                   ByteField("engineType", 0),
                   ByteField("engineID", 186),
                   ShortField("samplingInterval", 0) ]


class NetflowV5Record(Packet):
    name = "Netflow Record V5"
    fields_desc = [IPField("src", "127.0.0.1"),
                   IPField("dst", "127.0.0.1"),
                  IPField("nexthop", "0.0.0.0"),
                   ShortField("input", 0),
                   ShortField("output", 0),
                   IntField("dpkts", 1),
                   IntField("dOctets", 60),
                   IntField("first", 0),
                   IntField("last", 0),
                   ShortField("srcport", 50697),
                   ShortField("dstport", 10000),
                   ByteField("pad1",0),
                   ByteField("tcpFlags",2),
                   ByteField("prot",6),    #Defaults to UDP (17). TCP is (6)
                   ByteField("tos",0),
                   ShortField("src_as", 0),
                   ShortField("dst_as", 0),
                   ByteField("src_mask", 0),
                   ByteField("dst_mask", 0),
                   ShortField("pad2", 0)]


