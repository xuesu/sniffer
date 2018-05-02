import enum
import socket

import packet.ethernet
import utils


class ARPPacket(packet.ethernet.EthernetPacket):
    class OPTYPE(enum.IntEnum):
        ARPREQUEST = 1
        ARPREPLY = 2
        RARPREQUEST = 3
        RARPREPLY = 4

    def __init__(self):
        super(ARPPacket, self).__init__()
        self.hard_type = 1
        self.prot_type = ARPPacket.FRAMETYPE.IP
        self.hard_size = -1
        self.prot_size = -1
        self.arp_op = None
        self.sender_addr = None
        self.sender_ip_addr = None
        self.target_addr = None
        self.target_ip_addr = None
        self.final_protocol = packet.Packet.PROTOCOL.ARP

    @staticmethod
    def unpack(buff):
        arp_op = ARPPacket.OPTYPE(int.from_bytes(buff[6:8], byteorder='big'))
        if arp_op == ARPPacket.OPTYPE.ARPREPLY or arp_op == ARPPacket.OPTYPE.RARPREQUEST:
            pat = ARPPacket()
        else:
            pat = RARPPacket()
        pat.arp_op = arp_op
        pat.hard_type = int.from_bytes(buff[:2], byteorder='big')
        pat.prot_type = packet.ethernet.EthernetPacket.FRAMETYPE(int.from_bytes(buff[2:4], byteorder='big'))
        pat.hard_size = buff[4]
        pat.prot_size = buff[5]
        pat.sender_addr = utils.string2hexip(buff[8: 8 + pat.hard_size])
        if pat.prot_size == 6:
            pat.sender_ip_addr = utils.string2hexip(buff[8 + pat.hard_size: 8 + pat.hard_size + pat.prot_size])
        else:
            pat.sender_ip_addr = socket.inet_ntoa(buff[8 + pat.hard_size: 8 + pat.hard_size + pat.prot_size])
        pat.target_addr = utils.string2hexip(buff[8 + pat.hard_size + pat.prot_size: 8 + pat.hard_size * 2 + pat.prot_size])
        if pat.prot_size == 6:
            pat.target_ip_addr = utils.string2hexip(buff[8 + 2 * pat.hard_size + pat.prot_size:8 + 2 * pat.hard_size + pat.prot_size * 2])
        else:
            pat.target_ip_addr = socket.inet_ntoa(buff[8 + 2 * pat.hard_size + pat.prot_size:8 + 2 * pat.hard_size + pat.prot_size * 2])
        return pat


class RARPPacket(ARPPacket):
    def __init__(self):
        super(RARPPacket, self).__init__()
        self.final_protocol = packet.Packet.PROTOCOL.RARP
