import enum

import packet
import utils


class EthernetPacket(packet.Packet):
    class FRAMETYPE(enum.IntEnum):
        IP = 0x0800
        ARP = 0x0806
        RARP = 0x8035

    def __init__(self):
        super(EthernetPacket, self).__init__()
        self.des_mac = None
        self.src_mac = None
        self.frame_type = None
        self.payload = None
        self.final_protocol = packet.Packet.PROTOCOL.ETHERNET

    @staticmethod
    def unpack(buff):
        frame_type = EthernetPacket.FRAMETYPE(int.from_bytes(buff[12:14], byteorder='big'))
        payload = buff[14:]
        if frame_type == EthernetPacket.FRAMETYPE.IP:
            import packet.ip
            pac = packet.ip.IPPacket.unpack(payload)
        elif frame_type == EthernetPacket.FRAMETYPE.ARP:
            import packet.arp
            pac = packet.arp.ARPPacket.unpack(payload)
        elif frame_type == EthernetPacket.FRAMETYPE.RARP:
            import packet.arp
            pac = packet.arp.RARPPacket.unpack(payload)
        else:
            pac = EthernetPacket()
            pac.payload = payload
        pac.frame_type = frame_type
        pac.des_mac = utils.string2hexip(buff[:6])
        pac.src_mac = utils.string2hexip(buff[6:12])
        return pac


