import enum
import socket

import packet.ethernet
import utils


class IPPacket(packet.ethernet.EthernetPacket):
    class IPVERSION(enum.IntEnum):
        V4 = 4
        V6 = 6

    class SUBPROTOCOL(enum.IntEnum):
        ICMP = 1
        IGMP = 2
        TCP = 6
        UDP = 17

    def __init__(self):
        super(IPPacket, self).__init__()
        self.ip_version = None
        self.subprotocol = None
        self.src_ip = None
        self.des_ip = None
        self.payload = None
        self.final_protocol = packet.Packet.PROTOCOL.IP

    @staticmethod
    def unpack(buff):
        ipversion = IPPacket.IPVERSION(utils.get_i_from_raw_bytes(buff, 0, 4))
        if ipversion == IPPacket.IPVERSION.V4:
            return IPv4Packet.unpack(buff)
        raise NotImplementedError()


class IPv4Packet(IPPacket):
    def __init__(self):
        super(IPv4Packet, self).__init__()
        # Origin: Type Of Service
        self.dscp = 0
        self.ecn = None
        self.identification = None
        self.df = False
        self.mf = False
        self.offset = 0
        self.ttl = 0
        self.ip_checksum = 0
        self.ip_options = None
        self.ip_version = IPPacket.IPVERSION.V4
        self.ip_totoal_length = -1

    @staticmethod
    def unpack(buff):
        ihl = utils.get_i_from_raw_bytes(buff, 4, 8) * 4
        header = buff[:ihl]
        payload = buff[ihl:]
        if IPPacket.SUBPROTOCOL(buff[9]) == IPPacket.SUBPROTOCOL.TCP:
            import packet.tcp
            pac = packet.tcp.TCPPacket.unpack(payload)
        else:
            pac = IPv4Packet()
        pac.ip_totoal_length = int.from_bytes(header[2:4], byteorder='big')
        pac.subprotocol = IPPacket.SUBPROTOCOL(header[9])
        pac.dscp = utils.get_i_from_raw_bytes(header, 8, 14)
        pac.ecn = utils.get_i_from_raw_bytes(header, 14, 16)
        pac.payload = payload
        pac.identification = header[4]
        pac.df = utils.get_b_from_raw_bytes(header, 49)
        pac.mf = utils.get_b_from_raw_bytes(header, 50)
        pac.offset = utils.get_i_from_raw_bytes(header, 51, 64) * 8
        pac.ttl = header[8]
        pac.ip_checksum = int.from_bytes(header[10:12], byteorder='big')
        pac.src_ip = socket.inet_ntoa(header[12:16])
        pac.des_ip = socket.inet_ntoa(header[16:20])
        if ihl > 20:
            pac.ip_options = header[20:]
        return pac
