import dpkt
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
        self.sub_protocol = None
        self.src_ip = None
        self.des_ip = None
        self.ip_total_length = -1
        self.final_protocol = packet.Packet.PROTOCOL.IP

    @staticmethod
    def unpack(buff):
        ip_version = utils.get_enum_from_value(IPPacket.IPVERSION, utils.get_i_from_raw_bytes(buff, 0, 4))
        if ip_version == IPPacket.IPVERSION.V4:
            return IPv4Packet.unpack(buff)
        elif ip_version == IPPacket.IPVERSION.V6:
            return IPv6Packet.unpack(buff)
        return None


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
        self.final_protocol = IPv4Packet.PROTOCOL.IPV4

    @staticmethod
    def unpack(buff):
        ihl = utils.get_i_from_raw_bytes(buff, 4, 8) * 4
        header = buff[:ihl]
        payload = buff[ihl:]
        sub_protocol = utils.get_enum_from_value(IPPacket.SUBPROTOCOL, buff[9])
        if sub_protocol == IPPacket.SUBPROTOCOL.TCP:
            import packet.tcp
            pac = packet.tcp.TCPPacket.unpack(payload)
        elif sub_protocol == IPPacket.SUBPROTOCOL.UDP:
            import packet.udp
            pac = packet.udp.UDPPacket.unpack(payload)
        else:
            pac = IPv4Packet()
            pac.payload = payload
            pac.sub_protocol = sub_protocol
        pac.ip_total_length = int.from_bytes(header[2:4], byteorder='big')
        pac.sub_protocol = IPPacket.SUBPROTOCOL(header[9])
        pac.dscp = utils.get_i_from_raw_bytes(header, 8, 14)
        pac.ecn = utils.get_i_from_raw_bytes(header, 14, 16)
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


class IPv6Packet(IPPacket):
    EXT_HEADERS_CODE = [dpkt.ip.IP_PROTO_HOPOPTS, dpkt.ip.IP_PROTO_ROUTING,
                        dpkt.ip.IP_PROTO_FRAGMENT, dpkt.ip.IP_PROTO_AH,
                        dpkt.ip.IP_PROTO_ESP, dpkt.ip.IP_PROTO_DSTOPTS]

    def __init__(self):
        super(IPv6Packet, self).__init__()
        # Origin: Type Of Service
        self.ip_options = None
        self.ds = 0
        self.ecn = 0
        self.flow_label = 0
        self.hop_limit = -1
        self.ip_version = IPPacket.IPVERSION.V6
        self.final_protocol = IPv4Packet.PROTOCOL.IPV6
        self.external_header_length = 0

    @staticmethod
    def unpack_exthdr(buff):
        nxt_header = buff[6]
        ext_headers = []
        ihl = 40
        while nxt_header in IPv6Packet.EXT_HEADERS_CODE:
            hhl = 2 + buff[ihl + 1]
            ext_headers.append((nxt_header, buff[ihl + 2: ihl + hhl]))
            nxt_header = buff[ihl]
            ihl += hhl
        try:
            sub_protocol = IPPacket.SUBPROTOCOL(nxt_header)
        except AttributeError:
            sub_protocol = None
        return buff[:40], sub_protocol, buff[ihl:], ext_headers

    @staticmethod
    def unpack(buff):
        header, sub_protocol, payload, ext_headers = IPv6Packet.unpack_exthdr(buff)
        if sub_protocol == IPPacket.SUBPROTOCOL.TCP:
            import packet.tcp
            pak = packet.tcp.TCPPacket.unpack(payload)
        elif sub_protocol == IPPacket.SUBPROTOCOL.UDP:
            import packet.udp
            pak = packet.udp.UDPPacket.unpack(payload)
        else:
            pak = IPv6Packet()
            pak.payload = payload
            pak.sub_protocol = sub_protocol
        pak.external_header_length = max(sum([len(exthdr[1]) + 2 for exthdr in ext_headers]) - 1, 0)
        pak.ds = utils.get_i_from_raw_bytes(header, 4, 10)
        pak.ecn = utils.get_i_from_raw_bytes(header, 10, 12)
        pak.flow_label = utils.get_i_from_raw_bytes(header, 12, 32)
        pak.ip_total_length = int.from_bytes(buff[4:6], byteorder='big')
        pak.hop_limit = buff[7]
        pak.src_ip = utils.string2hexip(header[8:24])
        pak.des_ip = utils.string2hexip(header[24:40])
        return pak
