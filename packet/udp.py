import packet.ip


class UDPPacket(packet.ip.IPPacket):
    def __init__(self):
        super(UDPPacket, self).__init__()
        self.src_port = -1
        self.des_port = -1
        self.udp_checksum = -1
        self.final_protocol = UDPPacket.PROTOCOL.UDP

    @staticmethod
    def unpack(buff):
        pak = UDPPacket()
        pak.src_port = int.from_bytes(buff[:2], byteorder='big')
        pak.des_port = int.from_bytes(buff[2:4], byteorder='big')
        pak.tcp_checksum = int.from_bytes(buff[6:8], byteorder='big')
        pak.payload = buff[8:]
        pak.final_protocol = UDPPacket.PROTOCOL.UDP
        return pak
