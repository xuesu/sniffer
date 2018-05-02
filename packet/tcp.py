import packet.ip
import utils


class TCPPacket(packet.ip.IPPacket):
    def __init__(self):
        super(TCPPacket, self).__init__()
        self.src_port = -1
        self.des_port = -1
        self.seq = -1
        self.ack = -1
        # whether the urgent pointer is valid
        self.urg = False
        self.ack = False
        # push mode
        self.psh = False
        # reset the connection
        self.rst = False
        self.syn = False
        self.fin = False
        self.window_size = -1
        self.tcp_checksum = -1
        self.urgent_point = -1
        self.tcp_options = None
        self.final_protocol = TCPPacket.PROTOCOL.TCP

    @staticmethod
    def unpack(buff):
        pak = TCPPacket()
        pak.src_port = int.from_bytes(buff[:2], byteorder='big')
        pak.des_port = int.from_bytes(buff[2:4], byteorder='big')
        pak.seq = int.from_bytes(buff[4:8], byteorder='big')
        pak.ack = int.from_bytes(buff[8:12], byteorder='big')
        ihl = utils.get_i_from_raw_bytes(buff, 96, 100) * 4
        pak.payload = buff[ihl:]
        header = buff[:ihl]
        pak.tcp_options = header[20:ihl]
        pak.urg = utils.get_b_from_raw_bytes(header, 106)
        pak.ack = utils.get_b_from_raw_bytes(header, 107)
        pak.psh = utils.get_b_from_raw_bytes(header, 108)
        pak.rst = utils.get_b_from_raw_bytes(header, 109)
        pak.syn = utils.get_b_from_raw_bytes(header, 110)
        pak.fin = utils.get_b_from_raw_bytes(header, 111)
        pak.window_size = int.from_bytes(buff[14:16], byteorder='big')
        pak.tcp_checksum = int.from_bytes(buff[16:18], byteorder='big')
        pak.urgent_point = int.from_bytes(buff[18:20], byteorder='big')
        return pak
