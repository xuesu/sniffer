import abc
import datetime
import enum


class Packet(abc.ABC):
    class PROTOCOL(enum.IntEnum):
        ETHERNET = 0
        IP = 1
        ARP = 2
        RARP = 3
        ICMP = 4
        TCP = 5
        UDP = 6
        FTP = 7
        HTTP = 8
        HTTPS = 9

        def get_filter_str(self):
            if self.value >= 7:
                return 'tcp'
            return self.name.lower()

        def get_sub_protocol(self):
            if self == Packet.PROTOCOL.IP:
                return set.union(Packet.PROTOCOL.TCP.get_sub_protocol(), Packet.PROTOCOL.UDP.get_sub_protocol(),
                                 Packet.PROTOCOL.ICMP.get_sub_protocol(), {self})
            elif self == Packet.PROTOCOL.TCP:
                return set.union(Packet.PROTOCOL.FTP.get_sub_protocol(), Packet.PROTOCOL.HTTP.get_sub_protocol(),
                                 Packet.PROTOCOL.HTTPS.get_sub_protocol(), {self})
            return {self}

    def __init__(self):
        self.num = 0
        self.catch_time = None
        self.final_protocol = None

    @staticmethod
    def unpack(buff):
        import packet.ethernet
        pak = packet.ethernet.EthernetPacket.unpack(buff)
        pak.catch_time = datetime.datetime.now()
        return pak

    def to_printable_dict(self):
        ans = dict()
        for field_name in vars(self):
            if field_name.startswith('_'):
                continue
            field_value = vars(self)[field_name]
            if field_value is None:
                continue
            if isinstance(field_value, enum.Enum):
                ans[field_name] = field_value.name
            elif isinstance(field_value, bool) or isinstance(field_value, int) \
                    or isinstance(field_value, float) or isinstance(field_value, str):
                ans[field_name] = field_value
            else:
                ans[field_name] = str(field_value)
        return ans