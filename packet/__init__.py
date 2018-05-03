import abc
import datetime
import enum
import inspect

import utils


class Packet(abc.ABC):
    class PROTOCOL(enum.IntEnum):
        BASIC = -1
        ETHERNET = 0
        IP = 1
        IPV4 = 2
        IPV6 = 3
        ARP = 4
        RARP = 5
        ICMP = 6
        UDP = 7
        TCP = 8
        FTP = 9
        HTTP = 10
        HTTPS = 11

        def get_filter_str(self):
            if self >= Packet.PROTOCOL.TCP:
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

    VARS = {}

    def fill_vars(self):
        classes = inspect.getmro(self.__class__)
        child = classes[0]()
        for i in range(1, len(classes) - 1):
            father = classes[i]()
            self.__class__.VARS[child.final_protocol.name] = [field_name for field_name in vars(child) not in vars(father)]
            child = father

    def __init__(self):
        self.num = 0
        self.catch_time = None
        self.final_protocol = Packet.PROTOCOL.BASIC
        self.payload = None

    @staticmethod
    def unpack(buff):
        import packet.ethernet
        pak = packet.ethernet.EthernetPacket.unpack(buff)
        pak.catch_time = datetime.datetime.now()
        return pak

    def to_printable_dict0(self):
        ans = dict()
        for field_name in vars(self):
            field_value = vars(self)[field_name]
            if field_value is None:
                continue
            if isinstance(field_value, enum.Enum):
                ans[field_name] = field_value.name
            elif isinstance(field_value, bool) or isinstance(field_value, int) \
                    or isinstance(field_value, float) or isinstance(field_value, str):
                ans[field_name] = field_value
            elif isinstance(field_value, bytes):
                ans[field_name] = utils.uni_decode(field_value)
            else:
                ans[field_name] = str(field_value)
        return ans

    def to_printable_dict(self):
        if self.__class__.__name__ not in self.__class__.VARS:
            self.fill_vars()
        ans = dict()
        for class_name in self.__class__.VARS:
            if class_name not in ans:
                ans[class_name] = dict()
            import packet.ip
            for field_name in self.__class__.VARS[class_name]:
                field_value = vars(self)[field_name]
                if field_value is None:
                    continue
                if isinstance(field_value, enum.Enum):
                    ans[class_name][field_name] = field_value.name
                elif isinstance(field_value, bool) or isinstance(field_value, int) \
                        or isinstance(field_value, float) or isinstance(field_value, str):
                    ans[class_name][field_name] = field_value
                elif isinstance(field_value, bytes):
                    ans[class_name][field_name] = utils.string2hexip(field_value)
                else:
                    ans[class_name][field_name] = str(field_value)
        return ans
