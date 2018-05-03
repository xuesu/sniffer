import datetime
import enum

import dpkt


class Packet:
    class PROTOCOL(enum.IntEnum):
        ETHERNET = 0
        IPV4 = 1
        IPV6 = 2
        ARP = 3
        ICMP = 4
        # ICMP6 = 5
        # IGMP = 6
        UDP = 7
        TCP = 8
        FTP = 9
        HTTP = 10
        HTTPS = 11

        def get_filter_str(self):
            if self >= Packet.PROTOCOL.TCP:
                return 'tcp'
            # elif self == Packet.PROTOCOL.ICMP6:
            #     return 'ip6 proto icmp6'
            # elif self == Packet.PROTOCOL.IGMP:
            #     return 'ip proto igmp'
            elif self == Packet.PROTOCOL.IPV6:
                return "ip6"
            elif self == Packet.PROTOCOL.IPV4:
                return "ip"
            elif self == Packet.PROTOCOL.ETHERNET:
                return ""
            return self.name.lower()

        def get_sub_protocol(self):
            if self == Packet.PROTOCOL.IPV4 or self == Packet.PROTOCOL.IPV6:
                return set.union(Packet.PROTOCOL.TCP.get_sub_protocol(), Packet.PROTOCOL.UDP.get_sub_protocol(),
                                 Packet.PROTOCOL.ICMP.get_sub_protocol(), {self})
            elif self == Packet.PROTOCOL.TCP:
                return set.union(Packet.PROTOCOL.FTP.get_sub_protocol(), Packet.PROTOCOL.HTTP.get_sub_protocol(),
                                 Packet.PROTOCOL.HTTPS.get_sub_protocol(), {self})
            return {self}

        @staticmethod
        def from_dpkt_class(cls):
            if cls == dpkt.ethernet.Ethernet:
                return Packet.PROTOCOL.ETHERNET
            elif cls == dpkt.ip.IP:
                return Packet.PROTOCOL.IPV4
            elif cls == dpkt.ip6.IP6:
                return Packet.PROTOCOL.IPV6
            elif cls == dpkt.arp.ARP:
                return Packet.PROTOCOL.ARP
            elif cls == dpkt.icmp.ICMP:
                return Packet.PROTOCOL.ICMP
            elif cls == dpkt.icmp6.ICMP6:
                return Packet.PROTOCOL.ICMP6
            elif cls == dpkt.igmp.IGMP:
                return Packet.PROTOCOL.IGMP
            elif cls == dpkt.udp.UDP:
                return Packet.PROTOCOL.UDP
            elif cls == dpkt.tcp.TCP:
                return Packet.PROTOCOL.TCP
            else:
                return None

    @staticmethod
    def get_final_protocol(pak):
        final_protocol = None
        while isinstance(pak, dpkt.Packet):
            if Packet.PROTOCOL.from_dpkt_class(pak.__class__) is not None:
                final_protocol = Packet.PROTOCOL.from_dpkt_class(pak.__class__)
                pak = pak.data
        return final_protocol

    def __init__(self, buff=None):
        self.num = -1
        self.catch_time = datetime.datetime.now()
        if buff is None:
            self.data = None
            self.final_protocol = None
        else:
            self.data = dpkt.ethernet.Ethernet()
            self.data.unpack(buff)
            self.final_protocol = Packet.get_final_protocol(self.data)
