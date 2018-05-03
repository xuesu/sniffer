import unittest

import functions.winpcapy as winpcapy


class WinPCapTest(unittest.TestCase):
    def test_list_all_devices(self):
        self.assertIsNotNone(winpcapy.WinPCap.list_all_devices())

    def test_set_proto_filter(self):
        device_names = [device_name for device_name in winpcapy.WinPCap.list_all_devices().keys()]
        phandle = winpcapy.WinPCap.open_device(device_names[0])
        winpcapy.WinPCap.pcap_set_filter(phandle, "ip proto icmp")

    def test_set_addr_filter(self):
        device_names = [device_name for device_name in winpcapy.WinPCap.list_all_devices().keys()]
        phandle = winpcapy.WinPCap.open_device(device_names[0])
        addr_filter = winpcapy.AddressFilter("src or dst", "port", 6912)
        winpcapy.WinPCap.pcap_set_filter(phandle, addr_filter.get_filter_str())
        addr_filter = winpcapy.AddressFilter("src and dst", "host", "www.baidu.com")
        winpcapy.WinPCap.pcap_set_filter(phandle, addr_filter.get_filter_str())
        addr_filter = winpcapy.AddressFilter("src", "host", "127.0.0.1")
        winpcapy.WinPCap.pcap_set_filter(phandle, addr_filter.get_filter_str())
        addr_filter = winpcapy.AddressFilter("dst", "mac address", "00:90:41:C0:C1:C3")
        winpcapy.WinPCap.pcap_set_filter(phandle, addr_filter.get_filter_str())