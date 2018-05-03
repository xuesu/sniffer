import unittest

import packet.arp
import packet.ethernet
import packet.ip


class PacketTest(unittest.TestCase):
    def test_to_printable_dict_ethernet(self):
        buff = b't%\x8a\xcc.\xa0X\xfb\x84\xf0\x90\xb5\x08\x00E\x00\x00)|\x93@\x00@\x06\x14I\n\xcb\x048\x9f\xe2\xfb\ro\x8e\x01\xbb\xda\xfc\x1dG\x19>\xf0\xd6P\x10\x01\x04\x91:\x00\x00\x00'
        pat = packet.ethernet.EthernetPacket.unpack(buff)
        pd = pat.to_printable_dict()
        self.assertIsNotNone(pd)

    def test_unpack_ethernet(self):
        buff = b't%\x8a\xcc.\xa0X\xfb\x84\xf0\x90\xb5\x08\x00E\x00\x00)|\x93@\x00@\x06\x14I\n\xcb\x048\x9f\xe2\xfb\ro\x8e\x01\xbb\xda\xfc\x1dG\x19>\xf0\xd6P\x10\x01\x04\x91:\x00\x00\x00'
        pat = packet.ethernet.EthernetPacket.unpack(buff)
        self.assertEqual(pat.src_mac, '58:fb:84:f0:90:b5')
        self.assertIsNotNone(pat.des_mac)
        self.assertEqual(pat.frame_type, pat.FRAMETYPE.IP)
        self.assertIsNotNone(pat.payload)

        buff = b'\xff\xff\xff\xff\xff\xff4\x80\xb3\xf0[n\x08\x06\x00\x01\x08\x00\x06\x04\x00\x014\x80\xb3\xf0[n\n\xca8\xfb\x00\x00\x00\x00\x00\x00\n\xca?\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        pat = packet.ethernet.EthernetPacket.unpack(buff)
        self.assertEqual(pat.frame_type, pat.FRAMETYPE.ARP)

    def test_unpack_ipv4(self):
        buff = b't%\x8a\xcc.\xa0X\xfb\x84\xf0\x90\xb5\x08\x00E\x00\x00)|\x93@\x00@\x06\x14I\n\xcb\x048\x9f\xe2\xfb\ro\x8e\x01\xbb\xda\xfc\x1dG\x19>\xf0\xd6P\x10\x01\x04\x91:\x00\x00\x00'[
               14:]
        pat = packet.ip.IPPacket.unpack(buff)
        self.assertEqual(pat.ipversion, pat.IPVERSION.V4)
        self.assertEqual(pat.subprotocol, pat.SUBPROTOCOL.TCP)
        self.assertEqual(pat.checksum, 5193)
        self.assertEqual(pat.des_ip, '159.226.251.13')
        self.assertEqual(pat.df, True)
        self.assertEqual(pat.mf, False)
        self.assertEqual(pat.dscp, 0)
        self.assertEqual(pat.ecn, 0)
        self.assertEqual(pat.identification, 124)
        self.assertEqual(pat.offset, 0)
        self.assertEqual(pat.src_ip, '10.203.4.56')
        self.assertEqual(pat.ttl, 64)
        self.assertIsNotNone(pat.payload)

    def test_unpack_arp(self):
        buff = b'\xff\xff\xff\xff\xff\xff4\x80\xb3\xf0[n\x08\x06\x00\x01\x08\x00\x06\x04\x00\x014\x80\xb3\xf0[n\n\xca8\xfb\x00\x00\x00\x00\x00\x00\n\xca?\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'[
               14:]
        pat = packet.arp.ARPPacket.unpack(buff)
        self.assertEqual(pat.hard_type, 1)
        self.assertEqual(pat.prot_type, pat.FRAMETYPE.IP)
        self.assertEqual(pat.hard_size, 6)
        self.assertEqual(pat.prot_size, 4)
