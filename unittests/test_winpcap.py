import unittest

import functions.winpcapy as winpcapy


class WinPCapTest(unittest.TestCase):
    def test_listalldevices(self):
        winpcapy.WinPCap.list_all_devices()
