import unittest

import utils


class UtilsTest(unittest.TestCase):
    def test_get_i_from_raw_bytes(self):
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE'), 0xfe)
        for i in range(8):
            self.assertEqual(utils.get_i_from_raw_bytes(b'\xFF', i, i + 1), 1)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE', 0, 8), 0xfe)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE\xDC', 0, 16), 0xfedc)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE\xDC', 0, 8), 0xfe)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE', 0, 4), 0xf)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE', 4, 8), 0xe)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE', 0, 8, True), 0xfe)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE\xDC', 0, 16, True), 0xdcfe)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE\xDC', 0, 8, True), 0xdc)
        self.assertEqual(utils.get_i_from_raw_bytes(b'\xFE', 0, 4, True), 0xf)
