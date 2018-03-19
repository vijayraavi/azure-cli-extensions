import unittest
from validations.networking import (is_valid_ip_address, is_valid_cidr, is_valid_port_range)

class IsValidIpAddressTestCase(unittest.TestCase):
    def test_none(self):
        self.assertFalse(is_valid_ip_address(None))
    def test_empty_string(self):
        self.assertFalse(is_valid_ip_address(""))
    def test_only_whitespace(self):
        self.assertFalse(is_valid_ip_address(" "))
    def test_invalid(self):
        self.assertFalse(is_valid_ip_address("NOT_VALID"))
    def test_cidr(self):
        self.assertFalse(is_valid_ip_address("10.0.0.0/16"))
    def test_valid(self):
        self.assertTrue(is_valid_ip_address("10.0.0.0"))

class IsValidCidrTestCase(unittest.TestCase):
    def test_none(self):
        self.assertFalse(is_valid_cidr(None))
    def test_empty_string(self):
        self.assertFalse(is_valid_cidr(""))
    def test_only_whitespace(self):
        self.assertFalse(is_valid_cidr(" "))
    def test_invalid(self):
        self.assertFalse(is_valid_cidr("NOT_VALID"))
    def test_ip_address(self):
        self.assertFalse(is_valid_cidr("10.0.0.0"))
    def test_valid(self):
        self.assertTrue(is_valid_cidr("10.0.0.0/16"))

class IsValidPortRangeTestCase(unittest.TestCase):
    def test_none(self):
        self.assertFalse(is_valid_port_range(None))
    def test_empty_string(self):
        self.assertFalse(is_valid_port_range(""))
    def test_only_whitespace(self):
        self.assertFalse(is_valid_port_range(" "))
    def test_invalid(self):
        self.assertFalse(is_valid_port_range("NOT_VALID"))
    def test_invalid_min(self):
        self.assertFalse(is_valid_port_range("0"))
    def test_invalid_max(self):
        self.assertFalse(is_valid_port_range("65536"))
    def test_invalid_min_range(self):
        self.assertFalse(is_valid_port_range("0-65535"))
    def test_invalid_max_range(self):
        self.assertFalse(is_valid_port_range("1-65536"))
    def test_invalid_range_too_many_parts(self):
        self.assertFalse(is_valid_port_range("1-10-20"))
    def test_invalid_range_max_before_min(self):
        self.assertFalse(is_valid_port_range("100-50"))
    def test_valid_min(self):
        self.assertTrue(is_valid_port_range("1"))
    def test_valid_max(self):
        self.assertTrue(is_valid_port_range("65535"))
    def test_valid_star(self):
        self.assertTrue(is_valid_port_range("*"))
    def test_valid_port_range(self):
        self.assertTrue(is_valid_port_range("1-65535"))
