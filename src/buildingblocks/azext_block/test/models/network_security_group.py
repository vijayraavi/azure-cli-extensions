import unittest
from models.network_security_group import (NetworkSecurityGroup, SecurityRule)

class BaseTestCase(unittest.TestCase):
    _invalid_string_arguments = frozenset([None, "", " ", "NOT_VALID"])
    def _test_invalid_string_arguments(self, func):
        for invalid_arg in self._invalid_string_arguments:
            with self.subTest(arg=invalid_arg):
                self.assertFalse(func(invalid_arg))

class SecurityRuleIsValidProtocolTestCase(BaseTestCase):
    _valid_protocols_test = frozenset(['TCP', 'UDP', '*'])

    test_invalid_string_arguments = lambda self: self._test_invalid_string_arguments(SecurityRule._is_valid_protocol)

    def test_valid(self):
        diff = SecurityRule._valid_protocols ^ self._valid_protocols_test
        self.assertEqual(len(diff), 0, "Values not in both sets: {}".format(",".join(diff)))
        for value in self._valid_protocols_test:
            with self.subTest(arg=value):
                self.assertTrue(SecurityRule._is_valid_protocol(value))

class SecurityRuleIsValidAddressPrefixTestCase(BaseTestCase):
    _valid_default_tags_test = frozenset(['VirtualNetwork', 'AzureLoadBalancer', 'Internet', '*'])

    test_invalid_string_arguments = lambda self: self._test_invalid_string_arguments(SecurityRule._is_valid_address_prefix)

    def test_invalid_ip_address(self):
        self.assertFalse(SecurityRule._is_valid_address_prefix("256.256.256.256"))
    def test_invalid_cidr(self):
        self.assertFalse(SecurityRule._is_valid_address_prefix("10.0.0.0/33"))

    def test_valid(self):
        diff = SecurityRule._valid_default_tags ^ self._valid_default_tags_test
        self.assertEqual(len(diff), 0, "Values not in both sets: {}".format(",".join(diff)))
        for value in self._valid_default_tags_test:
            with self.subTest(arg=value):
                self.assertTrue(SecurityRule._is_valid_address_prefix(value))

class SecurityRuleIsValidDirectionTestCase(BaseTestCase):
    _valid_directions_test = frozenset(['Inbound', 'Outbound'])

    test_invalid_string_arguments = lambda self: self._test_invalid_string_arguments(SecurityRule._is_valid_direction)

    def test_valid(self):
        diff = SecurityRule._valid_directions ^ self._valid_directions_test
        self.assertEqual(len(diff), 0, "Values not in both sets: {}".format(",".join(diff)))
        for value in self._valid_directions_test:
            with self.subTest(arg=value):
                self.assertTrue(SecurityRule._is_valid_direction(value))

class SecurityRuleIsValidPriorityTestCase(BaseTestCase):
    test_invalid_string_arguments = lambda self: self._test_invalid_string_arguments(SecurityRule._is_valid_priority)

    def test_invalid_min(self):
        self.assertFalse(SecurityRule._is_valid_priority(99))
    def test_invalid_max(self):
        self.assertFalse(SecurityRule._is_valid_priority(4097))
    def test_min(self):
        self.assertTrue(SecurityRule._is_valid_priority(100))
    def test_max(self):
        self.assertTrue(SecurityRule._is_valid_priority(4096))

class SecurityRuleIsValidAccessTestCase(BaseTestCase):
    _valid_accesses_test = frozenset(['Allow', 'Deny'])

    test_invalid_string_arguments = lambda self: self._test_invalid_string_arguments(SecurityRule._is_valid_access)

    def test_valid(self):
        diff = SecurityRule._valid_accesses ^ self._valid_accesses_test
        self.assertEqual(len(diff), 0, "Values not in both sets: {}".format(",".join(diff)))
        for value in self._valid_accesses_test:
            with self.subTest(arg=value):
                self.assertTrue(SecurityRule._is_valid_access(value))

class NetworkSecurityGroupTestCase(unittest.TestCase):
    def test_expand_named_security_rules(self):
        network_security_group = NetworkSecurityGroup(
            subscription_id="00000000-0000-1000-8000-000000000000",
            resource_group_name="test-rg",
            location="westus",
            name="test-nsg",
            security_rules=[SecurityRule(name="ActiveDirectory")])
        self.assertEqual(len(network_security_group.security_rules), 16)