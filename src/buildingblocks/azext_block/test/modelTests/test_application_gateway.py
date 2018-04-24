from enum import Enum
import unittest
import unittest.mock as mock

from azext_block.models import (Sku, ApplicationGatewayBuildingBlock, ApplicationGateway, FrontendIPConfiguration, BackendHttpSettings, HttpListener, RedirectConfiguration, RequestRoutingRule)

class MockSkus(Enum):
    small = 'Standard_Big'

class SkuTest(unittest.TestCase):
    @mock.patch('azext_block.models.Sku._valid_tiers', new_callable=mock.PropertyMock)
    def test_valid_tiers_uses_validtiers_member(self, mocked_p):
        mocked_p.return_value = ['Frog']
        target = Sku()
        self.assertTrue(target._is_valid_tier("Frog"))

    def test_valid_tiers_match_known_WAF(self):
        target = Sku()
        self.assertTrue(target._is_valid_tier("WAF"))

    def test_valid_tiers_match_known_Standard(self):
        target = Sku()
        self.assertTrue(target._is_valid_tier("Standard"))


    @mock.patch('azext_block.models.Sku._valid_sizes', new_callable=mock.PropertyMock)
    def test_valid_sizes_uses_validsizes_member(self, mocked_p):
        mocked_p.return_value = ['Standard_Big', 'Standard_Mocks']
        target = Sku()
        self.assertTrue(target._is_valid_sku("Big"))

    def test_valid_sizes_match_known_Small(self):
        target = Sku()
        self.assertTrue(target._is_valid_sku("Small"))

    def test_valid_sizes_match_known_Medium(self):
        target = Sku()
        self.assertTrue(target._is_valid_sku("Medium"))

    def test_valid_sizes_match_known_Large(self):
        target = Sku()
        self.assertTrue(target._is_valid_sku("Large"))

    def test_valid_capacity_must_be_positive(self):
        target = Sku()
        self.assertFalse(target._is_valid_capacity(-1))

    def test_valid_capacity_cannot_be_zero(self):
        target = Sku()
        self.assertFalse(target._is_valid_capacity(0))

    def test_valid_capacity_cannot_be_gt_10(self):
        target = Sku()
        self.assertFalse(target._is_valid_capacity(11))

class FrontendIPConfigurationTest(unittest.TestCase):
    def test_is_Public_valid_gateway_type(self):
        target = FrontendIPConfiguration(application_gateway_type='Public')
        self.assertTrue(target._is_valid_gateway_type("Public"))

    def test_is_Private_valid_gateway_type(self):
        target = FrontendIPConfiguration(application_gateway_type='Internal')
        self.assertTrue(target._is_valid_gateway_type("Internal"))

    def test_is_Frog_invalid_gateway_type(self):        
        target = FrontendIPConfiguration(application_gateway_type='Frog')
        self.assertFalse(target._is_valid_gateway_type("Frog"))

    def test_is_valid_gateway_type_irrelevant_to_current(self):        
        target = FrontendIPConfiguration(application_gateway_type='Internal')
        self.assertTrue(target._is_valid_gateway_type("Public"))

class BackendHttpSettingsTest(unittest.TestCase):
    @mock.patch('azext_block.models.BackendHttpSettings._valid_affinity', new_callable=mock.PropertyMock)
    def test_valid_affinity_uses_validaffinities_member(self, mocked_p):
        mocked_p.return_value = ['Microsoft']
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_cookie_based_affinity("Microsoft"))

    def test_valid_affinity_match_known_Enabled(self):
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_cookie_based_affinity("Enabled"))

    def test_valid_affinity_match_known_Disabled(self):
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_cookie_based_affinity("Disabled"))

    def test_valid_affinity_doesnotmatch_unknown(self):
        target = BackendHttpSettings()
        self.assertFalse(target._is_valid_cookie_based_affinity("Elastacloud"))

    @mock.patch('azext_block.models.BackendHttpSettings._valid_protocol_types', new_callable=mock.PropertyMock)
    def test_valid_protocol_uses_validaffinities_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_protocol("Elastacloud"))

    def test_valid_protocol_match_known_Http(self):
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_protocol("Http"))

    def test_valid_protocol_match_known_Https(self):
        target = BackendHttpSettings()
        self.assertTrue(target._is_valid_protocol("Https"))

    def test_valid_protocol_doesnotmatch_unknown(self):
        target = BackendHttpSettings()
        self.assertFalse(target._is_valid_protocol("Elastacloud"))

class HttpListenerTest(unittest.TestCase):
    @mock.patch('azext_block.models.HttpListener._valid_protocol_types', new_callable=mock.PropertyMock)
    def test_valid_protocol_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = HttpListener()
        self.assertTrue(target._is_valid_protocol("Elastacloud"))

    def test_valid_protocol_match_known_Http(self):
        target = HttpListener()
        self.assertTrue(target._is_valid_protocol("Http"))

    def test_valid_protocol_match_known_Https(self):
        target = HttpListener()
        self.assertTrue(target._is_valid_protocol("Https"))

    def test_valid_protocol_doesnotmatch_unknown(self):
        target = HttpListener()
        self.assertFalse(target._is_valid_protocol("Elastacloud"))

class RedirectConfigurationTest(unittest.TestCase):
    @mock.patch('azext_block.models.RedirectConfiguration._redirect_types', new_callable=mock.PropertyMock)
    def test_valid_redirect_type_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("Elastacloud"))

    def test_valid_redirect_match_known_Permanent(self):
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("Permanent"))

    def test_valid_redirect_match_known_Found(self):
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("Found"))

    def test_valid_redirect_match_known_SeeOther(self):
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("SeeOther"))

    def test_valid_redirect_match_known_Temporary(self):
        target = RedirectConfiguration()
        self.assertTrue(target._is_valid_redirect_type("Temporary"))

    def test_valid_redirect_doesnotmatch_unknown(self):
        target = RedirectConfiguration()
        self.assertFalse(target._is_valid_redirect_type("Elastacloud"))


class RequestRoutingRuleTest(unittest.TestCase):
    @mock.patch('azext_block.models.RequestRoutingRule._valid_routing_rule_types', new_callable=mock.PropertyMock)
    def test_valid_redirect_type_uses_member(self, mocked_p):
        mocked_p.return_value = ['Elastacloud']
        target = RequestRoutingRule()
        self.assertTrue(target._is_valid_routing_rule_type("Elastacloud"))

    def test_valid_redirect_match_known_Basic(self):
        target = RequestRoutingRule()
        self.assertTrue(target._is_valid_routing_rule_type("Basic"))

    def test_valid_redirect_match_known_PathBasedRouting(self):
        target = RequestRoutingRule()
        self.assertTrue(target._is_valid_routing_rule_type("PathBasedRouting"))

    def test_valid_redirect_doesnotmatch_unknown(self):
        target = RequestRoutingRule()
        self.assertFalse(target._is_valid_routing_rule_type("Elastacloud"))
