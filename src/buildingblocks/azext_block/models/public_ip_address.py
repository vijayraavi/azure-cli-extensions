from azure.mgmt.network.models import (IPAllocationMethod,
                                       IPVersion,
                                       PublicIPAddressDnsSettings,
                                       PublicIPAddress as PublicIPAddressSdk,
                                       PublicIPAddressSkuName)
from .building_block_settings import (BuildingBlock)
from .resources import (Resource,
                        ResourceId,
                        TaggedResource,
                        TopLevelResource,
                        convert_string_to_enum)
from ..validations import (ValidationFunction)

BuildingBlock.register_sdk_model(PublicIPAddressSdk, {
    'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
    'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
})

@ResourceId(namespace="Microsoft.Network", type="publicIPAddresses")
class PublicIPAddress(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'str'},
        'public_ip_allocation_method': {'key': 'publicIPAllocationMethod', 'type': 'str'},
        'public_ip_address_version': {'key': 'publicIPAddressVersion', 'type': 'str'},
        #'dns_settings': {'key': 'properties.dnsSettings', 'type': 'PublicIPAddressDnsSettings'},
        'idle_timeout_in_minutes': {'key': 'idleTimeoutInMinutes', 'type': 'int'},
        'zones': {'key': 'zones', 'type': '[str]'},
        'domain_name_label': {'key': 'domainNameLabel', 'type': 'str'},
        'reverse_fqdn': {'key': 'reverseFqdn', 'type': 'str'}
    }

    _valid_skus = [e.value for e in PublicIPAddressSkuName]
    _valid_ip_allocation_methods = [e.value for e in IPAllocationMethod]
    _valid_ip_address_versions = [e.value for e in IPVersion]

    def __init__(self, sku=None, public_ip_allocation_method=None, public_ip_address_version=None, idle_timeout_in_minutes=None, zones=None, domain_name_label=None, reverse_fqdn=None, **kwargs):
        super(PublicIPAddress, self).__init__(**kwargs)
        self.sku = convert_string_to_enum(PublicIPAddressSkuName, sku) if sku else PublicIPAddressSkuName.basic
        self.public_ip_allocation_method = convert_string_to_enum(IPAllocationMethod, public_ip_allocation_method) if public_ip_allocation_method else IPAllocationMethod.dynamic
        self.public_ip_address_version = convert_string_to_enum(IPVersion, public_ip_address_version) if public_ip_address_version else IPVersion.ipv4
        self.idle_timeout_in_minutes = idle_timeout_in_minutes
        self.zones = zones
        self.domain_name_label = domain_name_label
        self.reverse_fqdn = reverse_fqdn
        self._validation.update({
            'sku': {'required': True, 'custom': PublicIPAddress._is_valid_sku},
            'public_ip_allocation_method': {'required': True, 'custom': PublicIPAddress._is_valid_ip_allocation_method},
            'public_ip_address_version': {'required': True, 'custom': PublicIPAddress._is_valid_ip_address_version},
            'reverse_fqdn': {'custom': self._validate_reverse_fqdn}
        })

    def transform(self):
        parameters = {
            'subscription_id': self.subscription_id,
            'resource_group_name': self.resource_group_name,
            'location': self.location,
            'name': self.name,
            'id': self.id, # pylint: disable=no-member
            'sku': self.sku,
            'public_ip_allocation_method': self.public_ip_allocation_method,
            'public_ip_address_version': self.public_ip_address_version,
            'idle_timeout_in_minutes': self.idle_timeout_in_minutes
        }

        if self.domain_name_label or self.reverse_fqdn:
            parameters.update({
                'dns_settings': PublicIPAddressDnsSettings(domain_name_label=self.domain_name_label, reverse_fqdn=self.reverse_fqdn)
            })
        factory = BuildingBlock.get_sdk_model(PublicIPAddressSdk)
        return factory(**parameters)

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ip_allocation_methods)))
    def _is_valid_sku(cls, value):
        return value.value in cls._valid_skus

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ip_allocation_methods)))
    def _is_valid_ip_allocation_method(cls, value):
        return value.value in cls._valid_ip_allocation_methods

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ip_address_versions)))
    def _is_valid_ip_address_version(cls, value):
        return value.value in cls._valid_ip_address_versions

    @ValidationFunction()
    def _validate_reverse_fqdn(self, value):
        if self.public_ip_address_version == IPVersion.ipv6 and value is not None:
            return False, 'reverseFqdn cannot be set if publicIPAddressVersion is IPv6'
        return True
