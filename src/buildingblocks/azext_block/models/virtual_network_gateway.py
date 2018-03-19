from ..validations import(ValidationFunction)
from .public_ip_address import (PublicIPAddress)
from .building_block_settings import (BuildingBlock, RegisterBuildingBlock)
from .resources import (TaggedResource, TopLevelResource, Resource, ResourceId, convert_string_to_enum, extract_resource_groups)
from msrestazure.tools import (resource_id)
from azure.mgmt.network.models import (
    SubResource,
    VirtualNetworkGatewayIPConfiguration,
    VirtualNetworkGatewayType,
    VpnType,
    VirtualNetworkGateway as VirtualNetworkGatewaySdk,
    VirtualNetworkGatewaySku,
    VirtualNetworkGatewaySkuName
)

@RegisterBuildingBlock(name='VirtualNetworkGateway', template_url='buildingBlocks/virtualNetworkGateways/virtualNetworkGateways.json', deployment_name='vngw')
class VirtualNetworkGatewayBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[VirtualNetworkGateway]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(VirtualNetworkGatewayBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(VirtualNetworkGatewaySdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })

    def transform(self):
        # Make sure we have validated before this! :)
        public_ip_addresses = [virtual_network_gateway.public_ip_address.transform() for virtual_network_gateway in self.settings if virtual_network_gateway.public_ip_address]
        virtual_network_gateways = [virtual_network_gateway.transform() for virtual_network_gateway in self.settings]

        resource_groups = extract_resource_groups(virtual_network_gateways, public_ip_addresses)
        template_parameters = {
            "virtualNetworkGateways": virtual_network_gateways,
            "publicIpAddresses": public_ip_addresses
        }
        return resource_groups, template_parameters

@ResourceId(namespace="Microsoft.Network", type="virtualNetworkGateways")
class VirtualNetworkGateway(TaggedResource, TopLevelResource, Resource):

    _valid_gateway_types = frozenset([e.value for e in VirtualNetworkGatewayType])
    _valid_vpn_types = frozenset([e.value for e in VpnType])
    _valid_vpn_skus = frozenset([e.value for e in [VirtualNetworkGatewaySkuName.basic, VirtualNetworkGatewaySkuName.vpn_gw1, VirtualNetworkGatewaySkuName.vpn_gw2, VirtualNetworkGatewaySkuName.vpn_gw3]])
    _valid_express_route_skus = frozenset([e.value for e in [VirtualNetworkGatewaySkuName.standard, VirtualNetworkGatewaySkuName.high_performance, VirtualNetworkGatewaySkuName.ultra_performance]])

    _attribute_map = {
        'gateway_type': {'key': 'gatewayType', 'type': 'str'},
        'vpn_type': {'key': 'vpnType', 'type': 'str'},
        'enable_bgp': {'key': 'enableBgp', 'type': 'bool'},
        'active_active': {'key': 'activeActive', 'type': 'bool'},
        #'gateway_default_site': {'key': 'properties.gatewayDefaultSite', 'type': 'SubResource'},
        'sku': {'key': 'sku', 'type': 'str'},
        #'vpn_client_configuration': {'key': 'properties.vpnClientConfiguration', 'type': 'VpnClientConfiguration'},
        'bgp_settings': {'key': 'bgpSettings', 'type': 'azure.mgmt.network.models.BgpSettings'},
        'virtual_network': {'key': 'virtualNetwork', 'type': 'ResourceReference'},
        'is_public': {'key': 'isPublic', 'type': 'bool'},
        'public_ip_address_version': {'key': 'publicIPAddressVersion', 'type': 'str'},
        'domain_name_label': {'key': 'domainNameLabel', 'type': 'str'},
        'public_ip_address': {'key': 'publicIPAddress', 'type': 'PublicIPAddress'}
    }

    def __init__(self, gateway_type=None, vpn_type=None, enable_bgp=None, active_active=None, sku=None, bgp_settings=None, virtual_network=None, is_public=None, public_ip_address_version=None, domain_name_label=None, **kwargs):
        super(VirtualNetworkGateway, self).__init__(**kwargs)
        self.gateway_type = convert_string_to_enum(VirtualNetworkGatewayType, gateway_type) if gateway_type else VirtualNetworkGatewayType.vpn
        self.vpn_type = convert_string_to_enum(VpnType, vpn_type) if vpn_type else VpnType.route_based
        self.enable_bgp = enable_bgp if enable_bgp is not None else False
        self.active_active = active_active if active_active is not None else False
        self.sku = convert_string_to_enum(VirtualNetworkGatewaySkuName, sku) if sku else VirtualNetworkGatewaySkuName.vpn_gw1
        self.bgp_settings = bgp_settings
        self.virtual_network = virtual_network
        self.is_public = is_public if is_public is not None else False
        self.public_ip_address_version = public_ip_address_version
        self.domain_name_label = domain_name_label
        # Create our public ip address, if needed
        public_ip_address_parameters = {
            'subscription_id': self.subscription_id,
            'resource_group_name': self.resource_group_name,
            'location': self.location,
            'name': '{}-pip'.format(self.name),
            'tags': None,
            'sku': None,
            'public_ip_allocation_method': 'Dynamic',
            'public_ip_address_version': self.public_ip_address_version,
            'idle_timeout_in_minutes': None,
            'zones': None,
            'domain_name_label': self.domain_name_label
        }

        self.public_ip_address = PublicIPAddress(**public_ip_address_parameters) if self.is_public else None
        self._validation.update({
            'gateway_type': {'required': True, 'custom': VirtualNetworkGateway._is_valid_gateway_type},
            'vpn_type': {'required': True, 'custom': VirtualNetworkGateway._is_valid_vpn_type},
            'sku': {'required': True, 'custom': self._is_valid_sku},
            'virtual_network': {'required': True, 'custom': self._validate_virtual_network},
            'is_public': {'required': False, 'custom': self._validate_is_public}
        })

    def transform(self):
        ip_configuration_parameters = {
            'private_ip_allocation_method': 'Dynamic',
            'name': '{}-ipconfig'.format(self.name),
            'subnet': SubResource(id=resource_id(
                subscription=self.virtual_network.subscription_id,
                resource_group=self.virtual_network.resource_group_name,
                namespace='Microsoft.Network',
                type='virtualNetworks',
                name=self.virtual_network.name,
                child_type_1="subnets",
                child_name_1="GatewaySubnet"))
        }
        if self.public_ip_address:
            ip_configuration_parameters.update({
                'public_ip_address': SubResource(id=self.public_ip_address.id)
            })
        ip_configuration = VirtualNetworkGatewayIPConfiguration(**ip_configuration_parameters)

        factory = VirtualNetworkGatewayBuildingBlock.get_sdk_model(VirtualNetworkGatewaySdk)
        model = factory(
            name=self.name,
            id=self.id, # pylint: disable=no-member
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            ip_configurations=[ip_configuration],
            gateway_type=self.gateway_type,
            vpn_type=self.vpn_type,
            enable_bgp=self.enable_bgp,
            active_active=self.active_active,
            gateway_default_site=None,
            sku=VirtualNetworkGatewaySku(name=self.sku, tier=self.sku.value),
            vpn_client_configuration=None,
            bgp_settings=self.bgp_settings
        )

        return model

    @ValidationFunction()
    def _is_valid_sku(self, value):
        if self.gateway_type == VirtualNetworkGatewayType.vpn:
            return VirtualNetworkGateway._is_valid_vpn_sku(value), 'Value must be one of the following values: {}'.format(','.join(VirtualNetworkGateway._valid_vpn_skus))
        elif self.gateway_type == VirtualNetworkGatewayType.express_route:
            return VirtualNetworkGateway._is_valid_express_route_sku(value), 'Value must be one of the following values: {}'.format(','.join(VirtualNetworkGateway._valid_express_route_skus))
        else:
            return False, 'Unknown gateway_type: {}'.format(self.gateway_type)

    @ValidationFunction()
    def _validate_virtual_network(self, value):
        return self.subscription_id == value.subscription_id and self.resource_group_name == value.resource_group_name and self.location == value.location, 'Virtual Network Gateways must be created in the same subscription, resource group, and location as the associated Virtual Network'

    @ValidationFunction()
    def _validate_is_public(self, value):
        if self.gateway_type == VirtualNetworkGatewayType.express_route and not value:
            return False, "Value must be true for an ExpressRoute Virtual Network Gateway"
        return True

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_gateway_types)))
    def _is_valid_gateway_type(cls, value):
        return value.value in cls._valid_gateway_types

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_vpn_types)))
    def _is_valid_vpn_type(cls, value):
        return value.value in cls._valid_vpn_types

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_vpn_skus)))
    def _is_valid_vpn_sku(cls, value):
        return value.value in cls._valid_vpn_skus

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_express_route_skus)))
    def _is_valid_express_route_sku(cls, value):
        return value.value in cls._valid_express_route_skus
