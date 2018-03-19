from .building_block_settings import (BuildingBlock, RegisterBuildingBlock)
from .resources import (Resource, TopLevelResource, ResourceId, TaggedResource, ResourceReference, convert_string_to_enum, extract_resource_groups)
from ..validations import (ValidationFunction, is_none_or_whitespace)
from ..validations.networking import (is_valid_cidr, is_valid_ip_address)
from azure.mgmt.network.models import (AddressSpace,
                                       VirtualNetworkGatewayConnectionType,
                                       LocalNetworkGateway as LocalNetworkGatewaySdk,
                                       VirtualNetworkGateway as VirtualNetworkGatewaySdk,
                                       VirtualNetworkGatewayConnection as VirtualNetworkGatewayConnectionSdk,
                                       ExpressRouteCircuit as ExpressRouteCircuitSdk)

@RegisterBuildingBlock(name='Connection', template_url='buildingBlocks/connections/connections.json', deployment_name='conn')
class VirtualNetworkGatewayConnectionBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[VirtualNetworkGatewayConnection]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(VirtualNetworkGatewayConnectionBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(VirtualNetworkGatewayConnectionSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })
        cls.register_sdk_model(LocalNetworkGatewaySdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })

    def transform(self):
        local_network_gateways = [connection.local_network_gateway.transform() for connection in self.settings if connection.local_network_gateway]
        connections = [connection.transform() for connection in self.settings]
        resource_groups = extract_resource_groups(connections, local_network_gateways)
        template_parameters = {
            "connections": connections,
            "localNetworkGateways": local_network_gateways
        }
        return resource_groups, template_parameters

@ResourceId(namespace="Microsoft.Network", type="virtualNetworkGateways")
class VirtualNetworkGatewayReference(ResourceReference):
    def __init__(self, **kwargs):
        super(VirtualNetworkGatewayReference, self).__init__(**kwargs)

@ResourceId(namespace="Microsoft.Network", type="expressRouteCircuits")
class ExpressRouteCircuitReference(ResourceReference):
    def __init__(self, **kwargs):
        super(ExpressRouteCircuitReference, self).__init__(**kwargs)

@ResourceId(namespace="Microsoft.Network", type="localNetworkGateways")
class LocalNetworkGateway(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'address_prefixes': {'key': 'addressPrefixes', 'type': '[str]'},
        'ip_address': {'key': 'ipAddress', 'type': 'str'},
        'bgp_settings': {'key': 'bgpSettings', 'type': 'azure.mgmt.network.models.BgpSettings'},
    }

    def __init__(self, address_prefixes=None, ip_address=None, bgp_settings=None, **kwargs):
        super(LocalNetworkGateway, self).__init__(**kwargs)
        self.address_prefixes = address_prefixes if address_prefixes else []
        self.ip_address = ip_address
        self.bgp_settings = bgp_settings
        self._validation.update({
            'address_prefixes': {'required': True, 'min_items': 1, 'custom': LocalNetworkGateway._validate_address_prefixes},
            'ip_address': {'required': True, 'custom': is_valid_ip_address}
        })

    def transform(self):
        factory = VirtualNetworkGatewayConnectionBuildingBlock.get_sdk_model(LocalNetworkGatewaySdk)
        model = factory(
            id=self.id, # pylint: disable=no-member
            name=self.name,
            resource_group_name=self.resource_group_name,
            subscription_id=self.subscription_id,
            location=self.location,
            local_network_address_space=AddressSpace(address_prefixes=self.address_prefixes),
            gateway_ip_address=self.ip_address,
            bgp_settings=self.bgp_settings,
            tags=self.tags
        )

        return model

    @classmethod
    @ValidationFunction('One or more values is not a valid CIDR')
    def _validate_address_prefixes(cls, value):
        return all(is_valid_cidr(address_prefix) for address_prefix in value)

@ResourceId(namespace="Microsoft.Network", type="connections")
class VirtualNetworkGatewayConnection(TaggedResource, TopLevelResource, Resource):
    _valid_connection_types = frozenset([e.value for e in VirtualNetworkGatewayConnectionType])

    _attribute_map = {
        'connection_type': {'key': 'connectionType', 'type': 'str'},
        'routing_weight': {'key': 'routingWeight', 'type': 'int'},
        'shared_key': {'key': 'sharedKey', 'type': 'str'},
        'local_network_gateway': {'key': 'localNetworkGateway', 'type': 'LocalNetworkGateway'},
        'virtual_network_gateway': {'key': 'virtualNetworkGateway', 'type': 'VirtualNetworkGatewayReference'},
        'virtual_network_gateway1': {'key': 'virtualNetworkGateway1', 'type': 'VirtualNetworkGatewayReference'},
        'virtual_network_gateway2': {'key': 'virtualNetworkGateway2', 'type': 'VirtualNetworkGatewayReference'},
        'express_route_circuit': {'key': 'expressRouteCircuit', 'type': 'ExpressRouteCircuitReference'}
    }

    def __init__(self, connection_type=None, routing_weight=None, shared_key=None, local_network_gateway=None, virtual_network_gateway=None,
                 virtual_network_gateway1=None, virtual_network_gateway2=None, express_route_circuit=None, **kwargs):
        super(VirtualNetworkGatewayConnection, self).__init__(**kwargs)
        self.connection_type = convert_string_to_enum(VirtualNetworkGatewayConnectionType, connection_type)
        self.routing_weight = routing_weight
        self.shared_key = shared_key
        self.local_network_gateway = local_network_gateway
        self.virtual_network_gateway = virtual_network_gateway
        self.virtual_network_gateway1 = virtual_network_gateway1
        self.virtual_network_gateway2 = virtual_network_gateway2
        self.express_route_circuit = express_route_circuit
        self._validation.update(self._calculate_validations())

    def _calculate_validations(self):
        validations = {
            'connection_type': {'required': True, 'custom': VirtualNetworkGatewayConnection._is_valid_connection_type},
            'routing_weight': {'required': True}
        }
        if self.connection_type == VirtualNetworkGatewayConnectionType.ipsec:
            validations.update({
                'local_network_gateway': {'required': True},
                'shared_key': {'required': True, 'custom': self._validate_shared_key},
                'virtual_network_gateway': {'required': True}
            })
        elif self.connection_type == VirtualNetworkGatewayConnectionType.vnet2_vnet:
            validations.update({
                'virtual_network_gateway1': {'required': True},
                'virtual_network_gateway2': {'required': True},
                'shared_key': {'required': True, 'custom': self._validate_shared_key}
            })
        elif self.connection_type == VirtualNetworkGatewayConnectionType.express_route:
            validations.update({
                'shared_key': {'custom': self._validate_shared_key},
                'virtual_network_gateway': {'required': True},
                'express_route_circuit': {'required': True}
            })

        return validations

    def transform(self):
        kwargs = {
            "connection_type": self.connection_type,
            "id": self.id, # pylint: disable=no-member
            "name": self.name,
            "subscription_id": self.subscription_id,
            "resource_group_name": self.resource_group_name,
            "location": self.location,
            "routing_weight": self.routing_weight,
            "tags": self.tags
        }

        virtual_network_gateway_sdk_factory = VirtualNetworkGatewayConnectionBuildingBlock.get_sdk_model(VirtualNetworkGatewaySdk)
        if self.connection_type == VirtualNetworkGatewayConnectionType.ipsec:
            local_network_gateway_sdk_factory = VirtualNetworkGatewayConnectionBuildingBlock.get_sdk_model(LocalNetworkGatewaySdk)
            kwargs.update({
                "shared_key": self.shared_key,
                "virtual_network_gateway1": virtual_network_gateway_sdk_factory(id=self.virtual_network_gateway.id),
                "local_network_gateway2": local_network_gateway_sdk_factory(id=self.local_network_gateway.id)
            })
        elif self.connection_type == VirtualNetworkGatewayConnectionType.vnet2_vnet:
            kwargs.update({
                "shared_key": self.shared_key,
                "virtual_network_gateway1": virtual_network_gateway_sdk_factory(id=self.virtual_network_gateway1.id),
                "virtual_network_gateway2": virtual_network_gateway_sdk_factory(id=self.virtual_network_gateway2.id)
            })
        elif self.connection_type == VirtualNetworkGatewayConnectionType.express_route:
            express_route_circuit_sdk_factory = VirtualNetworkGatewayConnectionBuildingBlock.get_sdk_model(ExpressRouteCircuitSdk)
            kwargs.update({
                "shared_key": self.shared_key,
                "virtual_network_gateway1": virtual_network_gateway_sdk_factory(id=self.virtual_network_gateway.id),
                "peer": express_route_circuit_sdk_factory(id=self.express_route_circuit.id)
            })

        factory = VirtualNetworkGatewayConnectionBuildingBlock.get_sdk_model(VirtualNetworkGatewayConnectionSdk)
        model = factory(**kwargs)

        return model

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_connection_types)))
    def _is_valid_connection_type(cls, value):
        return value.value in cls._valid_connection_types

    @ValidationFunction()
    def _validate_shared_key(self, value):
        if self.connection_type == VirtualNetworkGatewayConnectionType.express_route and value is not None:
            return False, 'sharedKey cannot be specified for an ExpressRoute connection'
        return not is_none_or_whitespace(value), 'shared_key must be specified for connection_type {}'.format(self.connection_type)
