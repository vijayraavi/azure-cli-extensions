from azure.mgmt.network.models import (RouteNextHopType, SubResource, Route as RouteSdk, RouteTable as RouteTableSdk)
from msrestazure.tools import (resource_id)
from .building_block_settings import (BuildingBlock, RegisterBuildingBlock)
from .resources import (TaggedResource, TopLevelResource, Resource, ResourceId, convert_string_to_enum, extract_resource_groups)
from ..validations import(ValidationFunction)
from ..validations.networking import (is_valid_ip_address, is_valid_cidr)
from ..validations.utilities import (duplicates)

@RegisterBuildingBlock(name='RouteTable', template_url='buildingBlocks/routeTables/routeTables.json', deployment_name='rt')
class RouteTableBuildingBlock(BuildingBlock):

    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[RouteTable]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(RouteTableBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(RouteTableSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}
        })

    def transform(self):
        # Make sure we have validated before this! :)
        subnets = [RouteTableSubnet(
            name=subnet,
            subscription_id=virtual_network.subscription_id,
            resource_group_name=virtual_network.resource_group_name,
            location=virtual_network.location,
            virtual_network_name=virtual_network.name,
            route_table_id=route_table.id
        ) for route_table in self.settings for virtual_network in route_table.virtual_networks for subnet in virtual_network.subnets]
        route_tables = [route_table.transform() for route_table in self.settings]

        resource_groups = extract_resource_groups(route_tables)
        template_parameters = {
            "routeTables": route_tables,
            "subnets": subnets
        }

        return resource_groups, template_parameters

class Route(Resource):
    _attribute_map = {
        'next_hop': {'key': 'nextHop', 'type': 'str'},
        'address_prefix': {'key': 'addressPrefix', 'type': 'str'}
    }

    _valid_next_hop_types = [e.value for e in RouteNextHopType if e != RouteNextHopType.virtual_appliance]

    def __init__(self, next_hop=None, address_prefix=None, **kwargs):
        super(Route, self).__init__(**kwargs)
        self.next_hop = next_hop
        self.address_prefix = address_prefix
        self._validation.update({
            'next_hop': {'required': True, 'custom': Route._is_valid_next_hop},
            'address_prefix': {'required': True, 'custom': is_valid_cidr}
        })

    def transform(self):
        if is_valid_ip_address(self.next_hop):
            next_hop_type = RouteNextHopType.virtual_appliance
            next_hop_ip_address = self.next_hop
        else:
            next_hop_type = convert_string_to_enum(RouteNextHopType, self.next_hop)
            next_hop_ip_address = None

        factory = RouteTableBuildingBlock.get_sdk_model(RouteSdk)
        model = factory(
            next_hop_type=next_hop_type,
            address_prefix=self.address_prefix,
            next_hop_ip_address=next_hop_ip_address,
            name=self.name)
        return model

    @classmethod
    @ValidationFunction('Valid values are an IP Address or one of the following values: {}'.format(','.join(_valid_next_hop_types)))
    def _is_valid_next_hop(cls, value):
        return is_valid_ip_address(value) or value in cls._valid_next_hop_types

# We need a small class here since we aren't using an sdk class for the subnet wiring
class RouteTableSubnet(TopLevelResource, Resource):
    def __init__(self, virtual_network_name=None, route_table_id=None, **kwargs):
        super(RouteTableSubnet, self).__init__(**kwargs)
        self.virtual_network_name = virtual_network_name
        self.route_table = SubResource(id=route_table_id)
        # We will set the id here instead of using the decorator
        self.id = resource_id(
            subscription=self.subscription_id,
            resource_group=self.resource_group_name,
            namespace="Microsoft.Network",
            type="virtualNetworks",
            name=self.virtual_network_name,
            child_type_1="subnets",
            child_name_1=self.name)

    _attribute_map = {
        'virtual_network_name': {'key': 'virtualNetwork', 'type': 'str'},
        'route_table': {'key': 'properties.routeTable', 'type': 'SubResource'}
    }

@ResourceId(namespace="Microsoft.Network", type="routeTables")
class RouteTable(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'disable_bgp_route_propagation': {'key': 'disableBgpRoutePropagation', 'type': 'bool'},
        'routes': {'key': 'routes', 'type': '[Route]'},
        'virtual_networks': {'key': 'virtualNetworks', 'type' :'[VirtualNetworkReference]'}
    }

    def __init__(self, disable_bgp_route_propagation=None, routes=None, virtual_networks=None, **kwargs):
        super(RouteTable, self).__init__(**kwargs)
        self.disable_bgp_route_propagation = disable_bgp_route_propagation if disable_bgp_route_propagation is not None else False
        self.routes = routes if routes else []
        self.virtual_networks = virtual_networks if virtual_networks else []
        self._validation.update({
            'routes': {'required': True, 'min_items': 1, 'custom': self._find_duplicate_route_names},
            'virtual_networks': {'required': True}
        })

    def transform(self):
        routes = [r.transform() for r in self.routes]
        factory = RouteTableBuildingBlock.get_sdk_model(RouteTableSdk)
        model = factory(
            name=self.name,
            id=self.id, # pylint: disable=E1101
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            disable_bgp_route_propagation=self.disable_bgp_route_propagation,
            routes=routes,
            tags=self.tags)
        return model

    @ValidationFunction()
    def _find_duplicate_route_names(self, routes):
        # Ignore invalid names, as they will be caught by the Route validations
        duplicate_list = duplicates(routes, 'name')
        return len(duplicate_list) == 0, 'Duplicate route names: {}'.format(','.join(duplicate_list))
