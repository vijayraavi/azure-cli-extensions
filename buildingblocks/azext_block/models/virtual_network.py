from azure.mgmt.network.models import (AddressSpace,
                                       DhcpOptions,
                                       Subnet as SubnetSdk,
                                       SubResource,
                                       VirtualNetwork as VirtualNetworkSdk,
                                       VirtualNetworkPeering as VirtualNetworkPeeringSdk)
from .building_block_settings import (BuildingBlock, RegisterBuildingBlock)
from .resources import (Resource, ResourceId, ResourceReference, TaggedResource, TopLevelResource, extract_resource_groups)
from ..validations.networking import (is_valid_cidr)

@RegisterBuildingBlock(name='VirtualNetwork', template_url='buildingBlocks/virtualNetworks/virtualNetworks.json', deployment_name='vnet')
class VirtualNetworkBuildingBlock(BuildingBlock):

    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[VirtualNetwork]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(VirtualNetworkBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    def transform(self):
        # Make sure we have validated before this! :)
        virtual_networks = [vnet.transform() for vnet in self.settings]
        virtual_network_peerings = [peering for vnet in virtual_networks for peering in vnet.virtual_network_peerings]
        for vnet in virtual_networks:
            vnet.virtual_network_peerings = None

        resource_groups = extract_resource_groups(virtual_networks)
        template_parameters = {
            "virtualNetworks": virtual_networks,
            "virtualNetworkPeerings": virtual_network_peerings
        }
        return resource_groups, template_parameters

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(VirtualNetworkSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })
        cls.register_sdk_model(VirtualNetworkPeeringSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'},
            'location': {'key': 'location', 'type': 'str'}
        })

@ResourceId(namespace="Microsoft.Network", type="virtualNetworks")
class VirtualNetwork(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'address_prefixes': {'key': 'addressPrefixes', 'type': '[str]'},
        'subnets': {'key': 'subnets', 'type': '[Subnet]', 'parent': 'virtualNetwork'},
        'dns_servers': {'key': 'dnsServers', 'type': '[str]'},
        'virtual_network_peerings': {'key': 'virtualNetworkPeerings', 'type': '[VirtualNetworkPeering]', 'parent': 'virtual_network'}#,
        #'enable_ddos_protection': {'key': 'enableDdosProtection', 'type': 'bool'},
        #'enable_vm_protection': {'key': 'enableVmProtection', 'type': 'bool'}
    }

    def __init__(self, address_prefixes=None, subnets=None, dns_servers=None, virtual_network_peerings=None, enable_ddos_protection=None, enable_vm_protection=None, **kwargs):
        super(VirtualNetwork, self).__init__(**kwargs)
        self.address_prefixes = address_prefixes if address_prefixes else []
        self.subnets = subnets if subnets else []
        self.dns_servers = dns_servers if dns_servers else []
        self.virtual_network_peerings = virtual_network_peerings if virtual_network_peerings else []
        # Preview for now
        #self.enable_ddos_protection = enable_ddos_protection if enable_ddos_protection else True
        #self.enable_vm_protection = enable_vm_protection if enable_vm_protection else True
        self._validation.update({
            'address_prefixes': {'required': True, 'min_items': 1},
            'subnets': {'required': True, 'min_items': 1},
            'dns_servers': {'required': True},
            'virtual_network_peerings': {'required': True}#,
            #'enable_ddos_protection': {'required': True},
            #'enable_vm_protection': {'required': True}
        })

    def transform(self):
        factory = VirtualNetworkBuildingBlock.get_sdk_model(VirtualNetworkSdk)
        model = factory(
            id=self.id, # pylint: disable=no-member
            name=self.name,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            address_space=AddressSpace(address_prefixes=self.address_prefixes),
            dhcp_options=DhcpOptions(dns_servers=self.dns_servers),
            subnets=[s.transform() for s in self.subnets],
            virtual_network_peerings=[p.transform() for p in self.virtual_network_peerings],
            #enable_ddos_protection=self.enable_ddos_protection,
            #enable_vm_protection=self.enable_vm_protection,
            tags=self.tags
        )

        return model

class Subnet(Resource):
    _attribute_map = {
        'address_prefix': {'key': 'addressPrefix', 'type': 'str'}
    }

    def __init__(self, address_prefix=None, **kwargs):
        super(Subnet, self).__init__(**kwargs)
        self.address_prefix = address_prefix
        self._validation.update({
            'address_prefix': {'required': True, 'custom': is_valid_cidr}
        })

    def transform(self):
        factory = VirtualNetworkBuildingBlock.get_sdk_model(SubnetSdk)
        model = factory(
            name=self.name,
            address_prefix=self.address_prefix
        )

        return model

@ResourceId(namespace="Microsoft.Network", type="virtualNetworks")
class RemoteVirtualNetworkReference(ResourceReference):
    def __init__(self, **kwargs):
        super(RemoteVirtualNetworkReference, self).__init__(**kwargs)

class VirtualNetworkPeering(TopLevelResource, Resource):
    _attribute_map = {
        'allow_virtual_network_access': {'key': 'allowVirtualNetworkAccess', 'type': 'bool'},
        'allow_forwarded_traffic': {'key': 'allowForwardedTraffic', 'type': 'bool'},
        'allow_gateway_transit': {'key': 'allowGatewayTransit', 'type': 'bool'},
        'use_remote_gateways': {'key': 'useRemoteGateways', 'type': 'bool'},
        #'remote_virtual_network': {'key': 'remoteVirtualNetwork', 'type': 'ResourceReference'}
        'remote_virtual_network': {'key': 'remoteVirtualNetwork', 'type': 'RemoteVirtualNetworkReference'}
    }

    def __init__(self, allow_virtual_network_access=None, allow_forwarded_traffic=None, allow_gateway_transit=None, use_remote_gateways=None, remote_virtual_network=None, **kwargs):
        super(VirtualNetworkPeering, self).__init__(**kwargs)
        self.allow_virtual_network_access = allow_virtual_network_access if allow_virtual_network_access is not None else False
        self.allow_forwarded_traffic = allow_forwarded_traffic if allow_forwarded_traffic is not None else False
        self.allow_gateway_transit = allow_gateway_transit if allow_gateway_transit is not None else False
        self.use_remote_gateways = use_remote_gateways if use_remote_gateways is not None else False
        self.remote_virtual_network = remote_virtual_network
        self.name = self.name if self.name else "{}-peer".format(self.remote_virtual_network.name) if self.remote_virtual_network.name else None
        self._validation.update({
            'allow_virtual_network_access': {'required': True},
            'allow_forwarded_traffic': {'required': True},
            'allow_gateway_transit': {'required': True},
            'use_remote_gateways': {'required': True},
            'remote_virtual_network': {'required': True}
        })

    def transform(self):
        factory = VirtualNetworkBuildingBlock.get_sdk_model(VirtualNetworkPeeringSdk)
        model = factory(
            name="{}/{}".format(self.virtual_network.name, self.name), # pylint: disable=E1101
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            allow_virtual_network_access=self.allow_virtual_network_access,
            allow_forwarded_traffic=self.allow_forwarded_traffic,
            allow_gateway_transit=self.allow_gateway_transit,
            use_remote_gateways=self.use_remote_gateways,
            remote_virtual_network=SubResource(id=self.remote_virtual_network.id)
        )

        return model
