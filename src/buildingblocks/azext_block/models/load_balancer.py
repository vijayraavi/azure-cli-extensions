from azure.mgmt.network.models import (LoadBalancer as LoadBalancerSdk,
                                       LoadBalancerSkuName, SubResource)
from msrestazure.tools import resource_id

from .building_block_settings import (BuildingBlock,
                                      RegisterBuildingBlock)
from .resources import (Resource,
                        ResourceId,
                        TaggedResource,
                        TopLevelResource,
                        convert_string_to_enum,
                        extract_resource_groups)
from ..validations import ValidationFunction

@RegisterBuildingBlock(name='LoadBalancer', template_url='buildingBlocks/loadBalancers/loadBalancers.json', deployment_name='lb')
class LoadBalancerBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[LoadBalancer]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(LoadBalancerBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(LoadBalancerSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}
        })

    def transform(self):
        pass
        # # Make sure we have validated before this! :)
        # subnets = [NetworkSecurityGroupSubnet(
        #     name=subnet,
        #     subscription_id=virtual_network.subscription_id,
        #     resource_group_name=virtual_network.resource_group_name,
        #     location=virtual_network.location,
        #     virtual_network_name=virtual_network.name,
        #     network_security_group_id=network_security_group.id
        # ) for network_security_group in self.settings for virtual_network in network_security_group.virtual_networks for subnet in virtual_network.subnets]
        # network_interfaces = [NetworkSecurityGroupNetworkInterface(
        #     name=network_interface.name,
        #     subscription_id=network_interface.subscription_id,
        #     resource_group_name=network_interface.resource_group_name,
        #     location=network_interface.location,
        #     network_security_group_id=network_security_group.id
        # ) for network_security_group in self.settings for network_interface in network_security_group.network_interfaces]
        load_balancers = [load_balancer.transform() for load_balancer in self.settings]

        resource_groups = extract_resource_groups(load_balancers)
        template_parameters = {
            "loadBalancers": load_balancers
        }

        return resource_groups, template_parameters

@ResourceId(namespace='Microsoft.Network', type='networkSecurityGroups')
class LoadBalancer(TaggedResource, TopLevelResource, Resource):
    _valid_skus = frozenset([e.value for e in LoadBalancerSkuName])

    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'str'},
        'virtual_network': {'key': 'virtualNetwork', 'type': 'ResourceReference'}#,
        # 'frontend_ip_configurations': {'key': 'properties.frontendIPConfigurations', 'type': '[FrontendIPConfiguration]'},
        # 'backend_address_pools': {'key': 'properties.backendAddressPools', 'type': '[BackendAddressPool]'},
        # 'load_balancing_rules': {'key': 'properties.loadBalancingRules', 'type': '[LoadBalancingRule]'},
        # 'probes': {'key': 'properties.probes', 'type': '[Probe]'},
        # 'inbound_nat_rules': {'key': 'properties.inboundNatRules', 'type': '[InboundNatRule]'},
        # 'inbound_nat_pools': {'key': 'properties.inboundNatPools', 'type': '[InboundNatPool]'},
    }

    def __init__(self, sku=None, **kwargs):
        super(LoadBalancer, self).__init__(**kwargs)
        self.sku = sku if sku else LoadBalancerSkuName.basic
        # # We can expand the named rules here.
        # self.security_rules = NetworkSecurityGroup._expand_named_security_rules(security_rules if security_rules else [])
        # # Now we need to re-prioritize
        # for index, security_rule in enumerate(self.security_rules):
        #     security_rule.priority = (index * 10) + 100
        # self.virtual_networks = virtual_networks if virtual_networks else []
        # self.network_interfaces = network_interfaces if network_interfaces else []
        self._validation.update({
            'sku': {'required': True, 'custom': LoadBalancer._is_valid_sku}
        })

    def transform(self):
        factory = LoadBalancerBuildingBlock.get_sdk_model(LoadBalancerSdk)
        model = factory(
            id=self.id,  # pylint: disable=no-member
            name=self.name,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            tags=self.tags,
            sku=self.sku#,
            #security_rules=[security_rule.transform() for security_rule in self.security_rules]
        )

        return model

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_skus)))
    def _is_valid_sku(cls, value):
        return value.value in cls._valid_skus
