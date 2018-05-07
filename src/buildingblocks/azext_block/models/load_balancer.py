from azure.mgmt.network.models import (LoadBalancer as LoadBalancerSdk,
                                        BackendAddressPool as BackendAddressPoolSdk,
                                        LoadBalancerSkuName, 
                                        SubResource,
                                        FrontendIPConfiguration as FrontendIPConfigurationSdk,
                                        LoadBalancingRule as LoadBalancingRuleSdk,
                                        Probe as ProbeSdk,
                                        InboundNatRule as InboundNatRuleSdk,
                                        InboundNatPool as InboundNatPoolSdk,
                                        ProbeProtocol,
                                        TransportProtocol,
                                        LoadDistribution)

from msrestazure.tools import resource_id

from .building_block_settings import (BuildingBlock,
                                      RegisterBuildingBlock)
from .resources import (Resource,
                        ResourceId,
                        TaggedResource,
                        TopLevelResource,
                        ResourceReference,
                        BuildingBlockModel,
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
    def onregister(self):
        self.register_sdk_model(LoadBalancerSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}
        })

    def transform(self):
        load_balancers = [load_balancer.transform() for load_balancer in self.settings]

        resource_groups = extract_resource_groups(load_balancers)
        template_parameters = {
            "loadBalancers": load_balancers
        }

        return resource_groups, template_parameters

@ResourceId(namespace='Microsoft.Network', type='loadBalancers')
class LoadBalancer(TaggedResource, TopLevelResource, Resource):
    _valid_skus = frozenset([e.value for e in LoadBalancerSkuName])
    
    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'str'},
        'virtual_network': {'key': 'virtualNetwork', 'type': 'ResourceReference'},
        'frontend_ip_configurations': {'key': 'FrontendIPConfigurations', 'type': '[LoadBalancerFrontendIPConfiguration]', 'parent': 'load_balancer'},
        'backend_pools': {'key': 'backendPools', 'type': '[LoadBalancerBackendAddressPool]'},
        'load_balancing_rules': {'key': 'loadBalancingRules', 'type': '[LoadBalancingRule]', 'parent': 'load_balancer'},
        'probes': {'key': 'probes', 'type': '[LoadBalancerProbe]', 'parent': 'load_balancer'},
        'inbound_nat_rules': {'key': 'inboundNatRules', 'type': '[InboundNatRule]', 'parent': 'load_balancer'},
        'inbound_nat_pools': {'key': 'inboundNatPools', 'type': '[InboundNatPool]', 'parent': 'load_balancer'},
    }

    def __init__(self, sku=None, virtual_network=None, frontend_ip_configurations=None, backend_pools=None, load_balancing_rules=None, probes=None, inbound_nat_rules=None, inbound_nat_pools=None, **kwargs):
        super(LoadBalancer, self).__init__(**kwargs)
        self.sku = sku if sku else LoadBalancerSkuName.basic
        self.virtual_network = virtual_network if virtual_network is not None else None
        self.frontend_ip_configurations = frontend_ip_configurations if frontend_ip_configurations is not None else []
        self.backend_pools = backend_pools if backend_pools is not None else []
        self.load_balancing_rules = load_balancing_rules if load_balancing_rules is not None else  []
        self.probes = probes if probes is not None else []
        self.inbound_nat_pools = inbound_nat_pools if inbound_nat_pools is not None else []
        self.inbound_nat_rules = inbound_nat_rules if inbound_nat_rules is not None else []

        self._validation.update({
            'sku': {'required': True, 'custom': LoadBalancer._is_valid_sku},
            #'load_balancing_rules': {'required': True, 'min_items': 1},
            #'backend_pools': {'required': True, 'min_items': 1},
            'frontend_ip_configurations': {'required': True, 'min_items': 1}
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
            sku=self.sku,
            frontend_ip_configurations = [f.transform() for f in self.frontend_ip_configurations],
            backend_address_pools = [b.transform() for b in self.backend_pools],
            load_balancing_rules = [l.transform() for l in self.load_balancing_rules],
            probes= [p.transform() for p in self.probes],
            inbound_nat_pools=[i.transform() for i in self.inbound_nat_pools],
            inbound_nat_rules=[i.transform() for i in self.inbound_nat_rules]
        )

        return model

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_skus)))
    def _is_valid_sku(self, value):
        return value.value in self._valid_skus

    @staticmethod
    @ValidationFunction()
    def _is_valid_transport_protocol(value):
        _valid_transport_protocols = [e.value for e in TransportProtocol]

        return value.value in _valid_transport_protocols, 'Invalid transport protocol. Value must be in {}'.format(','.join(_valid_transport_protocols))
    
    @staticmethod
    @ValidationFunction('Idle timeout must be between 4 and 30 minutes for TCP')
    def _is_valid_idle_timeout_in_minutes(value):
        if value >= 4 and value <=30:
            return True
        else:
            return False

    @staticmethod
    @ValidationFunction('Is not valid port')
    def _is_valid_port(value):
        return 1 <= value <= 65535

class LoadBalancerFrontendIPConfiguration(TopLevelResource, Resource):
    _attribute_map = {
        'load_balancer_type': {'key': 'loadBalancerType', 'type': 'str'},
        'public_ip_address': {'key': 'publicIpAddress', 'type': 'str'},
        'internal_load_balancer_settings': {'key': 'internalLoadBalancerSettings', 'type': 'InternalLoadBalancerSetting', 'parent': 'frontend_ip_configuration'}
    }

    def __init__(self, load_balancer_type=None, public_ip_address=None, internal_load_balancer_settings=None, **kwargs):
        super(LoadBalancerFrontendIPConfiguration, self).__init__(**kwargs)
        self.load_balancer_type = load_balancer_type if load_balancer_type else 'Public'
        self.public_ip_address = public_ip_address if public_ip_address else None
        self.internal_load_balancer_settings = internal_load_balancer_settings if internal_load_balancer_settings else None
        self._validation.update({
            'load_balancer_type': {'required': True, 'custom': self._is_valid_load_balancer_type},
            'internal_load_balancer_settings': {'required': False, 'custom': self._is_valid_internal_load_balancer_settings},
            'public_ip_address': {'required': False, 'custom': self._is_valid_public_ip_address}
        })

    def transform(self):
        # default name to default-feConfig if name is none
        factory = LoadBalancerBuildingBlock.get_sdk_model(FrontendIPConfigurationSdk)

        if self.load_balancer_type == 'Internal':
            model = factory(
                name = self.name if self.name else 'default-feConfig',
                private_ip_allocation_method = 'Static',
                private_ip_address = self.internal_load_balancer_settings.private_ip_address,
                subnet = SubResource(id=resource_id(
                    subscription=self.subscription_id,  # pylint: disable=E1101
                    resource_group=self.resource_group_name,  # pylint: disable=E1101
                    namespace='Microsoft.Network',
                    type='virtualNetworks',
                    name=self.internal_load_balancer_settings.subnet_name,  # pylint: disable=E1101
                    child_type_1='subnets',
                    child_name_1=self.internal_load_balancer_settings.subnet_name)) if self.internal_load_balancer_settings and self.internal_load_balancer_settings.subnet_name else None
            )

            return model
        elif self.load_balancer_type == 'Public':
            model = factory(
                name = self.name if self.name else 'default-feConfig',
                private_ip_allocation_method = 'Dyanamic',
                public_ip_address = SubResource(id=resource_id(
                    subscription=self.subscription_id, # pylint: disable=E1101
                    resource_group=self.resource_group_name, # pylint: disable=E1101
                    namespace='Microsoft.Network',
                    type='publicIPAddresses',
                    name= self.public_ip_address))
            )

            return model

    @ValidationFunction('Value must be one of the following values: Public, Internal')
    def _is_valid_load_balancer_type(self, value):
        types = ['Public', 'Internal']

        if value in types:
            return True
        else:
            return False

    @ValidationFunction()
    def _is_valid_internal_load_balancer_settings(self, value):
        if value == None and self.load_balancer_type == 'Internal':   # pylint: disable=E1101
            return False, 'Value must be set if loadBalancerType is internal'
        elif self.load_balancer_type == 'Public' and value != None: # pylint: disable=E1101
            return False, 'Value must not be set loadBalancerType is Public'
        else:
            return True

    @ValidationFunction()
    def _is_valid_public_ip_address(self, value):
        if self.load_balancer_type == 'Public' and value == None: # pylint: disable=E1101
            return False, 'If loadBalancerType is Public, publicIPAddress must be specified'
        elif self.load_balancer_type == 'Internal' and value != None: # pylint: disable=E1101
            return False, 'If load balancer is Internal then publicIPAddress must not be set'
        else:
            return True

class LoadBalancerBackendAddressPool(Resource):
    _attribute_map = {

    }

    def __init__(self,**kwargs):
        super(LoadBalancerBackendAddressPool, self).__init__(**kwargs)

    def transform(self):
        factory = LoadBalancerBuildingBlock.get_sdk_model(BackendAddressPoolSdk)

        model = factory(
            name = self.name
        )

        return model

class LoadBalancingRule(TopLevelResource, Resource):
    _attribute_map = {
        'protocol': {'key': 'protocol', 'type': 'str'},
        'idle_timeout_in_minutes': {'key': 'idleTimeoutInMinutes', 'type': 'int'},
        'frontend_ip_configuration_name': {'key': 'FrontendIPConfigurationName', 'type': 'str'},
        'backend_pool_name': {'key': 'backendPoolName', 'type': 'str'},
        'frontend_port': {'key': 'frontendPort', 'type': 'int'},
        'backend_port': {'key': 'backendPort', 'type': 'int'},
        'enable_floating_ip': {'key': 'enableFloatingIP', 'type': 'bool'},
        'probe_name': {'key': 'probeName', 'type': 'str'},
        'load_distribution': {'key': 'loadDistribution', 'type': 'str'}
    }

    _valid_load_distribution = frozenset([e.value for e in LoadDistribution])

    def __init__(self, protocol=None, idle_timeout_in_minutes=None, frontend_ip_configuration_name=None, backend_pool_name=None, frontend_port=None, backend_port=None, enable_floating_ip=None, probe_name=None, load_distribution=None, **kwargs):
        super(LoadBalancingRule, self).__init__(**kwargs)
        self.protocol = protocol if protocol else None
        self.idle_timeout_in_minutes = idle_timeout_in_minutes if idle_timeout_in_minutes else None
        self.frontend_ip_configuration_name = frontend_ip_configuration_name if frontend_ip_configuration_name else None # Default frontend ip configuraton to name 'default-feConfig' and type = public
        self.backend_pool_name = backend_pool_name if backend_pool_name else None
        self.frontend_port = frontend_port if frontend_port else None
        self.backend_port = backend_port if backend_port else None
        self.enable_floating_ip = enable_floating_ip if enable_floating_ip else None
        self.probe_name = probe_name if probe_name else None
        self.load_distribution = load_distribution if load_distribution else 'Default'
        self._validation.update({
            'backend_pool_name': {'custom': self._is_valid_backend_pool_name},
            'frontend_ip_configuration_name': {'custom': self._is_valid_frontend_ip_configuration},
            'probe_name': {'custom': self._is_valid_probe_name},
            'load_distribution': {'required': True, 'custom': LoadBalancingRule._is_valid_load_distribution},
            'idle_timeout_in_minutes': {'custom': LoadBalancer._is_valid_idle_timeout_in_minutes},
            'frontend_port': {'required': True, 'custom': LoadBalancer._is_valid_port},
            'backend_port': {'required': True, 'custom': LoadBalancer._is_valid_port}
        })

    def transform(self):
        
        factory = LoadBalancerBuildingBlock.get_sdk_model(LoadBalancingRuleSdk)

        model = factory(
            frontend_ip_configuration = SubResource(id=resource_id(
                subscription=self.subscription_id, # pylint: disable=E1101
                resource_group=self.resource_group_name, # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='loadBalancers',
                name=self.load_balancer.name, # pylint: disable=E1101
                child_type_1='FrontendIPConfigurations',
                child_name_1=self.frontend_ip_configuration_name)) if self.frontend_ip_configuration_name else None,
            backend_address_pool = SubResource(id=resource_id(
                subscription=self.subscription_id, # pylint: disable=E1101
                resource_group=self.resource_group_name, # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='loadBalancers',
                name=self.load_balancer.name, # pylint: disable=E1101
                child_type_1='backendAddressPools',
                child_name_1=self.backend_pool_name)) if self.backend_pool_name else None,
            frontend_port = self.frontend_port,
            backend_port = self.backend_port,
            protocol = self.protocol,
            enable_floating_ip = self.enable_floating_ip,
            load_distribution = self.load_distribution,
            probe = SubResource(id=resource_id(
                subscription=self.subscription_id, # pylint: disable=E1101
                resource_group=self.resource_group_name, # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='loadBalancers',
                name=self.load_balancer.name, # pylint: disable=E1101
                child_type_1='probes',
                child_name_1=self.probe_name)) if self.probe_name else None,
        )
        
        return model

    @classmethod
    @ValidationFunction('Valid values must be one of the following: {}'.format(','.join(_valid_load_distribution)))
    def _is_valid_load_distribution(self, value):
        if value in self._valid_load_distribution:
            return True
        else:
            return False

    @ValidationFunction('The backend pool name does not exist in backendPools')
    def _is_valid_backend_pool_name(self, value):
        if value in [b.name for b in self.load_balancer.backend_pools]: # pylint: disable=E1101
            return True
        else:
            return False

    @ValidationFunction('The frontend ip configuration name does not exist in FrontendIPConfigurations')
    def _is_valid_frontend_ip_configuration(self, value):
        if value in [f.name for f in self.load_balancer.frontend_ip_configurations]: # pylint: disable=E1101
            return True
        else:
            return False

    @ValidationFunction('The probe name does not exist in probes')
    def _is_valid_probe_name(self, value):
        if value in [p.name for p in self.load_balancer.probes]: # pylint: disable=E1101
            return True
        else:
            return False

class LoadBalancerProbe(TopLevelResource, Resource):
    _attribute_map = {
        'protocol': {'key': 'protocol', 'type': 'str'},
        'request_path': {'key': 'requestPath', 'type': 'str'},
        'port': {'key': 'port', 'type': 'int'},
        'interval_in_seconds': {'key': 'intervalInSeconds', 'type': 'int'},
        'number_of_probes': {'key': 'numberOfProbes', 'type': 'int'}
    }

    _valid_protocols = frozenset([e.value for e in ProbeProtocol])

    def __init__(self, protocol=None, request_path=None, port=None, interval_in_seconds=None, number_of_probes=None, **kwargs):
        super(LoadBalancerProbe, self).__init__(**kwargs)
        self.protocol = protocol if protocol else None
        self.request_path = request_path if request_path else None
        self.port = port if port else None
        self.interval_in_seconds = interval_in_seconds if interval_in_seconds else 15
        self.number_of_probes = number_of_probes if number_of_probes else 2
        self._validation.update({
            'protocol': {'required': False, 'custom': self._is_valid_protocol},
            'interval_in_seconds': {'required': True, 'custom': self._is_valid_interval},
            'request_path': {'required': False, 'custom': self._is_valid_request_path},
            'number_of_probes': {'required': True, 'custom': self._is_valid_probes},
            'port': {'required': True, 'custom': LoadBalancer._is_valid_port}
        })

    def transform(self):
        factory = LoadBalancerBuildingBlock.get_sdk_model(ProbeSdk)

        model = factory(
            interval_in_seconds = self.interval_in_seconds,
            port = self.port,
            request_path = self.request_path,
            protocol = self.protocol,
            number_of_probes = self.number_of_probes
        )

        return model

    @classmethod
    @ValidationFunction('Valid values must be one of the following: {}'.format(','.join(_valid_protocols)))
    def _is_valid_protocol(self, value):
        if value in self._valid_protocols:
            return True
        else:
            return False

    @classmethod
    @ValidationFunction('Interval in seconds must be between 5 and 300')
    def _is_valid_interval(self, value): 
        if value >= 5 and value <= 300:
            return True
        else:
            return False

    # Is valid request path - must be specified if http - not if tcp
    @ValidationFunction()
    def _is_valid_request_path(self, value):
        if value == None and self.protocol == 'Http':  # pylint: disable=E1101
            return False, 'Request path must be specified if protocol is http'
        elif value != None and self.protocol != 'Http': # pylint: disable=E1101
            return False, 'Request path must not be specified if protocol is not http'
        else:
            return True

    @classmethod
    @ValidationFunction('Valid number of probes between 1 and 20')
    def _is_valid_probes(self, value):
        if value >= 1 and value <=20:
            return True
        else: 
            return False

class InboundNatRule(TopLevelResource, Resource):
    _attribute_map = {
        'starting_frontend_port': {'key': 'startingFrontendPort', 'type': 'int'},
        'backend_port': {'key': 'backendPort', 'type': 'int'},
        'frontend_ip_configuration_name': {'key': 'FrontendIPConfigurationName', 'type': 'str'},
        'enable_floating_ip': {'key': 'enableFloatingIP', 'type': 'bool'},
        'protocol': {'key': 'protocol', 'type': 'str'},
        'idle_timeout_in_minutes': {'key': 'idleTimeoutInMinutes', 'type': 'int'}
    }

    def __init__(self, starting_frontend_port=None, backend_port=None, frontend_ip_configuration_name=None, enable_floating_ip=None, protocol=None, idle_timeout_in_minutes=None, **kwargs):
        super(InboundNatRule, self).__init__(**kwargs)
        self.starting_frontend_port = starting_frontend_port if starting_frontend_port else None
        self.backend_port = backend_port if backend_port else None
        self.frontend_ip_configuration_name = frontend_ip_configuration_name if frontend_ip_configuration_name else None
        self.enable_floating_ip = enable_floating_ip if enable_floating_ip  else False
        self.protocol = protocol if protocol else None
        self.idle_timeout_in_minutes = idle_timeout_in_minutes if idle_timeout_in_minutes else None
        self._validation.update({
            'protocol': {'required': True, 'custom': LoadBalancer._is_valid_transport_protocol},
            'idle_timeout_in_minutes': {'required': True, 'custom': InboundNatRule._is_valid_idle_timeout_in_minutes},
            'frontend_ip_configuration_name': {'custom': self._is_valid_frontend_ip_configuration},
            'backend_port': {'required': False, 'custom': LoadBalancer._is_valid_port},
            'frontend_port': {'required': False, 'custom': LoadBalancer._is_valid_port}
        })

    def transform(self):
        factory = LoadBalancerBuildingBlock.get_sdk_model(InboundNatRuleSdk)

        model = factory(
            frontend_ip_configuration = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='loadBalancers',
                name=self.load_balancer.name, # pylint: disable=E1101
                child_type_1='FrontendIPConfigurations',
                child_name_1=self.frontend_ip_configuration_name)) if self.frontend_ip_configuration_name else None,
            protocol = self.protocol,
            enable_floating_ip = self.enable_floating_ip,
            frontend_port = self.starting_frontend_port,
            backend_port = self.backend_port,
            idle_timeout_in_minutes = self.idle_timeout_in_minutes
        )

        return model

    @ValidationFunction('Frontend ip configuration doesn\'t exist in frontend ip configurations')
    def _is_valid_frontend_ip_configuration(self, value):
        if value in [f.name for f in self.load_balancer.frontend_ip_configurations]: # pylint: disable=E1101
            return True
        else:
            return False

    @ValidationFunction('Idle timeout must be between 4 and 30 minutes')
    def _is_valid_idle_timeout_in_minutes(self, value):
        if value >= 4 and value <=30:
            return True
        else:
            return False

class InboundNatPool(TopLevelResource, Resource):
    _attribute_map = {
        'starting_frontend_port': {'key': 'startingFrontendPort', 'type': 'int'},
        'backend_port': {'key': 'backendPort', 'type': 'int'},
        'frontend_ip_configuration_name': {'key': 'FrontendIPConfigurationName', 'type': 'str'},
        'frontend_port_range_end': {'key': 'frontendPortRangeEnd', 'type': 'int'},
        'protocol': {'key': 'protocol', 'type': 'str'}
    }

    def __init__(self, starting_frontend_port=None, backend_port=None, frontend_ip_configuration_name=None, protocol=None, frontend_port_range_end=None, **kwargs):
        super(InboundNatPool, self).__init__(**kwargs)
        self.starting_frontend_port = starting_frontend_port if starting_frontend_port else None
        self.backend_port = backend_port if backend_port else None
        self.frontend_ip_configuration_name = frontend_ip_configuration_name if frontend_ip_configuration_name else None
        self.protocol = protocol if protocol else None
        self.frontend_port_range_end = frontend_port_range_end if frontend_port_range_end else None
        self._validation.update({
            'protocol': {'required': True, 'custom': LoadBalancer._is_valid_transport_protocol},
            'frontend_ip_configuration_name': {'custom': self.is_valid_frontend_ip_configuration},
            'starting_frontend_port': {'required': False, 'custom': LoadBalancer._is_valid_port},
            'backend_port': {'required': False, 'custom': LoadBalancer._is_valid_port},
            'frontend_port_range_end': {'required': False, 'custom': LoadBalancer._is_valid_port}
        })

    def transform(self):
        factory = LoadBalancerBuildingBlock.get_sdk_model(InboundNatPoolSdk)

        model = factory(
            frontend_port_range_start = self.starting_frontend_port,
            frontend_port_range_end = self.frontend_port_range_end,
            backend_port = self.backend_port,
            protocol = self.protocol,
            frontend_ip_configuration = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='loadBalancers',
                name=self.load_balancer.name, # pylint: disable=E1101
                child_type_1='FrontendIPConfigurations',
                child_name_1=self.frontend_ip_configuration_name)) if self.frontend_ip_configuration_name else None
        )

        return model

    @ValidationFunction('Frontend ip configuration doesn\'t exist in frontend ip configurations')
    def is_valid_frontend_ip_configuration(self, value):
        if value in [f.name for f in self.load_balancer.frontend_ip_configurations]: # pylint: disable=E1101
            return True
        else:
            return False

class InternalLoadBalancerSetting(BuildingBlockModel):
    _attribute_map = {
        'private_ip_address': {'key': 'privateIPAddress', 'type': 'str'},
        'subnet_name': {'key': 'subnetName', 'type': 'str'}
    }

    def __init__(self, private_ip_address=None, subnet_name=None, **kwargs):
        super(InternalLoadBalancerSetting, self).__init__(**kwargs)
        self.private_ip_address = private_ip_address if private_ip_address else None
        self.subnet_name = subnet_name if subnet_name else None
        self._validation.update({
        })

    


