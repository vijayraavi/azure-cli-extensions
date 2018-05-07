# TODO: Validations: -
# A pool can contain only one of these three: IPs in BackendAddresses array, IPConfigurations of standalone Network Interfaces
# Disabled rule group
# IP or FQDN
# More than 2 front end ip configurations - 1 public, 1 private
# Validate resource references
# Check defaults

from ..validations import ValidationFunction

from ..validations.networking import (is_valid_port_range)

from .public_ip_address import (PublicIPAddress)

from msrestazure.tools import resource_id

from .building_block_settings import (BuildingBlock,
                                      RegisterBuildingBlock)
from .resources import (Resource,
                        ResourceId,
                        TaggedResource,
                        TopLevelResource,
                        ResourceReference,
                        convert_string_to_enum,
                        extract_resource_groups,
                        BuildingBlockModel)

from azure.mgmt.network.models import (
    SubResource,
    ApplicationGateway as ApplicationGatewaySdk,
    ApplicationGatewaySkuName as ApplicationGatewaySkuName,
    ApplicationGatewaySku as ApplicationGatewaySkuSdk,
    ApplicationGatewayTier as ApplicationGatewayTier,
    ApplicationGatewaySslProtocol as ApplicationGatewaySslProtocolSdk,
    ApplicationGatewayProtocol as ApplicationGatewayProtocol,
    ApplicationGatewayCookieBasedAffinity as ApplicationGatewayCookieBasedAffinity,
    ApplicationGatewaySslProtocol as ApplicationGatewaySslProtocol,
    ApplicationGatewaySslPolicyType as ApplicationGatewaySslPolicyType,
    ApplicationGatewaySslPolicyName as ApplicationGatewaySslPolicyName,
    ApplicationGatewaySslCipherSuite as ApplicationGatewaySslCipherSuite,
    ApplicationGatewayRequestRoutingRuleType as ApplicationGatewayRequestRoutingRuleType,
    ApplicationGatewayRedirectType as ApplicationGatewayRedirectType,
    ApplicationGatewayFirewallMode as ApplicationGatewayFirewallModeSdk,
    ApplicationGatewayIPConfiguration as ApplicationGatewayIPConfigurationSdk,
    ApplicationGatewayFrontendIPConfiguration as ApplicationGatewayFrontendIPConfigurationSdk,
    ApplicationGatewayBackendAddressPool as ApplicationGatewayBackendAddressPoolSdk,
    ApplicationGatewayBackendAddress as ApplicationGatewayBackendAddressSdk,
    ApplicationGatewayBackendHttpSettings as ApplicationGatewayBackendHttpSettingsSdk,
    ApplicationGatewayHttpListener as ApplicationGatewayHttpListenerSdk,
    ApplicationGatewayRedirectConfiguration as ApplicationGatewayRedirectConfigurationSdk,
    ApplicationGatewayPathRule as ApplicationGatewayPathRuleSdk,
    ApplicationGatewayRequestRoutingRule as ApplicationGatewayRequestRoutingRuleSdk,
    ApplicationGatewayWebApplicationFirewallConfiguration as ApplicationGatewayWebApplicationFirewallConfigurationSdk,
    ApplicationGatewayFirewallDisabledRuleGroup as ApplicationGatewayFirewallDisabledRuleGroupSdk,
    ApplicationGatewayProbe as ApplicationGatewayProbeSdk,
    ApplicationGatewayProbeHealthResponseMatch as ApplicationGatewayProbeHealthResponseMatchSdk,
    ApplicationGatewayAuthenticationCertificate as ApplicationGatewayAuthenticationCertificateSdk,
    ApplicationGatewayFrontendPort as ApplicationGatewayFrontendPortSdk,
    ApplicationGatewaySslPolicy as ApplicationGatewaySslPolicySdk,
    ApplicationGatewayUrlPathMap as ApplicationGatewayUrlPathMapSdk,
    ApplicationGatewaySslCertificate as ApplicationGatewaySslCertificateSdk,
    ApplicationGatewayConnectionDraining as ApplicationGatewayConnectionDrainingSdk
)

@RegisterBuildingBlock(name='ApplicationGateway', template_url='buildingBlocks/applicationGateways/applicationGateways.json', deployment_name='agws')
class ApplicationGatewayBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[ApplicationGateway]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(ApplicationGatewayBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(ApplicationGatewaySdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })

    def transform(self):
        public_ip_addresses = self.get_ip_addresses(self.settings)
        application_gateways = [application_gateway.transform() for application_gateway in self.settings]

        resource_groups = extract_resource_groups(application_gateways)
        template_parameters = {
            "applicationGateways": application_gateways,
            "publicIpAddresses": public_ip_addresses
        }

        return resource_groups, template_parameters

    def proxy_extract_resource_groups(self, application_gateways):
        return extract_resource_groups(application_gateways)

    def get_ip_addresses(self,application_gateways):
        public_ip_addresses = []

        for application_gateway in application_gateways:
            ip_addresses = [application_gateway.frontend_ip_configurations for application_gateway in self.settings if application_gateway.frontend_ip_configurations]
            ip_addresses_public = [ip_address for ip_address in ip_addresses[0] if ip_address.application_gateway_type == 'Public']

            for ip_address in ip_addresses_public:
                public_ip_address_parameters = {
                    'subscription_id': self.subscription_id,
                    'resource_group_name': self.resource_group_name,
                    'location': self.location,
                    'name': '{}-{}-pip'.format(application_gateway.name, ip_address.name),
                    'public_ip_allocation_method': 'Dynamic',
                    'public_ip_address_version': 'IPv4',
                    'idle_timeout_in_minutes': None,
                    'zones': None,
                    'domain_name_label': None
                }

                public_ip_address = PublicIPAddress(**public_ip_address_parameters)
                public_ip_addresses.append(public_ip_address.transform())
        
        return public_ip_addresses

@ResourceId(namespace='Microsoft.Network', type='ApplicationGateways')
class ApplicationGateway(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'Sku'},
        'virtual_network': {'key': 'virtualNetwork', 'type': 'ResourceReference'},
        'gateway_ip_configurations': {'key': 'gatewayIPConfigurations', 'type': '[GatewayIPConfiguration]', 'parent': 'application_gateway'},
        'ssl_certificates': {'key': 'sslCertificates', 'type': '[SslCertificate]'},
        'authentication_certificates': {'key': 'authenticationCertificates', 'type': '[AuthenticationCertificate]'},
        'frontend_ip_configurations': {'key': 'frontendIPConfigurations', 'type': '[FrontendIPConfiguration]', 'parent': 'application_gateway'},
        'frontend_ports': {'key': 'frontendPorts', 'type': '[FrontendPort]'},
        'backend_address_pools': {'key': 'backendAddressPools', 'type': '[BackendAddressPool]'},
        'backend_http_settings_collection': {'key': 'backendHttpSettingsCollection', 'type': '[BackendHttpSettings]', 'parent': 'application_gateway'},
        'http_listeners': {'key': 'httpListeners', 'type': '[HttpListener]', 'parent': 'application_gateway'},
        'url_path_maps': {'key': 'urlPathMaps', 'type': '[UrlPathMap]', 'parent': 'application_gateway'},
        'request_routing_rules': {'key': 'requestRoutingRules', 'type': '[RequestRoutingRule]', 'parent': 'application_gateway'},
        'probes': {'key': 'probes', 'type': '[Probe]'},
        'redirect_configurations': {'key': 'redirectConfigurations', 'type': '[RedirectConfiguration]'},
        'web_application_firewall_configuration': {'key': 'webApplicationFirewallConfiguration', 'type': 'WebApplicationFirewallConfiguration'},
        'ssl_policy': {'key': 'sslPolicy', 'type': 'SslPolicy'}
    }

    def __init__(self, sku=None, virtual_network=None, gateway_ip_configurations=None, frontend_ip_configurations=None, backend_address_pools=None, backend_http_settings_collection=None, http_listeners=None, redirect_configurations=None, url_path_maps=None, request_routing_rules=None, web_application_firewall_configuration=None, probes=None, ssl_certificates=None, authentication_certificates=None, frontend_ports=None, ssl_policy=None, **kwargs):
         super(ApplicationGateway, self).__init__(**kwargs)
         self.sku = sku.transform() if sku else None
         self.virtual_network = virtual_network if virtual_network else None
         self.gateway_ip_configurations = gateway_ip_configurations if gateway_ip_configurations is not None else []
         self.frontend_ip_configurations = frontend_ip_configurations if frontend_ip_configurations is not None else []
         self.backend_address_pools = backend_address_pools if backend_address_pools is not None else []
         self.backend_http_settings_collection = backend_http_settings_collection if backend_http_settings_collection is not None else []
         self.http_listeners = http_listeners if http_listeners is not None else []
         self.redirect_configurations = redirect_configurations if redirect_configurations is not None else []
         self.url_path_maps = url_path_maps if url_path_maps is not None else []
         self.request_routing_rules = request_routing_rules if request_routing_rules is not None else []
         self.web_application_firewall_configuration = web_application_firewall_configuration.transform() if web_application_firewall_configuration is not None else []
         self.probes = probes if probes is not None else []
         self.ssl_certificates = ssl_certificates if ssl_certificates is not None else []
         self.authentication_certificates = authentication_certificates if authentication_certificates is not None else []
         self.frontend_ports = frontend_ports if frontend_ports is not None else []
         self.ssl_policy = ssl_policy.transform() if ssl_policy is not None else []
         self._validation.update({
             'sku': {'required': True},
             'gateway_ip_configurations': {'required': True, 'min_items': 1},
             'frontend_ip_configurations': {'required': True, 'min_items': 1, 'max_items': 2, 'custom': self._is_valid_frontend_ip_configurations},
             'backend_address_pools': {'required': True, 'min_items': 1},
             'backend_http_settings_collection': {'required': True, 'min_items': 1},
             'http_listeners': {'required': True, 'min_items': 1},
             'url_path_maps': {'required': True, 'min_items': 1, 'custom': self._is_valid_url_path_map_setting},
             'requesting_routing_rules': {'custom': self._is_valid_request_routing_rule},
             'web_application_firewall_configuration': {'required': True},
             'probes': {'required': True, 'min_items': 1},
             'frontend_ports': {'required': True, 'min_items': 1}
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewaySdk)
        model = factory(
            name = self.name,
            subscription_id = self.subscription_id,
            resource_group_name = self.resource_group_name,
            location = self.location,
            sku = self.sku,
            ssl_policy = self.ssl_policy,
            gateway_ip_configurations = [g.transform() for g in self.gateway_ip_configurations],
            authentication_certificates = [a.transform() for a in self.authentication_certificates],
            ssl_certificates = [s.transform() for s in self.ssl_certificates],
            frontend_ip_configurations = [f.transform() for f in self.frontend_ip_configurations],
            frontend_ports = [f.transform() for f in self.frontend_ports],
            probes = [p.transform() for p in self.probes],
            backend_address_pools = [b.transform() for b in self.backend_address_pools],
            backend_http_settings_collection = [b.transform() for b in self.backend_http_settings_collection],
            http_listeners = [l.transform() for l in self.http_listeners],
            url_path_maps = [u.transform() for u in self.url_path_maps],
            request_routing_rules = [r.transform() for r in self.request_routing_rules],
            redirect_configurations = [r.transform() for r in self.redirect_configurations],
            web_application_firewall_configuration = self.web_application_firewall_configuration
        )
        return model

    @ValidationFunction('There can be only 2 frontendIPConfigurations, 1 private and 1 public')
    def _is_valid_frontend_ip_configurations(self, value):
        if len(self.frontend_ip_configurations) < 2:
            return True
        elif self.frontend_ip_configurations[0].application_gateway_type != self.frontend_ip_configurations[1].application_gateway_type:
            return True
        else:
            return False

    @ValidationFunction()
    def _is_valid_url_path_map_setting(self, value):
        if value[0].default_backend_address_pool_name != None and value[0].default_redirect_configuration_name != None:
            return False, 'Value cannot be specified if defaultRedirectConfigurationName is defined'
        elif value[0].default_backend_http_settings_name != None and value[0].default_redirect_configuration_name != None:
            return False, 'Value cannot be specified if defaultRedirectConfigurationName is defined'
        else:
            return True

    @ValidationFunction()
    def _is_valid_request_routing_rule(self, value):
        return False
    

class Sku(Resource):
    _attribute_map = {
        'size': {'key': 'size', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
        'tier': {'key': 'tier', 'type': 'str'}
    }

    _valid_sizes = frozenset([e.value for e in ApplicationGatewaySkuName])
    _valid_tiers = frozenset([e.value for e in ApplicationGatewayTier])

    def __init__(self, size=None, capacity=None, tier=None, **kwargs):
         super(Sku, self).__init__(**kwargs)
         self.tier = tier if tier else 'Standard'
         self.size = size if size else 'Medium' if tier == 'WAF' else 'Small'
         self.capacity = capacity if capacity else None
         self._validation.update({
             'capacity': {'required': True, 'custom': self._is_valid_capacity},
             'tier': {'required': True, 'custom': self._is_valid_tier}
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewaySkuSdk)
        model = factory(
            name = '{}_{}'.format(self.tier, self.size),
            tier = self.tier,
            capacity = self.capacity
        )
        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_sizes)))
    def _is_valid_sku(self, value):
        value = '{}_{}'.format(self.application_gateway.sku.tier, value) # pylint: disable=E1101
        if value in self._valid_sizes:
            return True
        else:
            return False
   
    @ValidationFunction()
    def _is_valid_capacity(self, value):
        if value > 0 and value <= 10:
            return True
        else:
            return False

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_tiers)))
    def _is_valid_tier(self, value):
        if value in self._valid_tiers:
            return True
        else:
            return False

class GatewayIPConfiguration(Resource):
    _attribute_map = {
        'subnet_name': {'key': 'subnetName', 'type': 'str'}
    }

    def __init__(self, subnet_name=None, **kwargs):
         super(GatewayIPConfiguration, self).__init__(**kwargs)
         self.subnet_name = subnet_name if subnet_name else None

         self._validation.update({
             'subnet_name': {'required': True}
         })

    def transform(self):
        if self.subnet_name != None:
            self.subnet_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='virtualNetworks',
                name=self.application_gateway.virtual_network.name,  # pylint: disable=E1101
                child_type_1='subnets',
                child_name_1=self.subnet_name))

        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayIPConfigurationSdk)

        model = factory(
            name = self.name,
            subnet =  self.subnet_name
        )

        return model

class FrontendIPConfiguration(TopLevelResource, Resource):
    _attribute_map = {
        'application_gateway_type': {'key': 'applicationGatewayType', 'type': 'str'},
        'internal_application_gateway_settings': {'key': 'internalApplicationGatewaySettings', 'type': 'InternalApplicationGatewaySetting'},
        'public_ip_address': {'key': 'publicIPAddress', 'type': 'str'}
    }
    
    def __init__(self, application_gateway_type=None, internal_application_gateway_settings=None, public_ip_address=None, **kwargs):
        super(FrontendIPConfiguration, self).__init__(**kwargs)
        self.application_gateway_type = application_gateway_type if application_gateway_type else None
        self.internal_application_gateway_settings = internal_application_gateway_settings if internal_application_gateway_settings else None
        self.public_ip_address = self.public_ip_address if public_ip_address else None
        self._validation.update({
            'application_gateway_type': {'required': True, 'custom': self._is_valid_gateway_type},
            'internal_application_gateway_settings': {'custom': self._is_valid_internal_application_gateway_setting},
            'public_ip_address': {'custom': self._is_valid_public_ip_address}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayFrontendIPConfigurationSdk)

        model = factory(
            name = self.name,
            private_ip_allocation_method = 'Dynamic',
            public_ip_address = SubResource(id=resource_id(
                subscription=self.subscription_id,
                resource_group=self.resource_group_name,
                namespace='Microsoft.Network',
                type='publicIPAddresses',
                name='{}-{}-pip'.format(self.application_gateway.name, self.name))) if self.application_gateway_type == 'Public' else None, # pylint: disable=E1101
            subnet = SubResource(id=resource_id(
                subscription=self.subscription_id,
                resource_group=self.resource_group_name,
                namespace='Microsoft.Network',
                type='virtualNetworks',
                name=self.application_gateway.virtual_network.name,  # pylint: disable=E1101,
                child_type_1='subnets',
                child_name_1=self.internal_application_gateway_settings.subnet_name)) if self.internal_application_gateway_settings and self.internal_application_gateway_settings.subnet_name else None
        )

        return model

    @ValidationFunction('Value must be one of the following values: Public, Internal')
    def _is_valid_gateway_type(self, value):
        types = ['Public', 'Internal']

        if value in types:
            return True
        else:
            return False

    @ValidationFunction()
    def _is_valid_internal_application_gateway_setting(self, value):
        if self.internal_application_gateway_settings != None and self.application_gateway_type == 'Public': # pylint: disable=E1101
            return False, 'Internal application gateway settings must not be specified for Public gateways'
        else: 
            return True

    @ValidationFunction()
    def _is_valid_public_ip_address(self, value):
        if value.public_ip_address == None and value.application_gateway_type == 'Public': 
            return False, 'publicIpAddress must be specified'
        elif value.application_gateway_type == 'Internal' and value.public_ip_address != None:
            return False, 'publicIPAddress should not be specified for Internal gateway types'
        else:
            return True

class InternalApplicationGatewaySetting(BuildingBlockModel):
    _attribute_map = {
        'subnet_name': {'key': 'subnetName', 'type': 'str'}
    }

    def __init__(self, subnet_name=None, **kwargs):
         super(InternalApplicationGatewaySetting, self).__init__(**kwargs)
         self.subnet_name = subnet_name if subnet_name else None
         self._validation.update({
             'subnet_name': {'required': True}
         })        

class BackendAddressPool(Resource):

    _attribute_map = {
        'backend_addresses': {'key': 'backendAddresses', 'type': '[BackendAddress]'}
    }

    def __init__(self, backend_addresses=None, **kwargs):
         super(BackendAddressPool, self).__init__(**kwargs)
         self.backend_addresses = backend_addresses if backend_addresses is not None else []
         self._validation.update({
             'backend_addresses': {'required': True, 'min_items': 1}
         })

    def transform(self):
        if self.backend_addresses != None:
            self.backend_addresses = [ba.transform() for ba in self.backend_addresses]

        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayBackendAddressPoolSdk)

        model = factory(
            name = self.name,
            backend_addresses = self.backend_addresses
        )

        return model

class BackendAddress(Resource):
    _attribute_map = {
        'fqdn': {'key': 'fqdn', 'type': 'str'}
    }

    def __init__(self, fqdn=None, ip_address=None, **kwargs):
         super(BackendAddress, self).__init__(**kwargs)
         self.fqdn = fqdn if fqdn else None
         self._validation.update({
             'fqdn':{'required': True}
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayBackendAddressSdk)

        model = factory(
            fqdn = self.fqdn
        )

        return model

class BackendHttpSettings(Resource):
    _attribute_map = {
        'port': {'key': 'port', 'type': 'int'},
        'protocol': {'key': 'protocol', 'type': 'str'},
        'cookie_based_affinity': {'key': 'cookieBasedAffinity', 'type': 'str'},
        'affinity_cookie_name': {'key': 'affinityCookieName', 'type': 'str'},
        'connection_draining': {'key': 'connection_draining', 'type': 'ConnectionDraining'},
        'pick_host_name_from_backend_address': {'key': 'pickHostNameFromBackendAddress', 'type': 'bool'},
        'host_name': {'key': 'hostName', 'type': 'str'},
        'request_timeout': {'key': 'requestTimeout', 'type': 'int'},
        'path': {'key': 'path', 'type': 'str'},
        'host_header_name': {'key': 'hostHeaderName', 'type': 'str'},
        'probe_enabled': {'key': 'probeEnabled', 'type': 'bool'},
        'probe_name': {'key': 'probeName', 'type': 'str'}
    }

    _valid_affinity = frozenset([e.value for e in ApplicationGatewayCookieBasedAffinity])
    _valid_protocol_types = frozenset([e.value for e in ApplicationGatewayProtocol])

    def __init__(self, port=None, protocol=None, cookie_based_affinity=None, affinity_cookie_name=None, connection_draining=None, pick_host_name_from_backend_address=None, host_name=None, request_timeout=None, path=None, host_header_name=None, probe_enabled=None, probe_name=None, **kwargs):
         super(BackendHttpSettings, self).__init__(**kwargs)
         self.port = port if port else None
         self.protocol = protocol if protocol else None
         self.cookie_based_affinity = cookie_based_affinity if cookie_based_affinity else 'Default'
         self.affinity_cookie_name = affinity_cookie_name if affinity_cookie_name else None
         self.connection_draining = connection_draining.transform() if connection_draining else None
         self.pick_host_name_from_backend_address = pick_host_name_from_backend_address if pick_host_name_from_backend_address else False
         self.host_name = host_name if host_name else None
         self.request_timeout = request_timeout if request_timeout else 30
         self.path = path if path else None
         self.host_header_name = host_header_name if host_header_name else None
         self.probe_enabled = probe_enabled if probe_enabled else True
         self.probe_name = probe_name if probe_name else None
         self._validation.update({
            'port': {'custom': is_valid_port_range},
            'protocol': {'custom': BackendHttpSettings._is_valid_protocol},
            'cookie_based_affinity': {'required': True, 'custom': BackendHttpSettings._is_valid_cookie_based_affinity},
            'pick_host_name_from_backend_address': {'required': True},
            'request_timeout': {'required': True},
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayBackendHttpSettingsSdk)
        if self.probe_name != None:
            self.probe_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='probes',
                child_name_1=self.probe_name))

        model = factory(
            name = self.name,
            port = self.port,
            protocol = self.protocol,
            cookie_based_affinity = self.cookie_based_affinity if self.cookie_based_affinity else 'Disabled',
            request_timeout = self.request_timeout if self.request_timeout else 30,
            connection_draining = self.connection_draining,
            pick_host_name_from_backend_address = self.pick_host_name_from_backend_address if self.pick_host_name_from_backend_address else False,
            host_name = self.host_name,
            probe = self.probe_name,
            probe_enabled = True
        )

        return model
    
    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_affinity)))
    def _is_valid_cookie_based_affinity(self, value):
        
        if value in self._valid_affinity:
            return True
        else:
            return False

    @classmethod            
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_protocol_types)))
    def _is_valid_protocol(self, value):

        if value in self._valid_protocol_types:
            return True
        else:
            return False

class ConnectionDraining(Resource):
    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'drain_timeout_in_sec': {'key': 'drainTimeoutInSec', 'type': 'int'}
    }

    def __init__(self, enabled=None, drain_timeout_in_sec=None, **kwargs):
         super(ConnectionDraining, self).__init__(**kwargs)
         self.drain_timeout_in_sec = drain_timeout_in_sec if drain_timeout_in_sec else 1
         self.enabled = enabled if enabled else False

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayConnectionDrainingSdk)

        model = factory(
            drain_timeout_in_sec = self.drain_timeout_in_sec,
            enabled = self.enabled
        )

        return model
        
class HttpListener(Resource):
    _attribute_map = {
        'frontend_ip_configuration_name': {'key': 'frontendIPConfigurationName', 'type': 'str'},
        'frontend_port_name': {'key': 'frontendPortName', 'type': 'str'},
        'protocol': {'key': 'protocol', 'type': 'str'},
        'ssl_certificate_name': {'key': 'sslCertificateName', 'type': 'str'},
        'require_server_name_indication': {'key': 'requireServerNameIndication', 'type': 'bool'}
    }

    _valid_protocol_types = frozenset([e.value for e in ApplicationGatewayProtocol])

    def __init__(self, frontend_ip_configuration_name=None, frontend_port_name=None, protocol=None, ssl_certificate_name=None, require_server_name_indication=None, **kwargs):
        super(HttpListener, self).__init__(**kwargs)
        self.frontend_ip_configuration_name = frontend_ip_configuration_name if frontend_ip_configuration_name else None
        self.frontend_port_name = frontend_port_name if frontend_port_name else None
        self.protocol = protocol if protocol else None
        self.ssl_certificate_name = ssl_certificate_name if ssl_certificate_name else None
        self.require_server_name_indication = require_server_name_indication if require_server_name_indication else False
        self._validation.update({
            'protocol': {'custom': HttpListener._is_valid_protocol},
            'require_server_name_indication': {'required': True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayHttpListenerSdk)

        model = factory(
            name = self.name,
            frontend_ip_configuration = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='frontendIPConfigurations',
                child_name_1=self.frontend_ip_configuration_name)),
            frontend_port = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='frontendPorts',
                child_name_1=self.frontend_port_name)),
            protocol = self.protocol,
            ssl_certificate = self.ssl_certificate_name,
            require_server_name_indication = self.require_server_name_indication
        )

        return model

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_protocol_types)))
    def _is_valid_protocol(self, value):
        
        if value in self._valid_protocol_types:
            return True
        else:
            return False

class RedirectConfiguration(Resource):
    _attribute_map = {
        'redirect_type': {'key': 'redirectType', 'type': 'str'},
        'include_query_string': {'key': 'includeQueryString', 'type': 'bool'},
        'target_listener_name': {'key': 'targetListenerName', 'type': 'str'},
        'include_path': {'key': 'includePath', 'type': 'bool'},
        'target_url': {'key': 'targetUrl', 'type': 'str'}    
    }

    _redirect_types = frozenset([e.value for e in ApplicationGatewayRedirectType])

    def __init__(self, redirect_type=None, include_query_string=None, target_listener_name=None, include_path=None, target_url=None, **kwargs):
        super(RedirectConfiguration, self).__init__(**kwargs)
        self.redirect_type = redirect_type if redirect_type else None
        self.include_query_string = include_query_string if include_query_string else None
        self.target_listener_name = target_listener_name if target_listener_name else None
        self.include_path = include_path if include_path else None
        self.target_url = target_url if target_url else None
        self._validation.update({
            'redirect_type': {'required': True, 'custom': self._is_valid_redirect_type},
            'include_query_string': {'required': True},
            'target_listener_name': {'custom': self._is_valid_target_listener_name},
            'target_url': {'custom': self._is_valid_target_url}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayRedirectConfigurationSdk)

        model = factory(
            name = self.name,
            redirect_type = self.redirect_type,
            include_query_string = self.include_query_string,
            target_listener = self.target_listener_name,
            target_url = self.target_url
        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_redirect_types)))
    def _is_valid_redirect_type(self, value):
        
        if value in self._redirect_types:
            return True
        else:
            return False

    @ValidationFunction('Either targetUrl or targetListenerName must be specified, but not both')
    def _is_valid_target_url(self, value):
        if self.target_listener_name != None and value != None:
            return False
        
        else:
            return True

    @ValidationFunction('Either targetListenerName or targetUrl must be specified, but not both')
    def _is_valid_target_listener_name(self, value):
        if self.target_url != None and value != None:
            return False
        else:
            return True

    @ValidationFunction('Value cannot be specified if targetUrl is specified')
    def _is_valid_include_path(self, value):
        if self.target_url != None and value != None:
            return False
        else:
            return True

class UrlPathMap(Resource): 
    _attribute_map = {
        'default_backend_address_pool_name': {'key': 'defaultBackendAddressPoolName', 'type': 'str'},
        'default_backend_http_settings_name': {'key': 'defaultBackendHttpSettingsName', 'type': 'str'},
        'default_redirect_configuration_name': {'key': 'defaultRedirectConfigurationName', 'type': 'str'},
        'path_rules': {'key': 'pathRules', 'type': '[PathRule]', 'parent': 'url_path_map'}
    }

    def __init__(self, default_backend_address_pool_name=None, default_backend_http_settings_name=None, default_redirect_configuration_name=None, path_rules=None, **kwargs):
        super(UrlPathMap, self).__init__(**kwargs)
        self.default_backend_address_pool_name = default_backend_address_pool_name if default_backend_address_pool_name else None
        self.default_backend_http_settings_name = default_backend_http_settings_name if default_backend_http_settings_name else None
        self.default_redirect_configuration_name = default_redirect_configuration_name if default_redirect_configuration_name else None
        self.path_rules = path_rules if path_rules is not None else []
        self._validation.update({
            'path_rules':  {'required': True, 'min_items': 1, 'custom': self._is_valid_path_rule}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayUrlPathMapSdk)

        if self.default_redirect_configuration_name != None:
            self.default_redirect_configuration_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='redirectConfigurations',
                child_name_1=self.default_redirect_configuration_name))

        model = factory(
            name = self.name,
            default_backend_address_pool = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='backendAddressPools',
                child_name_1=self.default_backend_address_pool_name)),
            default_backend_http_settings = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='backendHttpSettingsCollection',
                child_name_1=self.default_backend_http_settings_name)),
            default_redirect_configuration = self.default_redirect_configuration_name,
            path_rules = [p.transform() for p in self.path_rules] # pylint: disable=E1101
        )
        
        return model

    @ValidationFunction()
    def _is_valid_path_rule(self, value):
        if value[0].backend_address_pool_name != None and value[0].redirect_configuration_name != None:
            return False, 'Value cannot be specified if redirectConfigurationName is defined'
        elif value[0].backend_http_settings_name != None and value[0].redirect_configuration_name != None:
            return False, 'Value cannot be specified if redirectConfigurationName is defined'
        else:
            return True

class PathRule(Resource):
    _attribute_map = {
        'paths': {'key': 'paths', 'type': '[str]'},
        'backend_address_pool_name': {'key': 'backendAddressPoolName', 'type': 'str'},
        'backend_http_settings_name': {'key': 'backendHttpSettingsName', 'type': 'str'},
        'redirect_configuration_name': {'key': 'redirectConfigurationName', 'type': 'str'}
    }

    def __init__(self, paths=None, backend_address_pool_name=None, backend_http_settings_name=None, redirect_configuration_name=None, **kwargs):
        super(PathRule, self).__init__(**kwargs)
        self.paths = paths if paths else None
        self.backend_address_pool_name = backend_address_pool_name if backend_address_pool_name else None
        self.backend_http_settings_name = backend_http_settings_name if backend_http_settings_name else None
        self.redirect_configuration_name = redirect_configuration_name if redirect_configuration_name else None
        self._validation.update({
            'paths': {'required': True, 'min_items': 1},
            'backend_address_pool_name': {'required': True},
            'backend_http_settings_name': {'required': True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayPathRuleSdk)

        if self.backend_address_pool_name != None:
            self.backend_address_pool_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.url_path_map.application_gateway.name, # pylint: disable=E1101
                child_type_1='backendAddressPools',
                child_name_1=self.backend_address_pool_name))

        if self.backend_http_settings_name != None:
            self.backend_http_settings_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.url_path_map.application_gateway.name, # pylint: disable=E1101
                child_type_1='backendHttpSettingsCollection',
                child_name_1=self.backend_http_settings_name))

        if self.redirect_configuration_name != None:
            self.redirect_configuration_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.url_path_map.application_gateway.name, # pylint: disable=E1101
                child_type_1='redirectConfigurations',
                child_name_1=self.redirect_configuration_name))

        model = factory (
            paths = self.paths,
            backend_address_pool = self.backend_address_pool_name,
            backend_http_settings = self.backend_http_settings_name,
            redirect_configuration = self.redirect_configuration_name,
            name=self.name
        )

        return model

class RequestRoutingRule(Resource):
    _attribute_map = {
        'http_listener_name': {'key': 'httpListenerName', 'type': 'str'},
        'rule_type': {'key': 'ruleType', 'type': 'str'},
        'backend_address_pool_name': {'key': 'backendAddressPoolName', 'type': 'str'},
        'backend_http_settings_name': {'key': 'backendHttpSettingsName', 'type': 'str'},
        'redirect_configuration_name': {'key': 'redirectConfigurationName', 'type': 'str'},
        'url_path_map_name': {'key': 'urlPathMapName', 'type': 'str'}
    }

    _valid_routing_rule_types = frozenset([e.value for e in ApplicationGatewayRequestRoutingRuleType])

    def __init__(self, http_listener_name=None, rule_type=None, backend_address_pool_name=None, backend_http_settings_name=None, redirect_configuration_name=None, url_path_map_name=None, **kwargs):
        super(RequestRoutingRule, self).__init__(**kwargs)
        self.http_listener_name = http_listener_name if http_listener_name else None
        self.rule_type = rule_type if rule_type else None
        self.backend_address_pool_name = backend_address_pool_name if backend_address_pool_name else None
        self.backend_http_settings_name = backend_http_settings_name if backend_http_settings_name else None
        self.redirect_configuration_name = redirect_configuration_name if redirect_configuration_name else None
        self.url_path_map_name = url_path_map_name if url_path_map_name else None
        self._validation.update({
            'http_listener_name': {'required': True},
            'rule_type': {'required': True, 'custom': RequestRoutingRule._is_valid_routing_rule_type}
        })

    def transform(self):
        if self.http_listener_name != None:
            self.http_listener_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='httpListeners',
                child_name_1=self.http_listener_name))
        if self.backend_address_pool_name != None:
            self.backend_address_pool_name =  SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='backendAddressPools',
                child_name_1=self.backend_address_pool_name))
        if self.backend_http_settings_name != None:
            self.backend_http_settings_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='backendHttpSettingsCollection',
                child_name_1=self.backend_http_settings_name))
        if self.url_path_map_name != None:
            self.url_path_map_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='urlPathMaps',
                child_name_1=self.url_path_map_name))
        if self.redirect_configuration_name != None:
            self.redirect_configuration_name = SubResource(id=resource_id(
                subscription=self.additional_properties['subscriptionId'], # pylint: disable=E1101
                resource_group=self.additional_properties['resourceGroupName'], # pylint: disable=E1101
                namespace='Microsoft.Network',
                type='applicationGateways',
                name=self.application_gateway.name, # pylint: disable=E1101
                child_type_1='urlPathMaps',
                child_name_1=self.redirect_configuration_name))
            
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayRequestRoutingRuleSdk)

        model = factory(
            name = self.name,
            rule_type = self.rule_type,
            backend_address_pool = self.backend_address_pool_name,
            backend_http_settings = self.backend_http_settings_name,
            url_path_map = self.url_path_map_name,
            redirect_configuration = self.redirect_configuration_name,
            http_listener= self.http_listener_name
        )

        return model

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_routing_rule_types)))
    def _is_valid_routing_rule_type(self, value):

        if value in self._valid_routing_rule_types:
            return True
        else:
            return False

class WebApplicationFirewallConfiguration(Resource):
    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'firewall_mode': {'key': 'firewallMode', 'type': 'str'},
        'rule_set_type': {'key': 'ruleSetType', 'type': 'str'},
        'rule_set_version': {'key': 'ruleSetVersion', 'type': 'str'},
        'disabled_rule_groups': {'key': 'disabledRuleGroups', 'type': '[DisabledRuleGroup]'}
    }

    _valid_firewall_mode = frozenset([e.value for e in ApplicationGatewayFirewallModeSdk])

    def __init__(self, enabled=None, firewall_mode=None, rule_set_type=None, rule_set_version=None, disabled_rule_groups=None, **kwargs):
        super(WebApplicationFirewallConfiguration, self).__init__(**kwargs)
        self.enabled = enabled if enabled else None
        self.firewall_mode = firewall_mode if firewall_mode else None
        self.rule_set_type = rule_set_type if rule_set_type else 'OWASP'
        self.rule_set_version = rule_set_version if rule_set_version else None
        self.disabled_rule_groups = disabled_rule_groups if disabled_rule_groups is not None else []
        self._validation.update({
            'enabled': {'required': True},
            'firewall_mode': {'required': True, 'custom': WebApplicationFirewallConfiguration._is_valid_firewall_mode},
            'rule_set_type': {'required': True, 'custom': WebApplicationFirewallConfiguration._is_valid_rule_type},
            'rule_set_version': {'required': True},
            'disabled_rule_groups': {'required': True, 'min_items': 1}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayWebApplicationFirewallConfigurationSdk)

        model = factory(
            enabled = self.enabled if self.enabled else True,
            firewall_mode = self.firewall_mode if self.firewall_mode else 'Prevention',
            rule_set_type = self.rule_set_type if self.rule_set_type else 'OWASP',
            rule_set_version = self.rule_set_version if self.rule_set_version else '3.0',
            disabled_rule_groups = [d.transform() for d in self.disabled_rule_groups]
        )

        return model

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_firewall_mode)))
    def _is_valid_firewall_mode(self, value):

        if value in self._valid_firewall_mode:
            return True
        else:
            return False

    @classmethod
    @ValidationFunction('Value must be set to OWASP')
    def _is_valid_rule_type(self, value):

        if value == 'OWASP':
            return True
        else:
            return False

class DisabledRuleGroup(Resource):
    _attribute_map = {
        'rule_group_name': {'key': 'ruleGroupName', 'type': 'str'},
        'rules': {'key': 'rules', 'type': '[str]'}
    }

    def __init__(self, rule_group_name=None, rules=None, **kwargs):
        super(DisabledRuleGroup, self).__init__(**kwargs)
        self.rule_group_name = rule_group_name if rule_group_name else None
        self.rules = rules if rules is not None else []
        self._validation.update({
            'rule_group_name': {'required': True},
            'rules': {'required': True, 'min_items': 1}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayFirewallDisabledRuleGroupSdk)

        model = factory(
            rule_group_name = self.rule_group_name,
            rules = self.rules
        )

        return model
        
class Probe(Resource):
    _attribute_map = {
        'protocol': {'key': 'protocol', 'type': 'str'},
        'host': {'key': 'host', 'type': 'str'},
        'path': {'key': 'path', 'type': 'str'},
        'interval': {'key': 'interval', 'type': 'int'},
        'timeout': {'key': 'timeout', 'type': 'int'},
        'unhealthy_threshold': {'key': 'unhealthyThreshold', 'type': 'int'},
        'pick_host_name_from_backend_http_settings': {'key': 'pickHostNameFromBackendHttpSettings', 'type': 'bool'},
        'min_servers': {'key': 'minServers', 'type': 'int'},
        'match': {'key': 'match', 'type': 'Match'}
    }

    _valid_protocol_types = frozenset([e.value for e in ApplicationGatewayProtocol])

    def __init__(self, protocol=None, host=None, path=None, interval=None, timeout=None, unhealthy_threshold=None, pick_host_name_from_backend_http_settings=None, min_servers=None, match=None, **kwargs):
        super(Probe, self).__init__(**kwargs)
        self.protocol = protocol if protocol else None
        self.host = host if host else None
        self.path = path if path else None
        self.interval = interval if interval else 30
        self.timeout = timeout if timeout else 30
        self.unhealthy_threshold = unhealthy_threshold if unhealthy_threshold else 3
        self.pick_host_name_from_backend_http_settings = pick_host_name_from_backend_http_settings if pick_host_name_from_backend_http_settings else False
        self.min_servers = min_servers if min_servers else 1
        self.match = match if match else None
        self._validation.update({
            'protocol': {'required': True, 'custom': self._is_valid_protocol},
            'host': {'required': True},
            'path': {'required': True},
            'interval': {'required': False, 'custom': self._is_valid_interval},
            'timeout': {'required': False, 'custom': self._is_valid_timeout},
            'unhealthy_threshold': {'required': False, 'custom': self._is_valid_unhealthy_threshold},
            'min_servers': {'custom': self._is_valid_min_servers}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayProbeSdk)

        model = factory(
            name = self.name,
            protocol = self.protocol,
            host = self.host,
            path = self.path,
            interval = self.interval,
            timeout = self.timeout,
            unhealthy_threshold = self.unhealthy_threshold,
            pick_host_name_from_backend_http_settings = self.pick_host_name_from_backend_http_settings,
            min_servers = self.min_servers
        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_protocol_types)))
    def _is_valid_protocol(self, value):

        if value in self._valid_protocol_types:
            return True
        else:
            return False

    @ValidationFunction('Value must be between 1 and 86400')
    def _is_valid_timeout(self, value):

        if value >= 1 and value <= 86400:
            return True
        else: 
            return False

    @ValidationFunction('Value must be between 1 and 86400')
    def _is_valid_interval(self, value):

        if value >= 1 and value <= 86400:
            return True
        else: 
            return False

    @ValidationFunction('Value must be between 1 and 20')
    def _is_valid_unhealthy_threshold(self, value):

        if value >= 1 and value <= 20:
            return True
        else:
            return False

    @ValidationFunction('minServers must be an integer equal or greater than 0')
    def _is_valid_min_servers(self, value):

        if value < 0:
            return False
        else:
            return True

class Match(Resource):
    _attribute_map = {
        'body': {'key': 'body', 'type': 'str'},
        'status_codes': {'key': 'statusCodes', 'type': '[str]'}
    }

    def __init__(self, body=None, status_codes=None, **kwargs):
        super(Match, self).__init__(**kwargs)
        self.body = body if body else None
        self.status_codes = status_codes if status_codes else None
        self._validation.update({
            'status_codes': {'required': True, 'custom': self._is_valid_status_code}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayProbeHealthResponseMatchSdk)

        model = factory(
            body = self.body,
            status_codes = self.status_codes
        )

        return model

    @ValidationFunction()
    def _is_valid_status_code(self, value):
        return True

class SslCertificate(Resource):
    _attribute_map = {
        'data': {'key': 'data', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'}
    }

    def __init__(self, data=None, password=None, **kwargs):
        super(SslCertificate, self).__init__(**kwargs)
        self.data = data if data else None
        self.password = password if password else None
        self._validation.update({
            'data': {'required': True},
            'password': {'required': True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewaySslCertificateSdk)

        model = factory(
            name = self.name,
            data = self.data,
            password = self.password
        )

        return model

class AuthenticationCertificate(Resource):
    _attribute_map = {
        'data': {'key': 'data', 'type': 'str'}
    }

    def __init__(self, data=None, **kwargs):
        super(AuthenticationCertificate, self).__init__(**kwargs)
        self.data = data if data else None

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayAuthenticationCertificateSdk)

        model = factory(
            name = self.name,
            data = self.data
        )

        return model

class FrontendPort(Resource):
    _attribute_map = {
        'port': {'key': 'port', 'type': 'int'}
    }

    def __init__(self, port=None, **kwargs):
        super(FrontendPort, self).__init__(**kwargs)
        self.port = port if port else None
        self._validation.update({
            'port': {'required': True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayFrontendPortSdk)

        model = factory(
            name = self.name,
            port = self.port
        )

        return model

class SslPolicy(Resource):
    _attribute_map = {
        'policy_type': {'key': 'policyType', 'type': 'str'},
        'policy_name': {'key': 'policyName', 'type': '[str]'},
        'disabled_ssl_protocols': {'key': 'disabledSslProtocols', 'type': '[str]'},
        'cipher_suites': {'key': 'cipherSuites', 'type': '[str]'},
        'min_protocol_version': {'key': 'minProtocolVersion', 'type': 'str'}
    }

    _valid_cipher_suites = frozenset([e.value for e in ApplicationGatewaySslCipherSuite])
    _valid_ssl_protocols = frozenset([e.value for e in ApplicationGatewaySslProtocol])
    _valid_ssl_policy_types = frozenset([e.value for e in ApplicationGatewaySslPolicyType])
    _valid_ssl_policy_names = frozenset([e.value for e in ApplicationGatewaySslPolicyName])

    def __init__(self, policy_type=None, policy_name=None, disabled_ssl_protocols=None, cipher_suites=None, min_protocol_version=None, **kwargs):
        super(SslPolicy, self).__init__(**kwargs)
        self.policy_type = policy_type if policy_type else None
        self.policy_name = policy_name if policy_name is not None else []
        self.disabled_ssl_protocols = disabled_ssl_protocols if disabled_ssl_protocols else None
        self.cipher_suites = cipher_suites if cipher_suites is not None else []
        self.min_protocol_version = min_protocol_version if min_protocol_version else None
        self._validation.update({
            'policy_type': {'required': True, 'custom': SslPolicy._is_valid_ssl_policy_type},
            'policy_name': {'required': True, 'min_items': 1, 'custom': SslPolicy._is_valid_ssl_policy_name},
            'cipher_suites': {'custom': SslPolicy._is_valid_cipher_suites},
            'disabled_ssl_protocols': {'custom': SslPolicy._is_valid_ssl_protocol},
            'min_protocol_version': {'custom': SslPolicy._is_valid_ssl_protocol}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewaySslPolicySdk)

        model = factory(
            disabled_ssl_protocols = self.disabled_ssl_protocols,
            policy_type = self.policy_type,
            policy_name = self.policy_name if self.policy_name else None,
            cipher_suites = self.cipher_suites,
            min_protocol_version = self.min_protocol_version
        )

        return model

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_cipher_suites)))
    def _is_valid_cipher_suites(self, value):

        if value in self._valid_cipher_suites:
            return True
        else:
            return False

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ssl_protocols)))
    def _is_valid_ssl_protocol(self, value):

        if value in self._valid_ssl_protocols:
            return True
        else:
            return False

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ssl_policy_types)))
    def _is_valid_ssl_policy_type(self, value):

        if value in self._valid_ssl_policy_types:
            return True
        else:
            return False

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ssl_policy_names)))
    def _is_valid_ssl_policy_name(self, value):

        if value in self._valid_ssl_policy_names:
            return True
        else:
            return False
