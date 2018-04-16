# TODO: A pool can contain only one of these three: IPs in BackendAddresses array, IPConfigurations of standalone Network Interfaces
# Validate IP Addresses
from msrestazure.tools import resource_id

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
    ApplicationGatewaySslCertificate as ApplicationGatewaySslCertificateSdk
)

from .building_block_settings import (BuildingBlock,
                                      RegisterBuildingBlock)
from .resources import (Resource,
                        ResourceId,
                        TaggedResource,
                        TopLevelResource,
                        convert_string_to_enum,
                        extract_resource_groups)
from ..validations import ValidationFunction

from ..validations.networking import (is_valid_port_range)



@RegisterBuildingBlock(name='ApplicationGateway', template_url='buildingBlocks/applicationGateways/applicationGateways.json', deployment_name='agws')
class ApplicationGatewayBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[ApplicationGateway]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(ApplicationGatewayBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    def transform(self):
        ip_addresses = [application_gateway.frontend_ip_configurations for application_gateway in self.settings if application_gateway.frontend_ip_configurations]
        public_ip_addresses = [ip_address.transform() for ip_address in ip_addresses[0] if ip_address.application_gateway_type == 'Public']
        application_gateways = [application_gateway.transform() for application_gateway in self.settings]
        
        resource_groups = extract_resource_groups(application_gateways)
        template_parameters = {
            'applicationGateways': application_gateways,
            'publicIpAddresses': public_ip_addresses
        }
        return resource_groups, template_parameters

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(ApplicationGatewaySdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })

@ResourceId(namespace="Microsoft.Network", type="ApplicationGateways")
class ApplicationGateway(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        "sku": {"key": "sku", "type": "Sku"},
        "gateway_ip_configurations": {"key": "gatewayIPConfigurations", "type": "[GatewayIPConfiguration]"},
        "frontend_ip_configurations": {"key": "frontendIPConfigurations", "type": "[FrontendIPConfiguration]", 'parent': 'application_gateway'},
        "backend_address_pools": {"key": "backendAddressPools", "type": "[BackendAddressPool]"},
        "backend_http_settings_collection": {"key": "backendHttpSettingsCollection", "type": "[BackendHttpSettings]"},
        "http_listeners": {"key": "httpListeners", "type": "[HttpListener]"},
        "redirect_configurations": {"key": "redirectConfigurations", "type": "[RedirectConfiguration]"},
        "url_path_maps": {"key": "urlPathMaps", "type": "[UrlPathMap]"},
        "request_routing_rules": {"key": "requestRoutingRules", "type": "[RequestRoutingRule]"},
        "web_application_firewall_configuration": {"key": "webApplicationFirewallConfiguration", "type": "WebApplicationFirewallConfiguration"},
        "probes": {"key": "probes", "type": "[Probe]"},
        "ssl_certificates": {"key": "sslCertificates", "type": "[SslCertificate]"},
        "authentication_certificate": {"key": "authenticationCertificate", "type": "[AuthenticationCertificate]"},
        "frontend_ports": {"key": "frontendPorts", "type": "[FrontendPort]"},
        "ssl_policy": {"key": "sslPolicy", "type": "SslPolicy"}
    }

    def __init__(self, sku=None, gateway_ip_configurations=None, frontend_ip_configurations=None, backend_address_pools=None, backend_http_settings_collection=None, http_listeners=None, redirect_configurations=None, url_path_maps=None, request_routing_rules=None, web_application_firewall_configuration=None, probes=None, ssl_certificates=None, authentication_certificate=None, frontend_ports=None, ssl_policy=None, **kwargs):
         super(ApplicationGateway, self).__init__(**kwargs)
         self.sku = sku if sku else None
         self.gateway_ip_configurations = gateway_ip_configurations if gateway_ip_configurations else None
         self.frontend_ip_configurations = frontend_ip_configurations if frontend_ip_configurations else None
         self.backend_address_pools = backend_address_pools if backend_address_pools else None
         self.backend_http_settings_collection = backend_http_settings_collection if backend_http_settings_collection else None
         self.http_listeners = http_listeners if http_listeners else None
         self.redirect_configurations = redirect_configurations if redirect_configurations else None
         self.url_path_maps = url_path_maps if url_path_maps else None
         self.request_routing_rules = request_routing_rules if request_routing_rules else None
         self.web_application_firewall_configuration = web_application_firewall_configuration if web_application_firewall_configuration else None
         self.probes = probes if probes else None
         self.ssl_certificates = ssl_certificates if ssl_certificates else None
         self.authentication_certificate = authentication_certificate if authentication_certificate else None
         self.frontend_ports = frontend_ports if frontend_ports else None
         self.ssl_policy = ssl_policy if ssl_policy else None
         self._validation.update({
             "sku": {"required": True},
             "gateway_ip_configurations": {"required": True, "min_items": 1},
             "frontend_ip_configurations": {"required": True, "min_items": 1},
             "backend_address_pools": {"required": True, "min_items": 1},
             "backend_http_settings_collection": {"required": True, "min_items": 1},
             "http_listeners": {"required": True, "min_items": 1},
             #"redirect_configurations": {"required": True, "min_items": 1},
             "url_path_maps": {"required": True, "min_items": 1},
             "requesting_routing_rules": {"required": True, "min_items": 1},
             "web_application_firewall_configuration": {"required": True},
             "probes": {"required": True, "min_items": 1},
             "ssl_certificates": {"required": True, "min_items": 1},
             "frontend_ports": {"required": True, "min_items": 1}
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewaySdk)
        model = factory(
            id = self.id,
            name = self.name,
            subscription_id = self.subscription_id,
            resource_group_name = self.resource_group_name,
            location = self.location,
            tags = self.tags,
            sku = self.sku,
            ssl_policy = self.ssl_policy,
            gateway_ip_configurations = self.gateway_ip_configurations,
            authentication_certificates = self.authentication_certificate,
            ssl_certificates = self.ssl_certificates,
            frontend_ip_configurations = self.frontend_ip_configurations,
            frontend_ports = self.frontend_ports,
            probes = self.probes,
            backend_address_pools = self.backend_address_pools,
            backend_http_settings_collection = self.backend_http_settings_collection,
            http_listeners = self.http_listeners,
            url_path_maps = self.url_path_maps,
            request_routing_rules = self.request_routing_rules,
            redirect_configurations = self.redirectConfigurations,
            web_application_firewall_configuration = self.web_application_firewall_configuration
        )
        return model

class Sku(Resource):
    _attribute_map = {
        "size": {"key": "size", "type": "str"},
        "capacity": {"key": "capacity", "type": "int"},
        "tier": {"key": "tier", "type": "str"}
    }

    _valid_sizes = frozenset([e.value for e in ApplicationGatewaySkuName])
    _valid_tiers = frozenset([e.value for e in ApplicationGatewayTier])

    def __init__(self, size=None, capacity=None, tier=None, **kwargs):
         super(Sku, self).__init__(**kwargs)
         self.size = size if size else "Small"
         self.capacity = capacity if capacity else None
         self.tier = tier if tier else "Standard"
         self._validation.update({
             "size": {"required": True, "custom": Sku._is_valid_sku},
             "capacity": {"required": True, "custom": Sku._is_valid_capacity},
             "tier": {"required": True, "custom": Sku._is_valid_tier}
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewaySkuSdk)
        model = factory(
            name = self.size,
            tier = self.tier,
            capacity = self.capacity
        )
        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_sizes)))
    def _is_valid_sku(self, value):
        value = 'Standard_{}'.format(value)
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
        "subnet_name": {"key": "subnetName", "type": "str"}
    }

    def __init__(self, subnet_name=None, **kwargs):
         super(GatewayIPConfiguration, self).__init__(**kwargs)
         self.subnet_name = subnet_name if subnet_name else None

         self._validation.update({
             "subnet_name": {"required": True}
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayIPConfigurationSdk)

        model = factory(
            id = self.id,
            name = self.name,
            subnet = self.subnet_name
        )

        return model

class FrontendIPConfiguration(TopLevelResource, Resource):
    _attribute_map = {
        "application_gateway_type": {"key": "applicationGatewayType", "type": "str"},
        "internal_application_gateway_settings": {"key": "internalApplicationGatewaySettings", "type": "InternalApplicationGatewaySetting"}
    }
    
    def __init__(self, application_gateway_type=None, internal_application_gateway_settings=None, **kwargs):
        super(FrontendIPConfiguration, self).__init__(**kwargs)
        self.application_gateway_type = application_gateway_type if application_gateway_type else None
        self.internal_application_gateway_settings = internal_application_gateway_settings if internal_application_gateway_settings else None
        self._validation.update({
            "application_gateway_type": {"required": True, "custom": FrontendIPConfiguration._is_valid_gateway_type}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayFrontendIPConfigurationSdk)

        model = factory(
            name = self.name,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            private_ip_allocation_method = 'Dynamic',
            public_ip_address = self.name if self.application_gateway_type == 'Public' else None,
            subnet = self.internal_application_gateway_settings.subnet_name if self.application_gateway_type == 'Internal' else None
        )

        return model

    @ValidationFunction('Value must be one of the following values: Public, Internal')
    def _is_valid_gateway_type(self, value):
        types = ["Public", "Internal"]

        if value in types:
            return True
        else:
            return False

class InternalApplicationGatewaySetting(Resource):
    _attribute_map = {
        "subnet_name": {"key": "subnetName", "type": "str"}
    }

    def __init__(self, subnet_name=None, **kwargs):
         super(InternalApplicationGatewaySetting, self).__init__(**kwargs)
         self.subnet_name = subnet_name if subnet_name else None
         self._validation.update({
             "subnet_name": {"required": True}
         })

    def transform(self):
        # TODO
        return False

class BackendAddressPool(Resource):

    _attribute_map = {
        "backend_addresses": {"key": "backendAddresses", "type": "[BackendAddress]"}
    }

    def __init__(self, backend_addresses=None, **kwargs):
         super(BackendAddressPool, self).__init__(**kwargs)
         self.backend_addresses = backend_addresses if backend_addresses else None
         self._validation.update({
             "backend_addresses": {"required": True, "min_items": 1}
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayBackendAddressPoolSdk)

        model = factory(
            id = self.id,
            name = self.name,
            backend_addresses = self.backend_addresses
        )

        return model

class BackendAddress(Resource):
    _attribute_map = {
        "fqdn": {"key": "fqdn", "type": "str"}#,
        #"ip_address": {"key": "ipAddress", "type": "str"}
    }

    def __init__(self, fqdn=None, ip_address=None, **kwargs):
         super(BackendAddress, self).__init__(**kwargs)
         self.fqdn = fqdn if fqdn else None
         #self.ip_address if ip_address else None
         self._validation.update({
            # Todo
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayBackendAddressSdk)

        model = factory(
            fqdn = self.fqdn#,
            #ip_address = self.ip_address
        )

        return model

class BackendHttpSettings(Resource):
    _attribute_map = {
        "port": {"key": "port", "type": "int"},
        "protocol": {"key": "protocol", "type": "str"},
        "cookie_based_affinity": {"key": "cookieBasedAffinity", "type": "str"},
        "affinity_cookie_name": {"key": "affinityCookieName", "type": "str"},
        "connection_draining": {"key": "connection_draining", "type": "ConnectionDraining"},
        "pick_host_name_from_backend_address": {"key": "pickHostNameFromBackendAddress", "type": "bool"},
        "host_name": {"key": "hostName", "type": "str"},
        "request_timeout": {"key": "requestTimeout", "type": "int"},
        "path": {"key": "path", "type": "str"},
        "host_header_name": {"key": "hostHeaderName", "type": "str"},
        "probe_enabled": {"key": "probeEnabled", "type": "bool"},
        "probe_name": {"key": "probeName", "type": "str"}
    }

    _valid_affinity = frozenset([e.value for e in ApplicationGatewayCookieBasedAffinity])
    _valid_protocol_types = frozenset([e.value for e in ApplicationGatewayProtocol])

    def __init__(self, port=None, protocol=None, cookie_based_affinity=None, affinity_cookie_name=None, connection_draining=None, pick_host_name_from_backend_address=None, host_name=None, request_timeout=None, path=None, host_header_name=None, probe_enabled=None, probe_name=None, **kwargs):
         super(BackendHttpSettings, self).__init__(**kwargs)
         self.port = port if port else None
         self.protocol = protocol if protocol else None
         self.cookie_based_affinity = cookie_based_affinity if cookie_based_affinity else None
         self.affinity_cookie_name = affinity_cookie_name if affinity_cookie_name else None
         self.connection_draining = connection_draining if connection_draining else None
         self.pick_host_name_from_backend_address = pick_host_name_from_backend_address if pick_host_name_from_backend_address else None
         self.host_name = host_name if host_name else None
         self.request_timeout = request_timeout if request_timeout else None
         self.path = path if path else None
         self.host_header_name = host_header_name if host_header_name else None
         self.probe_enabled = probe_enabled if probe_enabled else None
         self.probe_name = probe_name if probe_name else None
         self._validation.update({
            "port": {"required": True, "custom": is_valid_port_range},
            "protocol": {"required": True, "custom": BackendHttpSettings._is_valid_protocol},
            "cookie_based_affinity": {"required": True, "custom": BackendHttpSettings._is_valid_cookie_based_affinity},
            "connection_draining": {"required": True},
            "pick_host_name_from_backend_address": {"required": True},
            "host_name": {"required": True},
            "request_timeout": {"required": True},
            "probe_name": {"required": True}
         })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayBackendHttpSettingsSdk)

        model = factory(
            name = self.name,
            port = self.port,
            protocol = self.protocol,
            cookie_based_affinity = self.cookie_based_affinity,
            request_timeout = self.request_timeout,
            connection_draining = self.connection_draining,
            pick_host_name_from_backend_address = self.pick_host_name_from_backend_address,
            host_name = self.host_name
        )

        # TODO: prob, authentication certificates, probe, affinity_cookie_name, path

        return model
    
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_affinity)))
    def _is_valid_cookie_based_affinity(self, value):
        
        if value in self._valid_affinity:
            return True
        else:
            return False
            
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_protocol_types)))
    def _is_valid_protocol(self, value):

        if value in self._valid_protocol_types:
            return True
        else:
            return False

class ConnectionDraining(Resource):
    _attribute_map = {
        "enabled": {"key": "enabled", "type": "bool"},
        "drain_timeout_in_sec": {"key": "drainTimeoutInSec", "type": "int"}
    }

    def __init__(self, enabled=None, drain_timeout_in_sec=None, **kwargs):
         super(ConnectionDraining, self).__init__(**kwargs)

    def transform(self):
        # TODO: Transform
        return False
        
class HttpListener(Resource):
    _attribute_map = {
        "frontend_ip_configuration_name": {"key": "frontendIPConfigurationName", "type": "str"},
        "frontend_port_name": {"key": "frontendPortName", "type": "str"},
        "protocol": {"key": "protocol", "type": "str"},
        "ssl_certificate_name": {"key": "sslCertificateName", "type": "str"},
        "require_server_name_indication": {"key": "requireServerNameIndication", "type": "bool"}
    }

    _valid_protocol_types = frozenset([e.value for e in ApplicationGatewayProtocol])

    def __init__(self, frontend_ip_configuration_name=None, frontend_port_name=None, protocol=None, ssl_certificate_name=None, require_server_name_indication=None, **kwargs):
        super(HttpListener, self).__init__(**kwargs)
        self.frontend_ip_configuration_name = frontend_ip_configuration_name if frontend_ip_configuration_name else None
        self.frontend_port_name = frontend_port_name if frontend_port_name else None
        self.protocol = protocol if protocol else None
        self.ssl_certificate_name = ssl_certificate_name if ssl_certificate_name else None
        self.require_server_name_indication = require_server_name_indication if require_server_name_indication else None
        self._validation.update({
            "frontend_ip_configuration_name": {"required": True},
            "frontend_port_name": {"required": True},
            "protocol": {"required": True, "custom": HttpListener._is_valid_protocol},
            "ssl_certificate_name": {"required": True},
            "require_server_name_indication": {"required": True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayHttpListenerSdk)

        model = factory(
            id = self.id,
            name = self.name,
            frontend_ip_cofiguration = self.frontend_ip_configuration_name,
            frontend_port = self.frontend_port_name,
            protocol = self.protocol,
            ssl_certificate = self.ssl_certificate_name,
            require_server_name_indication = self.require_server_name_indication
        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_protocol_types)))
    def _is_valid_protocol(self, value):
        
        if value in self._valid_protocol_types:
            return True
        else:
            return False

class RedirectConfiguration(Resource):
    _attribute_map = {
        "redirect_type": {"key": "redirectType", "type": "str"},
        "include_query_string": {"key": "includeQueryString", "type": "bool"},
        "target_listener_name": {"key": "targetListenerName", "type": "str"},
        "include_path": {"key": "includePath", "type": "bool"},
        "target_url": {"key": "targetUrl", "type": "str"}    
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
            "redirect_type": {"required": True, "custom": RedirectConfiguration._is_valid_redirect_type},
            "include_query_string": {"required": True},
            "target_listener_name": {"required": True},
            "target_url": {"required": True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayRedirectConfigurationSdk)

        model = factory(
            id = self.id,
            name = self.name,
            redirect_type = self.redirect_type,
            include_query_string = self.include_query_string,
            target_listener = self.target_listener_name,
            target_url = self.target_url
        )

        # TODO: Routing request rules

        # TODO: Url path maps

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_redirect_types)))
    def _is_valid_redirect_type(self, value):
        
        if value in self._redirect_types:
            return True
        else:
            return False

class UrlPathMap(Resource): 
    _attribute_map = {
        "default_backend_address_pool_name": {"key": "defaultBackendAddressPoolName", "type": "str"},
        "default_backend_http_settings_name": {"key": "defaultBackendHttpSettingsName", "type": "str"},
        "default_redirect_configuration_name": {"key": "defaultRedirectConfigurationName", "type": "str"},
        "path_rules": {"key": "pathRules", "type": "[PathRule]"}
    }

    def __init__(self, default_backend_address_pool_name=None, default_backend_http_settings_name=None, default_redirect_configuration_name=None, path_rules=None, **kwargs):
        super(UrlPathMap, self).__init__(**kwargs)
        self.default_backend_address_pool_name = default_backend_address_pool_name if default_backend_address_pool_name else None
        self.default_backend_http_settings_name = default_backend_http_settings_name if default_backend_http_settings_name else None
        self.default_redirect_configuration_name = default_redirect_configuration_name if default_redirect_configuration_name else None
        self.path_rules = path_rules if path_rules else None
        self._validation.update({
            "default_backend_address_pool_name": {"required": True},
            "default_backend_http_settings_name":  {"required": True},
            "default_redirect_configuration_name":  {"required": True},
            "path_rules":  {"required": True, "min_items": 1}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayUrlPathMapSdk)

        model = factory(
            id = self.id,
            name = self.name,
            default_backend_address_pool = self.default_backend_address_pool_name,
            default_backend_http_settings = self.default_backend_http_settings_name,
            default_redirect_configuration = self.default_redirect_configuration_name,
            path_rules = self.path_rules
        )

        return model

class PathRule(Resource):
    _attribute_map = {
        "paths": {"key": "paths", "type": "[str]"},
        "backend_address_pool_name": {"key": "backendAddressPoolName", "type": "str"},
        "backend_http_settings_name": {"key": "backendHttpSettingsName", "type": "str"},
        "redirect_configuration_name": {"key": "redirectConfigurationName", "type": "str"}
    }

    def __init__(self, paths=None, backend_address_pool_name=None, backend_http_settings_name=None, redirect_configuration_name=None, **kwargs):
        super(PathRule, self).__init__(**kwargs)
        self.paths = paths if paths else None
        self.backend_address_pool_name = backend_address_pool_name if backend_address_pool_name else None
        self.backend_http_settings_name = backend_http_settings_name if backend_http_settings_name else None
        self.redirect_configuration_name = redirect_configuration_name if redirect_configuration_name else None
        self._validation.update({
            "paths": {"required": True, "min_items": 1},
            "backend_address_pool_name": {"required": True},
            "backend_http_settings_name": {"required": True},
            "redirect_configuration_name": {"required": True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayPathRuleSdk)

        model = factory (
            id = self.id,
            paths = self.paths,
            backend_address_pool = self.backend_address_pool_name,
            backend_http_settings = self.backend_http_settings_name,
            redirect_configuration = self.redirect_configuration_name
        )

        return model

class RequestRoutingRule(Resource):
    _attribute_map = {
        "http_listener_name": {"key": "httpListenerName", "type": "str"},
        "rule_type": {"key": "ruleType", "type": "str"},
        "backend_address_pool_name": {"key": "backendAddressPoolName", "type": "str"},
        "backend_http_settings_name": {"key": "backendHttpSettingsName", "type": "str"},
        "redirect_configuration_name": {"key": "redirectConfigurationName", "type": "str"},
        "url_path_map_name": {"key": "urlPathMapName", "type": "str"}
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
            "http_listener_name": {"required": True},
            "rule_type": {"required": True, "custom": RequestRoutingRule._is_valid_routing_rule_type},
            "backend_address_pool_name": {"required": True},
            "backend_http_settings_name": {"required": True},
            "redirect_configuration_name": {"required": True},
            "url_path_map_name": {"required": True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayRequestRoutingRuleSdk)

        model = factory(
            id = self.id,
            name = self.name,
            rule_type = self.rule_type,
            backend_address_pool = self.backend_address_pool_name,
            backend_http_settings = self.backend_http_settings_name,
            url_path_map = self.url_path_map,
            redirect_configuration = self.redirect_configuration_name
        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_routing_rule_types)))
    def _is_valid_routing_rule_type(self, value):

        if value in self._valid_routing_rule_types:
            return True
        else:
            return False

class WebApplicationFirewallConfiguration(Resource):
    _attribute_map = {
        "enabled": {"key": "enabled", "type": "bool"},
        "firewall_mode": {"key": "firewallMode", "type": "str"},
        "rule_set_type": {"key": "ruleSetType", "type": "str"},
        "rule_set_version": {"key": "ruleSetVersion", "type": "str"},
        "disabled_rule_groups": {"key": "disabledRuleGroups", "type": "[DisabledRuleGroup]"}
    }

    _valid_firewall_mode = frozenset([e.value for e in ApplicationGatewayFirewallModeSdk])

    def __init__(self, enabled=None, firewall_mode=None, rule_set_type=None, rule_set_version=None, disabled_rule_groups=None, **kwargs):
        super(WebApplicationFirewallConfiguration, self).__init__(**kwargs)
        self.enabled = enabled if enabled else None
        self.firewall_mode = firewall_mode if firewall_mode else None
        self.rule_set_type = rule_set_type if rule_set_type else 'OWASP'
        self.rule_set_version = rule_set_version if rule_set_version else None
        self.disabled_rule_groups = disabled_rule_groups if disabled_rule_groups else None
        self._validation.update({
            "enabled": {"required": True},
            "firewall_mode": {"required": True, "custom": WebApplicationFirewallConfiguration._is_valid_firewall_mode},
            "rule_set_type": {"required": True, "custom": WebApplicationFirewallConfiguration._is_valid_rule_type},
            "rule_set_version": {"required": True},
            "disabled_rule_groups": {"required": True, "min_items": 1}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayWebApplicationFirewallConfigurationSdk)

        model = factory(
            enabled = self.enabled,
            firewall_mode = self.firewall_mode,
            rule_set_type = self.rule_set_type,
            rule_set_version = self.rule_set_version,
            disabled_rule_groups = self.disabled_rule_groups
        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_firewall_mode)))
    def _is_valid_firewall_mode(self, value):

        if value in self._valid_firewall_mode:
            return True
        else:
            return False

    @ValidationFunction('Value must be set to OWASP')
    def _is_valid_rule_type(self, value):

        if value == 'OWASP':
            return True
        else:
            return False

class DisabledRuleGroup(Resource):
    _attribute_map = {
        "rule_group_name": {"key": "ruleGroupName", "type": "str"},
        "rules": {"key": "rules", "type": "[str]"}
    }

    def __init__(self, rule_group_name=None, rules=None, **kwargs):
        super(DisabledRuleGroup, self).__init__(**kwargs)
        self.rule_group_name = rule_group_name if rule_group_name else None
        self.rules = rules if rules else None
        self._validation.update({
            "rule_group_name": {"required": True},
            "rules": {"required": True, "min_items": 1}
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
        "protocol": {"key": "protocol", "type": "str"},
        "host": {"key": "host", "type": "str"},
        "path": {"key": "path", "type": "str"},
        "interval": {"key": "interval", "type": "int"},
        "timeout": {"key": "timeout", "type": "int"},
        "unhealthy_threshold": {"key": "unhealthyThreshold", "type": "int"},
        "pick_host_name_from_backend_http_settings": {"key": "pickHostNameFromBackendHttpSettings", "type": "bool"},
        "min_servers": {"key": "minServers", "type": "int"},
        "match": {"key": "match", "type": "Match"}
    }

    _valid_protocol_types = frozenset([e.value for e in ApplicationGatewayProtocol])

    def __init__(self, protocol=None, host=None, path=None, interval=None, timeout=None, unhealthy_threshold=None, pick_host_name_from_backend_http_settings=None, min_servers=None, match=None, **kwargs):
        super(Probe, self).__init__(**kwargs)
        self.protocol = protocol if protocol else None
        self.host = host if host else None
        self.path = path if path else None
        self.interval = interval if interval else None
        self.timeout = timeout if timeout else None
        self.unhealthy_threshold = unhealthy_threshold if unhealthy_threshold else None
        self.pick_host_name_from_backend_http_settings = pick_host_name_from_backend_http_settings if pick_host_name_from_backend_http_settings else None
        self.min_servers = min_servers if min_servers else None
        self.match = match if match else None
        self._validation.update({
            "protocol": {"required": True, "custom": Probe._is_valid_protocol},
            "host": {"required": True},
            "path": {"required": True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock(ApplicationGatewayProbeSdk)

        model = factory(
            id = self.id,
            name = self.name,
            protocol = self.protocol,
            host = self.host,
            path = self.path
        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_protocol_types)))
    def _is_valid_protocol(self, value):

        if value in self._valid_protocol_types:
            return True
        else:
            return False

class Match(Resource):
    _attribute_map = {
        "body": {"key": "body", "type": "str"},
        "status_codes": {"key": "statusCodes", "type": "[str]"}
    }

    def __init__(self, body=None, status_codes=None, **kwargs):
        super(Match, self).__init__(**kwargs)
        self.body = body if body else None
        self.status_codes = status_codes if status_codes else None

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayProbeHealthResponseMatchSdk)

        model = factory(
            body = self.body,
            status_codes = self.status_codes
        )

        return model

class SslCertificate(Resource):
    _attribute_map = {
        "data": {"key": "data", "type": "str"},
        "password": {"key": "password", "type": "str"}
    }

    def __init__(self, data=None, password=None, **kwargs):
        super(SslCertificate, self).__init__(**kwargs)
        self.data = data if data else None
        self.password = password if password else None
        self._validation.update({
            "data": {"required": True},
            "password": {"required": True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewaySslCertificateSdk)

        model = factory(
            id = self.id,
            name = self.name,
            data = self.data,
            password = self.password
        )

        return model

class AuthenticationCertificate(Resource):
    _attribute_map = {
        "data": {"key": "data", "type": "str"}
    }

    def __init__(self, data=None, **kwargs):
        super(AuthenticationCertificate, self).__init__(**kwargs)
        self.data = data if data else None

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayAuthenticationCertificateSdk)

        model = factory(
            id = self.id,
            name = self.name,
            data = self.data
        )

        return model

class FrontendPort(Resource):
    _attribute_map = {
        "port": {"key": "port", "type": "int"}
    }

    def __init__(self, port=None, **kwargs):
        super(FrontendPort, self).__init__(**kwargs)
        self.port = port if port else None
        self._validation.update({
            "port": {"required": True}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewayFrontendPortSdk)

        model = factory(
            id = self.id,
            name = self.name,
            port = self.port
        )

        return model

class SslPolicy(Resource):
    _attribute_map = {
        "policy_type": {"key": "policyType", "type": "str"},
        "policy_name": {"key": "policyName", "type": "[str]"},
        "disabled_ssl_protocols": {"key": "disabledSslProtocols", "type": "[str]"},
        "cipher_suites": {"key": "cipherSuites", "type": "[str]"},
        "min_protocol_version": {"key": "minProtocolVersion", "type": "str"}
    }

    _valid_cipher_suites = frozenset([e.value for e in ApplicationGatewaySslCipherSuite])
    _valid_ssl_protocols = frozenset([e.value for e in ApplicationGatewaySslProtocol])
    _valid_ssl_policy_types = frozenset([e.value for e in ApplicationGatewaySslPolicyType])
    _valid_ssl_policy_names = frozenset([e.value for e in ApplicationGatewaySslPolicyName])

    def __init__(self, policy_type=None, policy_name=None, disabled_ssl_protocols=None, cipher_suites=None, min_protocol_version=None, **kwargs):
        super(SslPolicy, self).__init__(**kwargs)
        self.policy_type = policy_type if policy_type else None
        self.policy_name = policy_name if policy_name else None
        self.disabled_ssl_protocols = disabled_ssl_protocols if disabled_ssl_protocols else None
        self.cipher_suites = cipher_suites if cipher_suites else None
        self.min_protocol_version = min_protocol_version if min_protocol_version else None
        self._validation.update({
            "policy_type": {"required": True, "custom": SslPolicy._is_valid_ssl_policy_type},
            "policy_name": {"required": True, "min_items": 1, "custom": SslPolicy._is_valid_ssl_policy_name},
            "cipher_suites": {"custom": SslPolicy._is_valid_cipher_suites},
            "disabled_ssl_protocols": {"custom": SslPolicy._is_valid_ssl_protocol},
            "min_protocol_version": {"custom": SslPolicy._is_valid_ssl_protocol}
        })

    def transform(self):
        factory = ApplicationGatewayBuildingBlock.get_sdk_model(ApplicationGatewaySslPolicySdk)

        model = factory(

        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_cipher_suites)))
    def _is_valid_cipher_suites(self, value):

        if value in self._valid_cipher_suites:
            return True
        else:
            return False

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ssl_protocols)))
    def _is_valid_ssl_protocol(self, value):

        if value in self._valid_ssl_protocols:
            return True
        else:
            return False

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ssl_policy_types)))
    def _is_valid_ssl_policy_type(self, value):

        if value in self._valid_ssl_policy_types:
            return True
        else:
            return False

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_ssl_policy_names)))
    def _is_valid_ssl_policy_name(self, value):

        if value in self._valid_ssl_policy_names:
            return True
        else:
            return False
    

    
