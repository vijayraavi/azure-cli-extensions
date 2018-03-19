from azure.mgmt.network.models import (NetworkSecurityGroup as NetworkSecurityGroupSdk,
                                       SecurityRule as SecurityRuleSdk,
                                       SecurityRuleAccess,
                                       SecurityRuleDirection,
                                       SecurityRuleProtocol, SubResource)
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
from ..validations.networking import (is_valid_cidr,
                                      is_valid_ip_address,
                                      is_valid_port_range)

@RegisterBuildingBlock(name='NetworkSecurityGroup', template_url='buildingBlocks/networkSecurityGroups/networkSecurityGroups.json', deployment_name='nsg')
class NetworkSecurityGroupBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[NetworkSecurityGroup]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(NetworkSecurityGroupBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(NetworkSecurityGroupSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}
        })

    def transform(self):
        # Make sure we have validated before this! :)
        subnets = [NetworkSecurityGroupSubnet(
            name=subnet,
            subscription_id=virtual_network.subscription_id,
            resource_group_name=virtual_network.resource_group_name,
            location=virtual_network.location,
            virtual_network_name=virtual_network.name,
            network_security_group_id=network_security_group.id
        ) for network_security_group in self.settings for virtual_network in network_security_group.virtual_networks for subnet in virtual_network.subnets]
        network_interfaces = [NetworkSecurityGroupNetworkInterface(
            name=network_interface.name,
            subscription_id=network_interface.subscription_id,
            resource_group_name=network_interface.resource_group_name,
            location=network_interface.location,
            network_security_group_id=network_security_group.id
        ) for network_security_group in self.settings for network_interface in network_security_group.network_interfaces]
        network_security_groups = [network_security_group.transform() for network_security_group in self.settings]

        resource_groups = extract_resource_groups(network_security_groups)
        template_parameters = {
            "networkSecurityGroups": network_security_groups,
            "subnets": subnets,
            "networkInterfaces": network_interfaces
        }

        return resource_groups, template_parameters

class SecurityRule(Resource):

    _attribute_map = {
        'protocol': {'key': 'protocol', 'type': 'str'},
        'source_port_range': {'key': 'sourcePortRange', 'type': 'str'},
        'destination_port_range': {'key': 'destinationPortRange', 'type': 'str'},
        'source_address_prefix': {'key': 'sourceAddressPrefix', 'type': 'str'},
        'destination_address_prefix': {'key': 'destinationAddressPrefix', 'type': 'str'},
        'direction': {'key': 'direction', 'type': 'str'},
        'priority': {'key': 'priority', 'type': 'int'},
        'access': {'key': 'access', 'type': 'str'}
    }

    _valid_protocols = frozenset([e.value for e in SecurityRuleProtocol])
    _valid_default_tags = frozenset(['VirtualNetwork', 'AzureLoadBalancer', 'Internet', '*'])
    _valid_directions = frozenset([e.value for e in SecurityRuleDirection])
    _valid_accesses = frozenset([e.value for e in SecurityRuleAccess])

    def __init__(self, protocol=None, source_port_range=None, destination_port_range=None, source_address_prefix=None, destination_address_prefix=None, direction=None, priority=None, access=None, **kwargs):
        super(SecurityRule, self).__init__(**kwargs)
        self.protocol = convert_string_to_enum(SecurityRuleProtocol, protocol)
        self.source_port_range = source_port_range
        self.destination_port_range = destination_port_range
        self.source_address_prefix = source_address_prefix
        self.destination_address_prefix = destination_address_prefix
        self.direction = convert_string_to_enum(SecurityRuleDirection, direction)
        self.priority = priority
        self.access = convert_string_to_enum(SecurityRuleAccess, access)
        self._validation.update({
            'protocol': {'required': True, 'custom': SecurityRule._is_valid_protocol},
            'source_port_range': {'required': True, 'custom': is_valid_port_range},
            'destination_port_range': {'required': True, 'custom': is_valid_port_range},
            'source_address_prefix': {'required': True, 'custom': is_valid_port_range},
            'destination_address_prefix': {'required': True, 'custom': is_valid_port_range},
            'direction': {'required': True, 'custom': SecurityRule._is_valid_direction},
            'priority': {'required': True, 'custom': SecurityRule._is_valid_priority},
            'access': {'required': True, 'custom': SecurityRule._is_valid_access}
        })

    def transform(self):
        factory = NetworkSecurityGroupBuildingBlock.get_sdk_model(SecurityRuleSdk)
        model = factory(
            self.protocol,
            access=self.access,
            direction=self.direction,
            source_port_range=self.source_port_range,
            destination_port_range=self.destination_port_range,
            source_address_prefix=self.source_address_prefix,
            source_address_prefixes=None,
            source_application_security_groups=None,
            destination_address_prefix=self.destination_address_prefix,
            destination_address_prefixes=None,
            destination_application_security_groups=None,
            source_port_ranges=None,
            destination_port_ranges=None,
            priority=self.priority,
            name=self.name
        )
        return model

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_protocols)))
    def _is_valid_protocol(cls, value):
        return value.value in cls._valid_protocols

    @classmethod
    @ValidationFunction('Valid values are an IPAddress, a CIDR, or one of the following values: {}'.format(','.join(_valid_default_tags)))
    def _is_valid_address_prefix(cls, value):
        return is_valid_ip_address(value) or is_valid_cidr(value) or value in cls._valid_default_tags

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_directions)))
    def _is_valid_direction(cls, value):
        return value.value in cls._valid_directions

    @classmethod
    @ValidationFunction('Value must be between 100 and 4096, inclusive')
    def _is_valid_priority(cls, value):
        try:
            return 100 <= int(value) <= 4096
        except (TypeError, ValueError):
            return False

    @classmethod
    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_accesses)))
    def _is_valid_access(cls, value):
        return value.value in cls._valid_accesses

# We need a small class here since we aren't using an sdk class for the subnet wiring
class NetworkSecurityGroupSubnet(TopLevelResource, Resource):
    _attribute_map = {
        'virtual_network_name': {'key': 'virtualNetwork', 'type': 'str'},
        'network_security_group': {'key': 'properties.networkSecurityGroup', 'type': 'SubResource'}
    }

    def __init__(self, virtual_network_name=None, network_security_group_id=None, **kwargs):
        super(NetworkSecurityGroupSubnet, self).__init__(**kwargs)
        self.virtual_network_name = virtual_network_name
        self.network_security_group = SubResource(id=network_security_group_id)
        # We will set the id here instead of using the decorator
        self.id = resource_id(
            subscription=self.subscription_id,
            resource_group=self.resource_group_name,
            namespace="Microsoft.Network",
            type="virtualNetworks",
            name=self.virtual_network_name,
            child_type_1="subnets",
            child_name_1=self.name)

# We need a small class here since we aren't using an sdk class for the network interface wiring
class NetworkSecurityGroupNetworkInterface(TopLevelResource, Resource):
    _attribute_map = {
        'network_security_group': {'key': 'properties.networkSecurityGroup', 'type': 'SubResource'}
    }

    def __init__(self, network_security_group_id=None, **kwargs):
        super(NetworkSecurityGroupNetworkInterface, self).__init__(**kwargs)
        self.network_security_group = SubResource(id=network_security_group_id)
        # We will set the id here instead of using the decorator
        self.id = resource_id(
            subscription=self.subscription_id,
            resource_group=self.resource_group_name,
            namespace="Microsoft.Network",
            type="networkInterfaces",
            name=self.name)

@ResourceId(namespace='Microsoft.Network', type='networkSecurityGroups')
class NetworkSecurityGroup(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'security_rules': {'key': 'securityRules', 'type': '[SecurityRule]'},
        'virtual_networks': {'key': 'virtualNetworks', 'type' :'[VirtualNetworkReference]'},
        'network_interfaces': {'key': 'networkInterfaces', 'type': '[ResourceReference]'}
    }

    def __init__(self, security_rules=None, virtual_networks=None, network_interfaces=None, **kwargs):
        super(NetworkSecurityGroup, self).__init__(**kwargs)
        # We can expand the named rules here.
        self.security_rules = NetworkSecurityGroup._expand_named_security_rules(security_rules if security_rules else [])
        # Now we need to re-prioritize
        for index, security_rule in enumerate(self.security_rules):
            security_rule.priority = (index * 10) + 100
        self.virtual_networks = virtual_networks if virtual_networks else []
        self.network_interfaces = network_interfaces if network_interfaces else []
        self._validation.update({
            'security_rules': {'required': True, 'custom': self._find_duplicate_security_rule_names},
            'virtual_networks': {'required': True},
            'network_interfaces': {'required': True}
        })

    @classmethod
    def _expand_named_security_rules(cls, security_rules):
        def _create_named_security_rules(name=None, source_port_range=None, source_address_prefix=None, destination_address_prefix=None):
            return [SecurityRule(
                source_port_range=source_port_range if source_port_range else "*",
                source_address_prefix=source_address_prefix if source_address_prefix else "*",
                destination_address_prefix=destination_address_prefix if destination_address_prefix else "*", **kwargs
            ) for kwargs in NetworkSecurityGroup._named_security_rules[name]]
        # Get the named security rules out of our list
        named_security_rules = [rule for rule in security_rules if rule.name in cls._named_security_rules.keys()]
        # Assign over our parameter name with the non-named rules
        security_rules = [rule for rule in security_rules if rule.name not in cls._named_security_rules.keys()]
        # Append the expanded and mapped rules
        for named_security_rule in named_security_rules:
            security_rules += _create_named_security_rules(
                name=named_security_rule.name,
                source_port_range=named_security_rule.source_port_range,
                source_address_prefix=named_security_rule.source_address_prefix,
                destination_address_prefix=named_security_rule.destination_address_prefix)
        return security_rules

    def transform(self):
        factory = NetworkSecurityGroupBuildingBlock.get_sdk_model(NetworkSecurityGroupSdk)
        model = factory(
            id=self.id,  # pylint: disable=no-member
            name=self.name,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            location=self.location,
            tags=self.tags,
            security_rules=[security_rule.transform() for security_rule in self.security_rules]
        )

        return model

    @ValidationFunction()
    def _find_duplicate_security_rule_names(self, security_rules):
        # Ignore invalid names, as they will be caught by the SecurityRule validations
        seen = set()
        duplicates = set()
        seen_add = seen.add
        duplicates_add = duplicates.add
        for security_rule in security_rules:
            if security_rule.name in seen:
                duplicates_add(security_rule.name)
            else:
                seen_add(security_rule.name)
        duplicates = list(duplicates)
        return len(duplicates) == 0, 'Duplicate security rule names: {}'.format(','.join(duplicates))

    _named_security_rules = {
        "ActiveDirectory": [
            {
                "name": "AllowADReplication",
                "protocol": "*",
                "destination_port_range":"389",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowADReplicationSSL",
                "protocol": "*",
                "destination_port_range": "636",
                "direction": "Inbound",
                "access": "Allow"},
            {
                "name": "AllowADGCReplication",
                "protocol": "Tcp",
                "destination_port_range": "3268",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowADGCReplicationSSL",
                "protocol": "Tcp",
                "destination_port_range": "3269",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowDNS",
                "protocol": "*",
                "destination_port_range": "53",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowKerberosAuthentication",
                "protocol": "*",
                "destination_port_range": "88",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowADReplicationTrust",
                "protocol": "*",
                "destination_port_range": "445",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowSMTPReplication",
                "protocol": "Tcp",
                "destination_port_range": "25",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowRPCReplication",
                "protocol": "Tcp",
                "destination_port_range": "135",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowFileReplication",
                "protocol": "Tcp",
                "destination_port_range": "5722",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowWindowsTime",
                "protocol": "Udp",
                "destination_port_range": "123",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowPasswordChangeKerberes",
                "protocol": "*",
                "destination_port_range": "464",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowDFSGroupPolicy",
                "protocol": "Udp",
                "destination_port_range": "138",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowADDSWebServices",
                "protocol": "Tcp",
                "destination_port_range": "9389",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowNETBIOSAuthentication",
                "protocol": "Udp",
                "destination_port_range": "137",
                "direction": "Inbound",
                "access": "Allow"
            },
            {
                "name": "AllowNETBIOSReplication",
                "protocol": "Tcp",
                "destination_port_range": "139",
                "direction": "Inbound",
                "access": "Allow"
            }
        ],
        "Cassandra": [
            {
                "name": "Cassandra",
                "protocol": "Tcp",
                "destination_port_range": "9042",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "Cassandra-JMX": [
            {
                "name": "Cassandra-JMX",
                "protocol": "Tcp",
                "destination_port_range": "7199",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "Cassandra-Thrift": [
            {
                "name": "Cassandra-Thrift",
                "protocol": "Tcp",
                "destination_port_range": "9160",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "CouchDB": [
            {
                "name": "CouchDB",
                "protocol": "Tcp",
                "destination_port_range": "5984",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "CouchDB-HTTPS": [
            {
                "name": "CouchDB-HTTPS",
                "protocol": "Tcp",
                "destination_port_range": "6984",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "DNS-TCP": [
            {
                "name": "DNS-TCP",
                "protocol": "Tcp",
                "destination_port_range": "53",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "DNS-UDP": [
            {
                "name": "DNS-UDP",
                "protocol": "Udp",
                "destination_port_range": "53",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "DynamicPorts": [
            {
                "name": "DynamicPorts",
                "protocol": "Tcp",
                "destination_port_range": "49152-65535",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "ElasticSearch": [
            {
                "name": "ElasticSearch",
                "protocol": "Tcp",
                "destinationAddressPrefix": "*",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "FTP": [
            {
                "name": "FTP",
                "protocol": "Tcp",
                "destination_port_range": "21",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "HTTP": [
            {
                "name": "HTTP",
                "protocol": "Tcp",
                "destination_port_range": "80",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "HTTPS": [
            {
                "name": "HTTPS",
                "protocol": "Tcp",
                "destination_port_range": "443",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "IMAP": [
            {
                "name": "IMAP",
                "protocol": "Tcp",
                "destination_port_range": "143",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "IMAPS": [
            {
                "name": "IMAPS",
                "protocol": "Tcp",
                "destination_port_range": "993",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "Kestrel": [
            {
                "name": "Kestrel",
                "protocol": "Tcp",
                "destination_port_range": "22133",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "LDAP": [
            {
                "name": "LDAP",
                "protocol": "Tcp",
                "destination_port_range": "389",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "MongoDB": [
            {
                "name": "MongoDB",
                "protocol": "Tcp",
                "destination_port_range": "27017",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "Memcached": [
            {
                "name": "Memcached",
                "protocol": "Tcp",
                "destination_port_range": "11211",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "MSSQL": [
            {
                "name": "MSSQL",
                "protocol": "Tcp",
                "destination_port_range": "1433",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "MySQL": [
            {
                "name": "MySQL",
                "protocol": "Tcp",
                "destination_port_range": "3306",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "Neo4J": [
            {
                "name": "Neo4J",
                "protocol": "Tcp",
                "destination_port_range": "7474",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "POP3": [
            {
                "name": "POP3",
                "protocol": "Tcp",
                "destination_port_range": "110",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "POP3S": [
            {
                "name": "POP3S",
                "protocol": "Tcp",
                "destination_port_range": "995",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "PostgreSQL": [
            {
                "name": "PostgreSQL",
                "protocol": "Tcp",
                "destination_port_range": "5432",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "RabbitMQ": [
            {
                "name": "RabbitMQ",
                "protocol": "Tcp",
                "destination_port_range": "5672",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "RDP": [
            {
                "name": "RDP",
                "protocol": "Tcp",
                "destination_port_range": "3389",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "Redis": [
            {
                "name": "Redis",
                "protocol": "Tcp",
                "destination_port_range": "6379",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "Riak": [
            {
                "name": "Riak",
                "protocol": "Tcp",
                "destination_port_range": "8093",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "Riak-JMX": [
            {
                "name": "Riak-JMX",
                "protocol": "Tcp",
                "destination_port_range": "8985",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "SMTP": [
            {
                "name": "SMTP",
                "protocol": "Tcp",
                "destination_port_range": "25",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "SMTPS": [
            {
                "name": "SMTPS",
                "protocol": "Tcp",
                "destination_port_range": "465",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "SSH": [
            {
                "name": "SSH",
                "protocol": "Tcp",
                "destination_port_range": "22",
                "access": "Allow",
                "direction": "Inbound"
            }
        ],
        "WinRM": [
            {
                "name": "WinRM",
                "protocol": "Tcp",
                "destination_port_range": "5986",
                "access": "Allow",
                "direction": "Inbound"
            }
        ]
    }
