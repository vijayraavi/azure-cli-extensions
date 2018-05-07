# TODO: Create default auto scale setting profiles

# Virtual machine model imports
from azure.mgmt.compute.models import (VirtualMachine as VirtualMachineSdk, 
    AvailabilitySet as AvailabilitySetSdk, 
    VirtualMachineScaleSet as VirtualMachineScaleSetSdk,
    VirtualMachineScaleSetSkuScaleType,
    OSDisk as OSDiskSdk,
    ImageReference as ImageReferenceSdk,
    DataDisk as DataDiskSdk,
    VirtualMachineSizeTypes,
    OperatingSystemTypes)

# Autoscale settings
from azure.mgmt.monitor.models import (
    AutoscaleProfile as AutoScaleProfileSdk,
    ScaleCapacity as ScaleCapacitySdk,
    ScaleRule as ScaleRuleSdk,
    MetricTrigger as MetricTriggerSdk,
    ScaleAction as ScaleActionSdk
)

# Local model imports
from .application_gateway import (ApplicationGateway)
from .load_balancer import (LoadBalancer)
# Building block imports
from .building_block_settings import (BuildingBlock, RegisterBuildingBlock)
# Resource imports
from .resources import (Resource, ResourceId, ResourceReference, TaggedResource, TopLevelResource, extract_resource_groups)
# Validation imports
from ..validations.networking import (is_valid_cidr)
from ..validations.virtual_machine import (is_valid_sku)
from enum import Enum
from .public_ip_address import (PublicIPAddress)
from .network_interface import (NetworkInterface)

# Register building block
@RegisterBuildingBlock(name='VirtualMachine', template_url='buildingBlocks/virtualMachines/virtualMachines.json', deployment_name='vm')
class VirtualMachineBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[VirtualMachine]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(VirtualMachineBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    def transform(self):
        storage_accounts = []
        diagnostic_storage_accounts = []
        load_balancers = []
        scale_sets = []
        auto_scale_settings = []
        secrets = []

        virtual_machines = [vm.transform() for vm in self.settings]
        network_interfaces = [nic.transform() for nic in virtual_machines for nic in self.settings.nics]
        availability_set = [availability_set.transform() for availability_set in virtual_machines.availability_set]
        application_gateways = [application_gateway.transform() for application_gateway in virtual_machines.application_gateway_settings]

        public_ip_addresses = get_ip_addresses(self.settings.nics)

        resource_groups = extract_resource_groups(virtual_machines)
        template_parameters = {
            "virtualMachines": virtual_machines,
            "publicIpAddresses": public_ip_addresses,
            "networkInterfaces": network_interfaces,
            "storageAccounts": storage_accounts,
            "diagnosticStorageAccounts": diagnostic_storage_accounts,
            "availabilitySet": availability_set,
            "loadBalancers": load_balancers,
            "scaleSets": scale_sets,
            "autoScaleSettings": auto_scale_settings,
            "applicationGateways": application_gateways,
            "secrets": secrets 
        }
        return resource_groups, template_parameters
    def get_ip_addresses(self,network_interfaces):

        nics = [nic for nic in network_interfaces if network_interface.is_public == True]
        for nic in nics:
            public_ip_address_parameters = {
                'subscription_id': self.subscription_id,
                'resource_group_name': self.resource_group_name,
                'location': self.location,
                'name': "{}-{}-pip".format(nic.virtual_machine.name,  nic.name),
                'public_ip_allocation_method': 'Dynamic',
                'public_ip_address_version': "IPv4",
                'idle_timeout_in_minutes': None,
                'zones': None,
                'domain_name_label': None
            }

            public_ip_address = PublicIPAddress(**public_ip_address_parameters)
            public_ip_addresses.append(public_ip_address.transform())
        
        return public_ip_addresses

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(VirtualMachineSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}#
        })

@ResourceId(namespace="Microsoft.Compute", type="virtualMachines")
class VirtualMachine(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'vm_count': {'key': 'vmCount', 'type': 'int'},
        'name_prefix': {'key': 'namePrefix', 'type':'str'},
        'computer_name_prefix': {'key': 'computerNamePrefix', 'type': 'str'},
        'size': {'key': 'size', 'type':'str'},
        'os_type':{'key': 'osType', 'type':'str'},
        'image_reference': {'key': 'imageReference', 'type': 'ImageReference'},
        'admin_username': {'key': 'adminUsername', 'type': 'str'},
        'admin_password': {'key': 'adminPassword', 'type': 'str'},
        'ssh_public_key': {'key': 'sshPublicKey', 'type': 'str'},
        'nics': {'key': 'nics', 'type': '[NetworkInterface]'},
        'os_disk': {'key': 'osDisk', 'type': 'OSDisk'},
        'data_disk': {'key': 'dataDisk', 'type':'DataDisk'},
        'availability_set': {'key': 'availabilitySet', 'type': 'AvailabilitySet'},
        'diagnostic_storage_accounts': {'key': 'diagnosticStorageAccounts', 'type': '[DiagnosticStorageAccount]'},
        'storage_accounts': {'key': 'storageAccounts','type': '[StorageAccount]'},
        'scale_set_settings': {'key': 'scaleSetSettings', 'type':'ScaleSetSettings', 'parent': 'virtual_machine'},
        'load_balancer_settings': {'key': 'loadBalancerSettings', 'type': 'LoadBalancer'},
        'application_gateway_settings': {'key': 'applicationGatewaySettings','type': 'ApplicationGateway'}
    }

    _valid_os_types = frozenset([e.value for e in OperatingSystemTypes])
    _valid_sizes = frozenset([e.value for e in VirtualMachineSizeTypes])

    def __init__(self, vm_count=None, name_prefix=None, computer_name_prefix=None,size=None,os_type=None,image_reference=None,admin_username=None,admin_password=None,ssh_public_key=None, nics=None,os_disc=None,data_disks=None,availability_sets=None,diagnostic_storage_accounts=None,storage_accounts=None,scale_set_settings=None,load_balancer_settings=None,application_gateway_settings=None, **kwargs):
        super(VirtualMachine, self).__init__(**kwargs)
        self.vm_count = vm_count if vm_count else 1
        self.name_prefix = name_prefix
        self.computer_name_prefix = computer_name_prefix
        self.size = size if size else 'Standard_DS2_v2'
        self.os_type = os_type if os_type else None
        self.image_reference = image_reference if image_reference else None
        self.admin_username = admin_username if admin_username else None
        self.admin_password = admin_password if admin_password else None
        self.ssh_public_key = ssh_public_key if ssh_public_key else None
        self.nics = nics if nics else None
        self.os_disc = os_disc if os_disc else None
        self.data_disks = data_disks if data_disks else None
        self.availability_sets = availability_sets if availability_sets else None
        self.diagnostic_storage_accounts = diagnostic_storage_accounts if diagnostic_storage_accounts else None
        self.storage_accounts = storage_accounts if storage_accounts else None
        self.scale_set_settings = scale_set_settings if scale_set_settings else None
        self.load_balancer_settings = load_balancer_settings if load_balancer_settings else None
        self.application_gateway_settings = application_gateway_settings if application_gateway_settings else None

        self._validation.update({
            'name_prefix': {'required': True},
            'os_type': {'required': True, 'custom': VirtualMachine.is_valid_os_type},
            'size': {'required': True, 'custom': VirtualMachine.is_valid_size},
            'admin_username': {'required': True},
            'nics': {'required': True, 'min_items': 1}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(VirtualMachineSdk)
        model = factory(
            id=self.id, # pylint: disable=no-member
            name=self.name,
            subscription_id=self.subscription_id,
            resource_group_name=self.resource_group_name,
            tags=self.tags
        )

        return model

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_os_types)))
    def is_valid_os_type(self, value):
        if value in self._valid_os_types:
            return True
        else:
            return False

    @ValidationFunction('Value must be one of the following values: {}'.format(','.join(_valid_sizes)))
    def is_valid_size(self, value):
        if value in self._valid_sizes:
            return True
        else: 
            return False

class ImageReference():
    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
        'offer': {'key': 'offer', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'}
    }

    def __init__(self, id=None, publisher=None, offer=None, sku=None, version=None, **kwargs):
        super(ImageReference, self).__init__(**kwargs)
        self.id = id if id else None
        self.publisher = publisher if publisher else None
        self.offer = offer if offer else None
        self.sku = sku if sku else None
        self.version = version if version else 'latest'
        self._validation.update({
            'id': {'required': True},
            'publisher': {'required': True},
            'offer': {'required': True},
            'sku': {'required': True},
            'version': {'required': True}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(ImageReferenceSdk)
        model = factory(
            id = self.id,
            publisher = self.publisher,
            offer = self.offer,
            sku = self.sku,
            version = self.version
        )

        return model

class NetworkInterface():
    _attribute_map = {
        'is_public': {'key': 'isPublic', 'type': 'bool'},
        'subnet_name': {'key': 'subnetName', 'type': 'str'},
        'private_ip_allocation_method': {'key': 'privateIPAllocationMethod', 'type': 'str'},
        'private_ip_address_version': {'key': 'privateIPAllocationMethod', 'type': 'str'},
        'public_ip_allocation_method': {'key': 'privateIPAllocationMethod', 'type': 'str'},
        'starting_ip_address': {'key': 'startingIPAddress', 'type': 'str'},
        'enable_ip_forwarding': {'key': 'enableIPForwarding', 'type': 'bool'},
        'dns_servers': {'key': 'dnsServers', 'type': '[str]'},
        'is_primary': {'key': 'isPrimary', 'type': 'bool'},
        'domain_name_label_prefix': {'key': 'domainNameLabelPrefix', 'type': 'str'},
        'backend_pool_names': {'key': 'backendPoolNames', 'type': '[str]'},
        'inbound_nat_rules_names': {'key': 'inboundNatRulesNames', 'type': '[str]'}
    }

    def __init__(self, is_public=None, subnet_name=None, private_ip_allocation_method=None, private_ip_allocation_method=None,public_ip_allocation_method=None,starting_ip_address=None, enable_ip_forwarding=None,dns_servers=None,is_primary=None,domain_name_label_prefix=None,backend_pool_names=None,inbound_nat_rules_names=None, **kwargs):
        super(NetworkInterface, self).__init__(**kwargs)
        self._validation.update({})

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(NetworkInterfaceSdk)
        model = factory(
            name=self.name
        )

        return model

class OSDisk():
    _attribute_map = {
        'create_option': {'key': 'createOption', 'type': 'str'},
        'caching': {'key': 'caching', 'type': 'str'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'images': {'key': 'images', 'type': '[str]'}
    }

    def __init__(self, create_option=None,caching=None,disk_size_gb=None,images=None, **kwargs):
        super(OSDisk, self).__init__(**kwargs)
        self._validation.update({
            'images': {'required': True, 'min_items': 1}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(OSDiskSdk)
        model = factory(
            name = self.name
        )

        return model

class DataDisk():
    _attribute_map = {
         'count': {'key': 'count', 'type': 'int'},
         'caching': {'key': 'caching', 'type': 'str'},
         'create_option': {'key': 'createOption', 'type': 'str'},
         'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
         'disks': {'key': 'disks', 'type': '[Disk]'}
    }

    def __init__(self, count=None, caching=None, create_option=None, disk_size_gb=None, disks=None, **kwargs):
        super(DataDisk, self).__init__(**kwargs)
        self._validation.update({})

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(DataDiskSdk)
        model = factory(
            name = self.name
        )

        return model

class AvailabilitySet():
    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'platform_fault_domain_count': {'key': 'platformFaultDomainCount', 'type': 'int'},
        'platform_update_domain_count': {'key': 'platformUpdateDomainCount', 'type': 'int'}
    }

    def __init__(self, name=None,platform_fault_domain_count=None, platform_update_domain_count=None, **kwargs):
        super(AvailabilitySet, self).__init__(**kwargs)
        self.platform_fault_domain_count = platform_fault_domain_count if platform_fault_domain_count else 3
        self.platform_update_domain_count = platform_update_domain_count if platform_update_domain_count else 5
        self._validation.update({
            'name': {'required': True},
            'platform_fault_domain_count': {'required': False, 'custom': AvailabilitySet._is_valid_platform_fault_domain_count},
            'platform_update_domain_count': {'required': False, 'custom': AvailabilitySet.is_valid_platform_update_domain_count}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(AvailabilitySetSdk)
        model = factory(
            name = self.name,
            platform_fault_domain_count = self.platform_fault_domain_count,
            platform_update_domain_count = self.platform_update_domain_count
        )

        return model

    @classmethod
    @ValidationFunction('Value must be between 1 and 3')
    def _is_valid_platform_fault_domain_count(self, value):
        if value >= 1 and value <= 3:
            return True
        else:
            return False

    @classmethod
    @ValidationFunction('Value must be between 1 and 20')
    def is_valid_platform_update_domain_count(self, value):
        if value >= 1 and value <= 20:
            return True
        else:
            return False 

class DiagnosticStorageAccount():
    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'name_suffix': {'key': 'nameSuffix', 'type': 'str'},
        'sku_type': {'key': 'skuType', 'type': 'str'},
        'supports_https_traffic_only':{'key': 'supportsHttpsTrafficOnly', 'type': 'bool'},
        'encrypt_blob_storage': {'key': 'encryptBlobStorage', 'type': 'bool'},
        'encrypt_file_storage': {'key': 'encryptFileStorage', 'type': 'bool'},
        'key_vault_properties': {'key': 'keyVaultProperties', 'type': 'KeyVaultProperties'},
        'accounts': {'key': 'accounts', 'type': '[str]'}
    }

    def __init__(self, count=None, name_suffix=None, sku_type=None, supports_https_traffic_only=None, encrypt_blob_storage=None, encrypt_file_storage=None, key_vault_properties=None, accounts=None, **kwargs):
        super(DiagnosticStorageAccount, self).__init__(**kwargs)
        self._validation.update({})

    def transform(self):
        pass
        
class StorageAccount():
    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'managed': {'key': 'managed', 'type': 'bool'},
        'name_suffix': {'key': 'nameSuffix', 'type': 'str'},
        'sku_type': {'key': 'skuType', 'type': 'str'},
        'supports_https_traffic_only':{'key': 'supportsHttpsTrafficOnly', 'type': 'bool'},
        'encrypt_blob_storage': {'key': 'encryptBlobStorage', 'type': 'bool'},
        'encrypt_file_storage': {'key': 'encryptFileStorage', 'type': 'bool'},
        'key_vault_properties': {'key': 'keyVaultProperties', 'type': 'KeyVaultProperties'},
        'accounts': {'key': 'accounts', 'type': '[str]'}
    }

    def __init__(self, count=None, managed=None, name_suffix=None, sku_type=None, supports_https_traffic_only=None, encrypt_blob_storage=None, encrypt_file_storage=None, key_vault_properties=None, accounts=None, **kwargs):
        super(StorageAccount, self).__init__(**kwargs)
        self._validation.update({})

    def transform(self):
        pass

class ScaleSetSettings():
    _attribute_map = {
        'upgrade_policy': {'key': 'updatedPolicy', 'type': 'str'},
        'overprovision': {'key': 'overprovision', 'type': 'bool'},
        'single_placement_group': {'key': 'singlePlacementGroup', 'type': 'bool'},
        'auto_scale_settings': {'key': 'autoscaleSettings', 'type': '[AutoScaleSetting]'}   
    }

    def __init__(self, upgrade_policy=None, overprovision=None, single_placement_group=None, **kwargs):
        super(ScaleSetSettings, self).__init__(**kwargs)
        self.upgrade_policy = upgrade_policy if upgrade_policy else 'Automatic'
        self.overprovision = overprovision if overprovision else True
        self.single_placement_group = single_placement_group if single_placement_group else True
        self._validation.update({
            'upgrade_policy': {'required': True, 'custom': ScaleSetSettings.is_valid_upgrade_policy},
            'overprovision': {'required': True},
            'single_placement_group': {'required': True}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(VirtualMachineScaleSetSdk)
        
        model = factory(
            upgrade_policy = self.upgrade_policy,
            overprovision = self.overprovision,
            single_placement_group = self.single_placement_group,
            #sku = # TODO,
            #virtual_machine_profile= #TODO
        )

        return model

    @classmethod
    @ValidationFunction('Value must be set to Automatic or Manual')
    def is_valid_upgrade_policy(self, value):
        if value == "Automatic" or value == "Manual":
            return True
        else:
            return False

class Disk():
    _attribute_map = {
        'caching': {'key': 'caching', 'type': 'str'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'create_option': {'key': 'createOption', 'type': 'str'},
        'images': {'key': 'images', 'type': '[str]'}
    }

    def __init__(self, caching=None, disk_size_gb=None, create_option=None, images=None, **kwargs):
        super(Disk, self).__init__(**kwargs)
        self._validation.update({
            'caching': {'required': True},
            'disk_size_gb': {'required': True},
            'create_option': {'required': True},
            'images': {'required': True, 'min_items': 1}
        })

    def transform(self):

class KeyVaultProperties():
    _attribute_map = {
        'key_name': {'key': 'keyName', 'type': 'str'},
        'key_version': {'key', 'keyVersion', 'type': 'str'},
        'key_vault_uri': {'key': 'keyVaultUri', 'type': 'str'}
    }

    def __init__(self, key_name=None, key_version=None, key_vault_uri=None, **kwargs):
        super(KeyVaultProperties, self).__init__(**kwargs)
        self._validation.update({
            'key_name': {'required': True},
            'key_version': {'required': True}
        })

    def transform(self):
        pass

class AutoScaleSetting():
    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'profiles': {'key': 'profiles', 'type': '[AutoscaleProfileSdk]'}
    }

    def __init__(self, enabled=None, profiles=None, **kwargs):
        super(AutoScaleSetting, self).__init__(**kwargs)
        
    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(AutoScaleProfileSdk)

        model = factory(
            enabled = self.enabled,
            profiles = self.profiles
        )

        return model