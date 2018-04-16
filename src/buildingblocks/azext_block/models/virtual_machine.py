# Virtual machine model imports
from azure.mgmt.compute.models import (VirtualMachine as VirtualMachineSdk, 
    AvailabilitySet as AvailabilitySetSdk, 
    VirtualMachineScaleSet as VirtualMachineScaleSetSdk,
    OSDisk as OSDiskSdk,
    ImageReference as ImageReferenceSdk,
    DataDisk as DataDiskSdk)
# Network model imports
from azure.mgmt.network.models import (NetworkInterface as NetworkInterfaceSdk, IPConfiguration, Subnet as SubnetSdk)
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

# Register building block
@RegisterBuildingBlock(name='VirtualMachine', template_url='buildingBlocks/VirtualMachines/virtualMachines.json', deployment_name='vm')
class VirtualMachineBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[VirtualMachine]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(VirtualMachineBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    def transform(self):
        virtual_machines = []
        resource_groups = extract_resource_groups(virtual_machines)
        template_parameters = {
            "virtualMachines": virtual_machines
        }
        return resource_groups, template_parameters

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
        'scale_set_settings': {'key': 'scaleSetSettings', 'type':'ScaleSetSettings'},
        'load_balancer_settings': {'key': 'loadBalancerSettings', 'type': 'LoadBalancer'},
        'application_gateway_settings': {'key': 'applicationGatewaySettings','type': 'ApplicationGateway'}
    }

    def __init__(self, vm_count=None, name_prefix=None, computer_name_prefix=None,size=None,os_type=None,image_reference=None,admin_username=None,admin_password=None,ssh_public_key=None, nics=None,os_disc=None,data_disks=None,availability_sets=None,diagnostic_storage_accounts=None,storage_accounts=None,scale_set_settings=None,load_balancer_settings=None,application_gateway_settings=None, **kwargs):
        super(VirtualMachine, self).__init__(**kwargs)
        self.vm_count = vm_count if vm_count else 1
        self.name_prefix = name_prefix
        self.computer_name_prefix = computer_name_prefix
        self.size = size if size else 'Standard_DS2_v2'
        self.os_type = os_type if os_type else None

        self._validation.update({
            'name_prefix': {'required': True},
            'os_type': {'required': True, 'custom': is_valid_os_type},
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
        self._validation.update({})

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(ImageReferenceSdk)
        model = factory(
            name=self.name
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
        self._validation.update({
            'name': {'required': True}
        })

    def transform(self):
        factory = VirtualMachineBuildingBlock.get_sdk_model(AvailabilitySetSdk)
        model = factory(
            name = self.name
        )

        return model

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
        super(DiagnosticStorageAccount, self).__iniy(**kwargs)
        self._validation.update({})

    def transform(self):
        
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
        super(StorageAccount, self).__iniy(**kwargs)
        self._validation.update({})

    def transform(self):

class ScaleSetSettings():
    _attribute_map = {
        'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'},
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'upgrade_policy': {'key': 'updatedPolicy', 'type': 'str'},
        'overprovision': {'key': 'overprovision', 'type': 'bool'},
        'single_placement_group': {'key': 'singlePlacementGroup', 'type': 'bool'}

    }

    def __init__(self, resource_group_name=None, subscription_id=None, location=None, upgrade_policy=None, overprovision=None, single_placement_group=None, **kwargs):
        super(ScaleSetSettings, self).__iniy(**kwargs)
        self._validation.update({
            'upgrade_policy': {'required': True},
            'overprovision': {'required': True},
            'single_placement_group': {'required': True}
        })

    def transform(self):

class Disk():
    _attribute_map = {
        'caching': {'key': 'caching', 'type': 'str'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'create_option': {'key': 'createOption', 'type': 'str'},
        'images': {'key': 'images', 'type': '[str]'}
    }

    def __init__(self, caching=None, disk_size_gb=None, create_option=None, images=None, **kwargs):
        super(Disk, self).__iniy(**kwargs)
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
        super(Disk, self).__iniy(**kwargs)
        self._validation.update({
            'key_name': {'required': True},
            'key_version': {'required': True}
        })

    def transform(self):
