import copy
import json

from azure.mgmt.compute.models import (VirtualMachineExtension as VirtualMachineExtensionSdk)

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

@RegisterBuildingBlock(name='VirtualMachineExtension', template_url='buildingBlocks/virtualMachineExtensions/virtualMachineExtensions.json', deployment_name='vmext')
class VirtualMachineExtensionBuildingBlock(BuildingBlock):
    _attribute_map = {
        'settings': {'key': 'settings', 'type': '[VirtualMachineExtension]'}
    }

    def __init__(self, settings=None, **kwargs):
        super(VirtualMachineExtensionBuildingBlock, self).__init__(**kwargs)
        self.settings = settings if settings else []

    def transform(self):
        virtual_machine_extensions = [extensions.transform() for extensions in self.settings]

        virtual_machine_extensions_list = []
        extensionsProtectedSettings = []
        for vme_set in virtual_machine_extensions:
            for vme in vme_set:
                virtual_machine_extensions_list.append(vme)

                try:
                    if len(vme.protected_settings):
                        if 'reference' in vme.protected_settings:
                            if 'keyVault' not in vme.protected_settings['reference']:
                                vme.protected_settings._attribute_map = {}
                                extensionsProtectedSettings.append(json.dumps(vme.protected_settings, separators=(',',':')))
                            else:
                                vme.protected_settings._attribute_map = {}
                                extensionsProtectedSettings.append(vme.protected_settings)
                        else:
                            vme.protected_settings._attribute_map = {}
                            extensionsProtectedSettings.append(json.dumps(vme.protected_settings, separators=(',',':')))
                except Exception as e:
                    print(e)
        
        resource_groups = extract_resource_groups(virtual_machine_extensions_list)
        template_parameters = {
            'extensions': virtual_machine_extensions_list,
            'extensionsProtectedSettings': extensionsProtectedSettings
        }
        return resource_groups, template_parameters

    @classmethod
    def onregister(cls):
        cls.register_sdk_model(VirtualMachineExtensionSdk, {
            'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
            'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'}
        })

@ResourceId(namespace='Microsoft.Compute', type='virtualMachineExtensions')
class VirtualMachineExtension(TaggedResource, TopLevelResource, Resource):
    _attribute_map = {
        'vms' : {'key': 'vms', 'type': '[str]'},
        'extensions': {'key': 'extensions', 'type': '[Extension]'}
    }
    
    # , 'parent': 'virtualMachineExtension'}
    def __init__(self, vms=None, extensions=None, **kwargs):
        super(VirtualMachineExtension, self).__init__(**kwargs)
        self.vms = vms
        self.extensions = extensions
        self._validation.update({
            'vms': {'required': True, 'min_items': 1},
            'extensions': {'required': True, 'min_items': 1}
        })

    def transform(self):
        virtual_machine_extensions = []
        for vm in self.vms:
            for extension in self.extensions:
                """
                model = copy.deepcopy(extension)
                model.name = vm + '/' + model.name
                model.id=self.id
                model.subscription_id=self.subscription_id
                model.resource_group_name=self.resource_group_name
                model.location=self.location
                """
                factory = VirtualMachineExtensionBuildingBlock.get_sdk_model(VirtualMachineExtensionSdk)

                model = factory(
                    id=self.id, # pylint: disable=no-member
                    name=vm + '/' + extension.name,
                    subscription_id=self.subscription_id,
                    resource_group_name=self.resource_group_name,
                    location=self.location,
                    publisher=extension.publisher,
                    type=extension.virtual_machine_extension_type,
                    auto_upgrade_minor_version=extension.auto_upgrade_minor_version,
                    settings=extension.settings,
                    protected_settings=extension.protected_settings
                )

                # try:
                #     if len(model.protected_settings):
                #         if 'reference' in model.protected_settings:
                #             if 'keyVault' not in model.protected_settings['reference']:
                #                 model.protected_settings = json.dumps(model.protected_settings, separators=(',',':'))
                #             #else:
                #             #   model.protected_settings = json.dumps(model.protected_settings, separators=(',',':'))
                #         else:
                #             model.protected_settings = json.dumps(model.protected_settings, separators=(',',':'))
                # except Exception as e:
                #     print(e)
                
                virtual_machine_extensions.append(model)

        return virtual_machine_extensions

class Extension(Resource):
    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
        'virtual_machine_extension_type': {'key': 'type', 'type': 'str'},
        'type_handler_version': {'key': 'typeHandlerVersion', 'type': 'str'},
        'auto_upgrade_minor_version': {'key': 'autoUpgradeMinorVersion', 'type': 'bool'},
        'settings': {'key': 'settings', 'type': 'object'},
        'protected_settings': {'key': 'protectedSettings', 'type': 'object'}
    }

    def __init___(self, name=None, publisher=None, _type=None, type_handler_version=None, auto_upgrade_minor_version=None, settings=None, protected_settings=None, **kwargs):
        super(Extension, self).__init__(**kwargs)
        self.name = name
        self.publisher = publisher
        self.virtual_machine_extension_type = _type
        self.type_handler_version = type_handler_version
        self.auto_upgrade_minor_version = auto_upgrade_minor_version
        self.settings = settings if settings else None
        self.protected_settings = protected_settings if protected_settings else None

        self._validation.update({
            'name': {'required': False},
            'publisher': {'required': True},
            'virtual_machine_extension_type': {'required': True},
            'type_hander_version': {'required': True},
            'auto_upgrade_minor_version': {'required': True}
        })

    def transform(self):
        factory = VirtualMachineExtensionBuildingBlock.get_sdk_model(VirtualMachineExtensionSdk)
        model = factory(
            name=self.name,
            publisher=self.publisher,
            virtual_machine_extension_type=self.virtual_machine_extension_type,
            auto_upgrade_minor_version=self.auto_upgrade_minor_version,
            settings=self.settings,
            protected_settings=self.protected_settings
        )

        return model
