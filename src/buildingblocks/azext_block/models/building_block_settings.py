import inspect
import json
import logging

from msrest.serialization import Deserializer as MSRestDeserializer

from .resources import BuildingBlockModel, TopLevelResource
from ..validations import ValidationFunction

logger = logging.getLogger(name=__name__)

class BuildingBlocksParameterFile(BuildingBlockModel):
    _attribute_map = {
        'schema': {'key': '$schema', 'type': 'str'},
        'content_version': {'key': 'contentVersion', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': 'BuildingBlocksParameters'}
    }

    def __init__(self, schema=None, content_version=None, parameters=None, **kwargs):
        super(BuildingBlocksParameterFile, self).__init__(**kwargs)
        self.schema = schema
        self.content_version = content_version if content_version else '1.0.0.0'
        self.parameters = parameters
        self._validation.update({
            'schema': {'required': False},
            'content_version': {'required': True, 'custom': BuildingBlocksParameterFile.is_valid_content_version},
            'parameters': {'required': True}
        })

    @classmethod
    @ValidationFunction('contentVersion must be 1.0.0.0')
    def is_valid_content_version(cls, value):
        return value == '1.0.0.0'

    @classmethod
    def deserialize(cls, data, subscription_id=None, resource_group_name=None, location=None):
        json_obj = json.loads(data)
        # Set the "parent" information  We will put this in a different place in our json just so we can reparent easily
        # We put this in the JSON directly so we don't have to worry about dealing with the specific types
        # These will get thrown away after deserialization for all models who don't need them.
        subscription_id = subscription_id if subscription_id else json_obj.get('parameters', {}).get('subscriptionId', {}).get('value', None)
        resource_group_name = resource_group_name if resource_group_name else json_obj.get('parameters', {}).get('resourceGroupName', {}).get('value', None)
        location = location if location else json_obj.get('parameters', {}).get('location', {}).get('value', None)
        building_blocks = json_obj.get('parameters', {}).get('buildingBlocks', None)
        assert subscription_id, 'subscriptionId parameter must be provided'
        assert resource_group_name, 'resourceGroupName parameter must be provided'
        assert location, 'location parameter must be provided'
        assert building_blocks, 'buildingBlocks parameter must be provided'
        building_blocks['subscriptionId'] = subscription_id
        building_blocks['resourceGroupName'] = resource_group_name
        building_blocks['location'] = location
        cls._add_deployment_information(building_blocks)
        data = json.dumps(json_obj)

        deserializer = MSRestDeserializer(cls._infer_class_models())
        target_obj = deserializer(cls.__name__, data, content_type="application/json")
        cls._reparent_children(target_obj)
        return target_obj

    @classmethod
    def _add_deployment_information(cls, parent):
        children = [(k, v) for k, v in parent.items() if isinstance(v, (list, set, dict))]
        for key, value in children:
            if isinstance(value, (list, set)):
                # We need to make sure we only do this for dict types
                for child in [c for c in value if isinstance(c, dict)]:
                    if 'subscriptionId' not in child:
                        child['subscriptionId'] = parent.get('subscriptionId', None)
                    if 'resourceGroupName' not in child:
                        child['resourceGroupName'] = parent.get('resourceGroupName', None)
                    if 'location' not in child:
                        child['location'] = parent.get('location', None)
                    BuildingBlocksParameterFile._add_deployment_information(child)
            elif isinstance(value, dict) and key != 'tags' and key != "protectedSettings":
                if 'subscriptionId' not in value:
                    value['subscriptionId'] = parent.get('subscriptionId', None)
                if 'resourceGroupName' not in value:
                    value['resourceGroupName'] = parent.get('resourceGroupName', None)
                if 'location' not in value:
                    value['location'] = parent.get('location', None)
    @classmethod
    def _reparent_children(cls, parent):
        # Go through all attributes that are Models, since we can't reparent basic types. :)
        for attr, value in parent._attribute_map.items():
            obj_attr = getattr(parent, attr)
            if obj_attr:
                if isinstance(obj_attr, (list, set)):
                    for a in obj_attr:
                        # Not very good to check every time, but we'll optimize this later
                        if isinstance(a, BuildingBlockModel):
                            if 'parent' in value:
                                setattr(a, value['parent'], parent)
                            cls._reparent_children(a)
                elif isinstance(obj_attr, BuildingBlockModel):
                    if 'parent' in value:
                        setattr(obj_attr, value['parent'], parent)
                    cls._reparent_children(obj_attr)

class BuildingBlocksParameters(TopLevelResource, BuildingBlockModel):
    _attribute_map = {
        'building_blocks': {'key': 'buildingBlocks.value', 'type': '[BuildingBlock]'}
    }
    
    def __init__(self, building_blocks=None, **kwargs):
        super(BuildingBlocksParameters, self).__init__(**kwargs)
        self.building_blocks = building_blocks if building_blocks else []
        self._validation.update({
            # Override the validations
            'subscription_id': {'required': False},
            'resource_group_name': {'required': False},
            'location': {'required': False},
            'building_blocks': {'required': True, 'min_items': 1}
        })

class SdkModelFactory(object):
    def __init__(self):
        super(SdkModelFactory, self).__init__()
        self.__registry = {}

    def get_sdk_model(self, sdk_model):
        # Either return an SdkModelRegistration, or if not found, the SDK model
        return self.__registry.get(sdk_model, sdk_model)

    def register_model(self, sdk_model, additional_attributes_map):
        # This class will be used to return the method that can create the model
        class SdkModelRegistration(object):
            def __init__(self, sdk_model, attribute_map, additional_attribute_names):
                super(SdkModelRegistration, self).__init__()
                self.sdk_model = sdk_model
                self.attribute_map = attribute_map
                self.additional_attribute_names = additional_attribute_names or []
            def __call__(self, *args, **kwargs):
                additional_attributes = {k: kwargs.pop(k, None) for k in self.additional_attribute_names}
                model = sdk_model(*args, **kwargs)
                model._attribute_map = attribute_map
                for k, v in additional_attributes.items():
                    setattr(model, k, v)
                return model
        # We need to do a couple of housekeeping things here.
        # First, we need to pop all of the kwargs that are in our attribute_map so they
        # don't get passed to the SDK models.
        attribute_map = dict(additional_attributes_map if additional_attributes_map else {})
        additional_attribute_names = list(attribute_map.keys())
        additional_attribute_names.extend([k for k, v in sdk_model._validation.items() if v.get('readonly')])
        attribute_map.update(sdk_model._attribute_map)
        self.__registry[sdk_model] = SdkModelRegistration(sdk_model, attribute_map, additional_attribute_names)

class BuildingBlock(TopLevelResource, BuildingBlockModel):
    __sdk_model_factory = SdkModelFactory()

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'}
    }

    # type is our discriminator, so we need to register all building blocks here
    # We should probably make a method! :)
    _subtype_map = {
        'type': {
        }
    }

    template_url = None

    def __init__(self, **kwargs):
        super(BuildingBlock, self).__init__(**kwargs)
        self._validation.update({
            'type': {'required': True},
            'settings': {'required': True, 'min_items': 1}
        })

    @classmethod
    def register_sdk_model(cls, sdk_model, additional_attributes_map):
        BuildingBlock.__sdk_model_factory.register_model(sdk_model, additional_attributes_map)

    @classmethod
    def onregister(cls):
        pass

    @classmethod
    def get_sdk_model(cls, sdk_model):
        return BuildingBlock.__sdk_model_factory.get_sdk_model(sdk_model)

    @classmethod
    def _register_building_block(cls, name=None, building_block=None):
        assert name is not None, 'name must be provided'
        assert building_block is not None, 'building_block must be provided'
        if name in BuildingBlock._subtype_map['type']:
            raise TypeError("Building block '{}' already registered".format(name))
        BuildingBlock._subtype_map['type'].update({
            name: building_block.__name__
        })
        # Register any models needed
        building_block.onregister()

    @classmethod
    def get_template_url(cls, cli_ctx):
        from six.moves.urllib.parse import urljoin  # pylint: disable=import-error
        from ..block import (BLOCK)
        # We can use the default behavior of urljoin to support relative and absolute urls
        return urljoin(BLOCK.get_template_base_uri(cli_ctx), cls.template_url)

    def transform(self):
        return [], {}

    def process(self, output_base_filename, index, sas_token=None):
        output_filename = "{}-output-{:03d}.json".format(output_base_filename, index)
        deployment_name = "bb-{:03d}".format(index)
        resource_groups, template_parameters = self.transform()
        # Add deployment context
        template_parameters.update({
            'deploymentContext': DeploymentContext(parent_template_unique_string=deployment_name, sas_token=sas_token)
        })
        template_parameters = TemplateParameters(**template_parameters)
        template_parameter_file = TemplateParameterFile(parameters=template_parameters)
        with open(output_filename, "w") as f:
            json.dump(template_parameter_file.serialize(), f)
        return ProcessedBuildingBlock(self,
                                      resource_groups,
                                      output_filename,
                                      deployment_name,
                                      sas_token,
                                      self.subscription_id,
                                      self.resource_group_name,
                                      self.location)

class ProcessedBuildingBlock(object):
    def __init__(self, building_block, resource_groups, template_parameters_file, deployment_name, sas_token, subscription_id, resource_group_name, location):
        super(ProcessedBuildingBlock, self).__init__()
        self.building_block = building_block
        self.resource_groups = resource_groups
        self.template_parameters_file = template_parameters_file
        self.deployment_name = deployment_name
        self.sas_token = sas_token
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.location = location

class RegisterBuildingBlock(object):
    def __init__(self, name=None, template_url=None, deployment_name=None):
        assert not inspect.isclass(name), "Parameters must be provided"
        assert name is not None, "name must be provided"
        assert template_url is not None, "a relative or absolute template url must be provided"
        assert deployment_name is not None, "deployment name must be provided"
        self.name = name
        self.template_url = template_url
        self.deployment_name = deployment_name
    def __call__(self, cls):
        if not issubclass(cls, BuildingBlock):
            raise TypeError('@RegisterBuildingBlock can only be used on classes descended BuildingBlock')
        logger.info("Registering {} building block".format(self.name))
        BuildingBlock._register_building_block(name=self.name, building_block=cls)
        # We don't really need the discriminator anymore unless we want to serialize the building block settings, but we'll put it on as a class attribute for now
        cls.type = self.name
        cls.template_url = self.template_url
        cls.deployment_name = self.deployment_name
        return cls

class TemplateParameterFile(BuildingBlockModel):
    _attribute_map = {
        'schema': {'key': '$schema', 'type': 'str'},
        'content_version': {'key': 'contentVersion', 'type': 'str'},
        "parameters": {"key": "parameters", "type": "TemplateParameters"}
    }

    def __init__(self, parameters=None, **kwargs):
        super(TemplateParameterFile, self).__init__(**kwargs)
        self.schema = "http://schema.management.azure.com/schemas/2015-01-01/deploymentParameters.json#"
        self.content_version = "1.0.0.0"
        self.parameters = parameters if parameters else {}

class TemplateParameter(BuildingBlockModel):
    def __new__(cls, value):
        if cls is TemplateParameter:
            if isinstance(value, (list, set)):
                return super(TemplateParameter, cls).__new__(ArrayTemplateParameter)
            if isinstance(value, (dict, BuildingBlockModel)):
                return super(TemplateParameter, cls).__new__(ObjectTemplateParameters)
        return super(TemplateParameter, cls).__new__(cls, value)

    def __init__(self, value=None, **kwargs):
        super(TemplateParameter, self).__init__(**kwargs)

class ArrayTemplateParameter(TemplateParameter):
    _attribute_map = {
        "value": {"key": "value", "type": "[BuildingBlockModel]"}
    }

    def __init__(self, value=None, **kwargs):
        super(ArrayTemplateParameter, self).__init__(**kwargs)
        self.value = value if value else []

class ObjectTemplateParameters(TemplateParameter):
    _attribute_map = {
        "value": {"key": "value", "type": "BuildingBlockModel"}
    }

    def __init__(self, value=None, **kwargs):
        super(ObjectTemplateParameters, self).__init__(**kwargs)
        self.value = value if value else {}

class DeploymentContext(BuildingBlockModel):
    _attribute_map = {
        "parent_template_unique_string": {"key": "parentTemplateUniqueString", "type": "str"},
        "sas_token": {"key": "sasToken", "type": "str"}
    }

    def __init__(self, parent_template_unique_string=None, sas_token=None, **kwargs):
        super(DeploymentContext, self).__init__(**kwargs)
        self.parent_template_unique_string = parent_template_unique_string
        self.sas_token = sas_token if sas_token else ""

# This class will transform a dict into a set of template parameters
class TemplateParameters(BuildingBlockModel):
    def __init__(self, **kwargs):
        # Wrap the values and pass to Model!
        kwargs = {k: TemplateParameter(value=v) for k, v in kwargs.items()}
        self._attribute_map = {k: {"key": k, "type": "TemplateParameter"} for k in kwargs.keys()}
        super(TemplateParameters, self).__init__(**kwargs)
