import inspect
import sys
from msrest.serialization import (Model)
from msrestazure.tools import (resource_id)
from ..validations import(is_guid, is_none_or_whitespace, ValidationFunction)
from ..validations.utilities import (full_qual_name, unique)
from enum import (Enum)

def convert_string_to_enum(enum_type, value):
    assert inspect.isclass(enum_type) and issubclass(enum_type, Enum), 'enum_type must be a subclass of Enum'
    try:
        return enum_type(value)
    except ValueError as e:
        return None

# This metaclass is so we can inherit our _attribute_map fields.
# Child classes can override fields by specifying them
class ResourceMetaClass(type):
    def __new__(mcs, name, bases, dct):
        seen = set()
        apply = []
        # Go through the base classes and build up our apply ordering
        for base in bases:
            mro = inspect.getmro(base)
            for cls in reversed(mro):
                if not cls in seen:
                    seen.add(cls)
                    apply.append(cls)

        # Let's build up our attribute map and validations! :)
        # Maybe not validations! :|
        attribute_map = {}
        #validation = {}
        for cls in apply:
            attribute_map.update(getattr(cls, '_attribute_map', {}))
            #validation.update(getattr(cls, '_validation', {}))
        # If the class we are creating has an _attribute_map, update our generated attribute map
        # This allows overrides
        attribute_map.update(dct.get('_attribute_map', {}))
        dct['_attribute_map'] = attribute_map
        #validation.update(dct.get('_validation', {}))
        #dct['_validation'] = validation

        cls = super(ResourceMetaClass, mcs).__new__(mcs, name, bases, dct)
        # TODO - Remove this if the dynamic loading and decorator work!
        # # Subclass test!  Make this safer when we know it works. :)
        # # It works, but I'm not a huge fan of the 'BuildingBlock' string
        # if bases[0].__name__ == 'BuildingBlock':
        #     init_subclass = getattr(bases[0], '__init_subclass__', None)
        #     if init_subclass:
        #         init_subclass(cls)
        return cls

class BuildingBlockModel(Model, metaclass=ResourceMetaClass):
    _attribute_map = {}

    def __init__(self, **kwargs):
        super(BuildingBlockModel, self).__init__(**kwargs)
        # Hide Model's _validation class attribute
        # This requires all subclasses update the _validation dictionary if validations are needed.
        self._validation = {}
        self._validation_messages = {}

    # We need to override this and hope we can hook it here.
    @classmethod
    def _infer_class_models(cls):
        # We need to load the SDK types into the serializer/deserializer so we can minimize our types
        # We will defer to the base implementation to get the main models, then load up the azure ones

        # We may not want to do this because it fails deserialization, rather than throwing a
        # validation error, but it might be safe if we use classes that don't need/have validations (i.e. BgpSettings)
        class_models = super()._infer_class_models()
        azure_sdk_models_module = sys.modules.get('azure.mgmt.network.models', None)
        if azure_sdk_models_module:
            #models = {full_qual_name(v): v for k, v in azure_sdk_models_module.__dict__.items() if isinstance(v, type)}
            # We will use the azure_sdk_models_module.__name__ property instead of full_qual_name().  This will allow
            # the versions of the sdk models to update to the latest without changing code.
            models = {".".join((azure_sdk_models_module.__name__, v.__qualname__)): v for k, v in azure_sdk_models_module.__dict__.items() if isinstance(v, type)}
            class_models.update(models)
        return class_models

    def serialize(self, keep_readonly=False):
        """Return the JSON that would be sent to azure from this model.

        This is an alias to `as_dict(full_restapi_key_transformer, keep_readonly=False)`.

        :param bool keep_readonly: If you want to serialize the readonly attributes
        :returns: A dict JSON compatible object
        :rtype: dict
        """
        # serializer = Serializer(self._infer_class_models())
        # return serializer._serialize(self, keep_readonly=keep_readonly)
        return super(BuildingBlockModel, self).serialize(keep_readonly=True)

class Resource(BuildingBlockModel):
    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'}
    }

    def __init__(self, name=None, **kwargs):
        super(Resource, self).__init__(**kwargs)
        self.name = name
        self._validation.update({
            'name': {'required': True}
        })

class ResourceObject(BuildingBlockModel):
    _attribute_map = {}

    def __init__(self, name=None, **kwargs):
        super(ResourceObject, self).__init__(**kwargs)

# This decorator will replace the __init__ method of a Resource AND TopLevelResource subclass and generate the id attribute automatically
class ResourceId(object):
    def __init__(self, namespace=None, type=None):
        assert not inspect.isclass(namespace), "Parameters must be provided"
        assert namespace is not None, "namespace must be provided"
        assert type is not None, "type must be provided"
        self.namespace = namespace
        self.type = type
    def __call__(self_dec, cls): # pylint: disable=E0213
        if not (issubclass(cls, TopLevelResource) and issubclass(cls, Resource)):
            raise TypeError('@ResourceId can only be used on classes descended from both Resource and TopLevelResource')
        old_init = cls.__init__

        # Make sure we can serialize the id!
        cls._attribute_map.update({
            'id': {'key': 'id', 'type': 'str'}
        })

        def new_init(self, *args, **kwargs):
            # We have to call old_init first so the name is populated
            old_init(self, *args, **kwargs)
            # Add our resource id. MAGIC! :)
            self.id = resource_id(
                subscription=self.subscription_id,
                resource_group=self.resource_group_name,
                namespace=self_dec.namespace,
                type=self_dec.type,
                name=self.name)
            self._validation.update({
                'id': {'required': False}
            })

        cls.__init__ = new_init
        return cls

class TaggedResource(BuildingBlockModel):
    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'}
    }

    def __init__(self, tags=None, **kwargs):
        super(TaggedResource, self).__init__(**kwargs)
        self.tags = tags if tags else {}
        self._validation.update({
            'tags': {'required': True, 'custom': self._validate_tags}
        })

    @ValidationFunction()
    def _validate_tags(self, value):
        if len(value) > 15:
            return False, "Only 15 tags are allowed"
        if not all(1 <= len(k) <= 512 for k, v in value.items()):
            return False, "Tag names must be between 1 and 512 characters in length"
        if not all(not is_none_or_whitespace(v) and 1 <= len(v) <= 256 for k, v in value.items()):
            return False, "Tag values cannot be null, empty, only whitespace, or greater than 256 characters in length"
        return True

class TopLevelResource(BuildingBlockModel):
    _attribute_map = {
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'}
    }

    def __init__(self, subscription_id=None, resource_group_name=None, location=None, **kwargs):
        super(TopLevelResource, self).__init__(**kwargs)
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        self.location = location
        self._validation.update({
            'subscription_id': {'required': True, 'custom': is_guid},
            'resource_group_name': {'required': True, 'pattern': '^[-\\w\\._\\(\\)]{0,89}[-\\w_\\(\\)]$'},
            'location': {'required': True}
        })

class ResourceReference(Resource, TopLevelResource):
    def __init__(self, **kwargs):
        super(ResourceReference, self).__init__(**kwargs)

def extract_resource_groups(*args):
    class EqualityProxy(object):
        def __init__(self, obj):
            super(EqualityProxy, self).__init__()
            self.wrapped = obj

        def __getattr__(self, name):
            return getattr(self.wrapped, name)

        def __eq__(self, other):
            """Overrides the default implementation"""
            if isinstance(self, other.__class__) and isinstance(self.wrapped, other.wrapped.__class__):
                return self.wrapped.__dict__ == other.wrapped.__dict__
            return NotImplemented

        def __ne__(self, other):
            """Overrides the default implementation (unnecessary in Python 3)"""
            x = self.__eq__(other)
            if x is not NotImplemented:
                return not x
            return NotImplemented

        def __hash__(self):
            """Overrides the default implementation"""
            return hash(tuple(sorted(self.wrapped.__dict__.items())))

    resource_groups = [
        EqualityProxy(TopLevelResource(subscription_id=top_level_resource.subscription_id,
                         resource_group_name=top_level_resource.resource_group_name,
                         location=top_level_resource.location
                        )) for top_level_list in args for top_level_resource in top_level_list]
    return [proxy.wrapped for proxy in unique(resource_groups)]

# This likely needs to become a "registry" so we don't have to do this every, single time.
# But, for now, we'll see if we can remove OUR sdk model wrappers. :)
def wrap_sdk_model(sdk_model, attribute_map=None, *args, **kwargs):
    # We need to do a couple of housekeeping things here.
    # First, we need to pop all of the kwargs that are in our attribute_map so they
    # don't get passed to the SDK models.
    attribute_map = dict(attribute_map if attribute_map else {})
    additional_properties = {k: kwargs.pop(k, None) for k in attribute_map.keys() }
    # Secondly, we need to find all kwargs that are readonly in the SDK model
    # and use setattr to put them on the model.  This is because there is usually
    # not a way to pass them into the __init__ method of the model.  The SDK
    # serialization does the same thing, but they only use readonly fields for the GET
    # operations.
    for attr_name in [k for k, v in sdk_model._validation.items() if v.get('readonly') and k in kwargs.keys()]:
        additional_properties[attr_name] = kwargs.pop(attr_name, None)
    attribute_map.update(sdk_model._attribute_map)
    model = sdk_model(*args, **kwargs)
    model._attribute_map = attribute_map
    for k, v in additional_properties.items():
        setattr(model, k, v)
    return model