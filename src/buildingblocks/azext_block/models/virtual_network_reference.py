from .resources import (ResourceReference)
from ..validations import (is_guid)

class VirtualNetworkReference(ResourceReference):
    _attribute_map = {
        'subnets': {'key': 'subnets', 'type': '[str]'}
    }

    def __init__(self, subnets=None, **kwargs):
        super(VirtualNetworkReference, self).__init__(**kwargs)
        self.subnets = subnets if subnets else []
        self._validation.update({
            'subnets': {'required': True, 'min_items': 1}
        })
