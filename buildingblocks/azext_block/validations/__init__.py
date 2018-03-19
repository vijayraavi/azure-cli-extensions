#import re
import uuid
from .validation_function import (ValidationFunction)
from .building_block_validation_error import (BuildingBlockValidationError, patch_validation)
from .networking import (is_valid_cidr, is_valid_ip_address, is_valid_port_range)
__all__ = [
    'is_valid_cidr',
    'is_guid',
    'is_valid_ip_address',
    'is_valid_port_range',
    'patch_validation',
    'BuildingBlockValidationError',
    'ValidationFunction'
]
# Validation regular expressions
# We are going to wrap these in a ValidationFunction since the pattern error message isn't that readable.
#_guid_reg_ex = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
#_is_guid = re.compile(_guid_reg_ex, re.UNICODE)

#@ValidationFunction("is not a valid GUID")
#def is_guid(value):
#    return _is_guid.match(value) != None

@ValidationFunction("is not a valid GUID")
def is_guid(value):
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False

@ValidationFunction("cannot be None, empty, or only whitespace")
def is_none_or_whitespace(value):
    return value is None or value.strip() == ''
