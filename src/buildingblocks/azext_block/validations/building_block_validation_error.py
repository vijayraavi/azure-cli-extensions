from collections import (MutableMapping)
from contextlib import (contextmanager)
import inspect
from msrest.exceptions import (ValidationError)
from msrest.serialization import (Serializer)
from .utilities import (full_qual_name)

@contextmanager
def patch_validation():
    old_validation_error_new = ValidationError.__new__
    try:
        ValidationError.__new__ = lambda cls, rule, target, value, *args, **kwargs: super(ValidationError, BuildingBlockValidationError).__new__(
            BuildingBlockValidationError, rule, target, value, *args, **kwargs)
        # We are negating the result because the msrest serialization engine is backwards. :)
        Serializer.validation['custom'] = lambda x, y: not y(x)
        yield
    finally:
        ValidationError.__new__ = old_validation_error_new
        # We'll be safe and not throw the error in case something happened to our key
        try:
            del Serializer.validation['custom']
        except KeyError:
            pass

class BuildingBlockValidationError(ValidationError):
    # We need this to hold the "registered" non-instance validation messages.  The instance lookup will
    # use this as part of it's lookup traversal.
    _messages = {}

    def __init__(self, rule, target, value, *args, **kwargs):
        # We need to hijack the ValidationError here, so it's a little funky. :)
        # If rule is "custom", that means we are using OUR stuff, so we need to
        # figure out how to get the error messages in there.
        # value is ALWAYS a function/method in this case.
        # If value.__self__ is a class, that means the error message should be in THIS
        # class' _message table (We need to build a validation function registry...DONE!)
        #
        # If value.__self__ is an instance of Model, that means we need to get the
        # error message from the instance's _validation_messages dictionary, and
        # assign self._messages with the custom error (This is so multiple instances can return different errors)
        #
        # If value is a raw function, it should work like the class method (figure this out!)
        self._messages = _LookupDict()
        if rule == 'custom':
            if not callable(value):
                # THe validation dictionary has a non-callable value assigned to custom
                raise TypeError("{} has a non-callable custom validation".format(target))
            # Change to the REAL rule name :)
            rule = full_qual_name(value)
            value_self = getattr(value, '__self__', None)
            if value_self and not inspect.isclass(value_self):
                # We are an instance method, so get our message from the object instance
                message = getattr(value_self, '_validation_messages', {}).get(rule, None)
                if message:
                    self._messages.update({rule: message})
        super(BuildingBlockValidationError, self).__init__(rule, target, value, *args, **kwargs)

class _LookupDict(MutableMapping):
    def __init__(self, *args, **kwargs):
        self.store = dict()
        self.update(dict(*args, **kwargs))  # use the free update to set keys

    def __getitem__(self, key):
        # We are going to look in ourself first, then BuildingBlockValidationError, and finally ValidationError.
        # This should let us get the error message lookup correct without copying messages every time
        # If we can't find the key, raise KeyError so the Mapping.get() stuff can do the right thing
        return self.store[key] if key in self.store else BuildingBlockValidationError._messages[key] if key in BuildingBlockValidationError._messages else ValidationError._messages[key]

    def __setitem__(self, key, value):
        self.store[key] = value

    def __delitem__(self, key):
        del self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)
