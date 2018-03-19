from functools import (wraps)
import inspect
from .building_block_validation_error import (BuildingBlockValidationError)
from .utilities import (full_qual_name)

# This class will figure out what needs to happen when we call our validation methods.
# For an instance method, __call__ will return a wrapper method that will set the _validation_messages for the qualified method name on the INSTANCE
# For a classmethod, staticmethod, and function, it will take the error message and register the qualified name with OUR validation
# error (to keep from copying messages around)
class ValidationFunction(object):
    def __init__(self, error_message=None):
        # If this is used without parenthesis, error_message will actually be the function.
        # I tried to work around this, but the __call__ gets the value of the attribute we need to check
        # Look into decorators to see if we can fix this.  For now, we'll just assert if error_message is callable
        assert not callable(error_message), 'Usage needs to have parenthesis'
        self.error_message = error_message

    def __call__(self, fn):
        if not callable(fn):
            raise TypeError('Decorator target must be callable')
        # Because of the msrest validation engine, we can have, at MOST, two parameters
        # Two parameters for class and instance methods.  One for static and plain functions
        if len(inspect.signature(fn).parameters) > 2:
            raise TypeError('Decorated validation functions cannot have more than two parameters')

        # We will add all validators to our validation error.  These will get masked by the self._validation_messages for instance methods
        # Just in case a developer forgets to return a tuple from instance validation methods, we'll have a default message that gets
        # registered.  This default can be overridden by passing a message into the decorator
        name = full_qual_name(fn)
        BuildingBlockValidationError._messages[name] = self.error_message if self.error_message else "Default validation error for {}".format(name)

        @wraps(fn)
        # Since this mutates for different callables. :|
        def wrapped(*args, **kwargs):
            # Since __call__ will never get instance methods (they haven't been "bound" yet, since decorators run before class creation is complete),
            # we need to always wrap the callable.  For everything but instance methods, we need to just pass the result of the original.
            # Check the number of arguments.  If it is 1, it's a function or a staticmethod, so the message should have been registered in __call__
            # If there are two arguments, and args[0] is a class, the error message should have been registered in __call__
            # If there are two arguments, and args[0] is an instance of Resource (our base class), we need to destructure the tuple and set the message
            parameter_length = len(inspect.signature(fn).parameters)
            if parameter_length == 1 or inspect.isclass(args[0]):
                return fn(*args, **kwargs)
            else:
                # Just in case the method is not well-behaved. :)
                # Should we just do them all this way?  I'm thinking.....maybe....
                result = fn(*args, **kwargs)
                # We'll convert a single value to a tuple so our code is the same for both!
                result = result if isinstance(result, tuple) else (result,)
                message = result[1] if len(result) > 1 else None
                if message:
                    self = args[0]
                    self._validation_messages[full_qual_name(fn)] = message
                return result[0]
        return wrapped
