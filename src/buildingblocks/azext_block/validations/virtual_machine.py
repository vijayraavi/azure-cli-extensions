from .validation_function import (ValidationFunction)

@ValidationFunction('is not a valid os type')
def is_valid_os_type(value):
    try:
        if value == "linux":
            return True
        elif value == "windows":
            return True
        else:
            return False
    except ValueError:
        return False