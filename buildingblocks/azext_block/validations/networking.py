from .validation_function import (ValidationFunction)
from ipaddress import (ip_address, ip_network)

@ValidationFunction('is not a valid IP Address')
def is_valid_ip_address(value):
    try:
        ip_address(value)
    except ValueError:
        return False
    else:
        return True

@ValidationFunction('is not a valid CIDR')
def is_valid_cidr(value):
    try:
        cidr = ip_network(value)
    except ValueError:
        return False
    else:
        # If the prefixlen is equal to the max_prefixlen, this is just an IP address, so it is invalid as a CIDR.
        return cidr.prefixlen < cidr.max_prefixlen

@ValidationFunction('is not a valid port range')
def is_valid_port_range(value):
    def _is_valid_port(value):
        return 1 <= value <= 65535
    try:
        if value is None:
            return False
        elif value == "*":
            return True
        elif "-" in value:
            # The only other valid option is a range, so we'll assume that is what value is.
            # If not, this will raise a ValueError
            start, end = map(int, value.split('-'))
            return start < end and _is_valid_port(start) and _is_valid_port(end)
        else:
            return _is_valid_port(int(value))
    except ValueError:
        return False
