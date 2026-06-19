"""The module provides functionality for performing reverse DNS lookups.

It includes a function `reverse_dns_lookup` which resolves hostnames from IP addresses.
"""

import dns.exception
import dns.resolver
import dns.reversename

_resolver = dns.resolver.Resolver()
_resolver.lifetime = 5.0


def reverse_dns_lookup(target_ip: str) -> str:
    """Perform a reverse DNS lookup for the given IP address.

    If a hostname is found, it returns the hostname. If no valid hostname
    is found or an error occurs during lookup, it returns the original IP address.

    Args:
        target_ip: The IP address to look up.

    Returns:
        The resolved hostname, or the original IP address if no valid hostname is found.
    """
    rev_name = dns.reversename.from_address(target_ip)

    try:
        answer = _resolver.resolve(rev_name, 'PTR')
    except dns.exception.DNSException:
        return target_ip

    ptr_record = next(iter(answer), None)
    if not ptr_record:
        return target_ip

    hostname = str(ptr_record).rstrip('.')
    if not hostname:
        return target_ip

    return hostname
