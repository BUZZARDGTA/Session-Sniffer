"""The module provides functionality for performing reverse DNS lookups.

It includes a function `lookup` which resolves hostnames from IP addresses.
"""
import dns.resolver
import dns.reversename

NAMESERVERS = ['1.1.1.1', '1.0.0.1']

resolver = dns.resolver.Resolver()
resolver.nameservers = NAMESERVERS


def lookup(target_ip: str) -> str:
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
        answer = resolver.resolve(rev_name, 'PTR')
    except (dns.resolver.LifetimeTimeout, dns.resolver.NXDOMAIN, dns.resolver.YXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return target_ip

    ptr_record = next(iter(answer), None)
    if not ptr_record:
        return target_ip

    hostname = str(ptr_record).rstrip('.')
    if not hostname:
        return target_ip

    return hostname
