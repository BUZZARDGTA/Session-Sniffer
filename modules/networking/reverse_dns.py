"""This module provides functionality for performing reverse DNS lookups.

It includes a function `lookup` which resolves hostnames from IP addresses.
"""

# External/Third-party Python Libraries
import dns.resolver
import dns.reversename


NAMESERVERS = ["1.1.1.1", "1.0.0.1"]

resolver = dns.resolver.Resolver()
resolver.nameservers = NAMESERVERS


def lookup(target_ip: str):
    """Perform a reverse DNS lookup for the given IP address.

    If a hostname is found, it returns the hostname. If no valid hostname
    is found or an error occurs during lookup, it returns the original IP address.

    Args:
        target_ip (str): The IP address to look up.

    Returns:
        str: The resolved hostname, or the original IP address if no valid hostname is found.
    """
    try:
        rev_name = dns.reversename.from_address(target_ip)
        answer = resolver.resolve(rev_name, "PTR")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
        return target_ip

    if answer and answer[0] and (hostname := str(answer[0]).removesuffix(".")):
        return hostname

    return target_ip
