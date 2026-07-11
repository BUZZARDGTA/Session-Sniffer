"""The module provides functionality for performing reverse DNS lookups.

It includes a function `reverse_dns_lookup` which resolves hostnames from IP addresses.
"""

import threading
from typing import TYPE_CHECKING

import dns.exception
import dns.resolver
import dns.reversename

if TYPE_CHECKING:
    from collections.abc import Callable

    from dns.resolver import Resolver


def _init_smart_resolver() -> Resolver:
    """Perform a network check and return the optimal DNS resolver."""
    public_resolver = dns.resolver.Resolver(configure=False)
    public_resolver.nameservers = ['1.1.1.1', '8.8.8.8']

    try:
        # Test if public DNS is blocked in the user's country
        public_resolver.resolve(dns.reversename.from_address('1.1.1.1'), 'PTR')
    except dns.exception.DNSException:
        # Fallback to the local ISP resolver
        return dns.resolver.Resolver()

    return public_resolver


def _build_resolver_cache() -> tuple[Callable[[], Resolver], Callable[[], None]]:
    """Build a thread-safe DNS resolver cache using a closure to avoid global state."""
    instance: Resolver | None = None
    lock = threading.Lock()

    def get_resolver() -> Resolver:
        nonlocal instance

        # 1. Fast check outside the lock
        if instance is not None:
            return instance

        # 2. Safe check inside the lock
        with lock:
            if instance is not None:
                return instance

            instance = _init_smart_resolver()
            return instance

    def reset_resolver() -> None:
        """Clear the cached resolver, forcing a network check on the next lookup."""
        nonlocal instance
        with lock:
            instance = None

    return get_resolver, reset_resolver


# Expose the initialized functions to the module
_get_resolver, reset_resolver_cache = _build_resolver_cache()


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
        answer = _get_resolver().resolve(rev_name, 'PTR')
    except dns.exception.DNSException:
        return target_ip

    ptr_record = next(iter(answer), None)
    if not ptr_record:
        return target_ip

    hostname = str(ptr_record).rstrip('.')
    if not hostname:
        return target_ip

    return hostname
