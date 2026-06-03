"""Detection warning tracking systems and GUI detection settings."""

from threading import Lock
from typing import ClassVar


class _DetectionWarnings:
    """Base class for thread-safe IP detection warning tracking."""

    _lock: ClassVar[Lock]
    _notified_ips: ClassVar[set[str]]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        cls._lock = Lock()
        cls._notified_ips = set()

    @classmethod
    def add_notified_ip(cls, ip: str) -> bool:
        """Add an IP to the notified set in a thread-safe manner.

        Args:
            ip: The IP address to add.

        Returns:
            Whether the IP was newly added.
        """
        with cls._lock:
            if ip in cls._notified_ips:
                return False
            cls._notified_ips.add(ip)
            return True

    @classmethod
    def is_ip_notified(cls, ip: str) -> bool:
        """Check if an IP has already been notified.

        Args:
            ip: The IP address to check.

        Returns:
            Whether the IP has been notified.
        """
        with cls._lock:
            return ip in cls._notified_ips

    @classmethod
    def remove_notified_ip(cls, ip: str) -> bool:
        """Remove an IP from the notified set in a thread-safe manner.

        Args:
            ip: The IP address to remove.

        Returns:
            Whether the IP was present and removed.
        """
        with cls._lock:
            if ip in cls._notified_ips:
                cls._notified_ips.discard(ip)
                return True
            return False

    @classmethod
    def clear_all_notified_ips(cls) -> None:
        """Clear all notified IPs in a thread-safe manner."""
        with cls._lock:
            cls._notified_ips.clear()

    @classmethod
    def get_notified_ips_count(cls) -> int:
        """Get the count of notified IPs in a thread-safe manner."""
        with cls._lock:
            return len(cls._notified_ips)

    @classmethod
    def remove_notified_ips_batch(cls, ips: set[str]) -> int:
        """Remove multiple IPs from the notified set in a single thread-safe operation.

        Args:
            ips: Set of IP addresses to remove.

        Returns:
            The number of IPs that were actually removed.
        """
        with cls._lock:
            initial_count = len(cls._notified_ips)
            cls._notified_ips -= ips
            return initial_count - len(cls._notified_ips)

    @classmethod
    def get_notified_ips_copy(cls) -> set[str]:
        """Get a copy of the notified IPs set in a thread-safe manner."""
        with cls._lock:
            return cls._notified_ips.copy()


class MobileWarnings(_DetectionWarnings):
    """Track which IPs have triggered the mobile detection warning."""


class VPNWarnings(_DetectionWarnings):
    """Track which IPs have triggered the VPN detection warning."""


class HostingWarnings(_DetectionWarnings):
    """Track which IPs have triggered the hosting detection warning."""
