"""Detection warning tracking systems and GUI detection settings."""

from dataclasses import dataclass
from threading import Lock
from typing import ClassVar


class MobileWarnings:
    """Track which IPs have triggered the mobile detection warning."""

    lock: ClassVar = Lock()
    notified_mobile_ips: ClassVar[set[str]] = set()

    @classmethod
    def add_notified_ip(cls, ip: str) -> bool:
        """Add an IP to the notified mobile IPs set in a thread-safe manner.

        Args:
            ip: The IP address to add

        Returns:
            Whether the IP was newly added.
        """
        with cls.lock:
            if ip in cls.notified_mobile_ips:
                return False
            cls.notified_mobile_ips.add(ip)
            return True

    @classmethod
    def is_ip_notified(cls, ip: str) -> bool:
        """Check if an IP has already been notified for mobile detection.

        Args:
            ip: The IP address to check

        Returns:
            Whether the IP has been notified.
        """
        with cls.lock:
            return ip in cls.notified_mobile_ips

    @classmethod
    def remove_notified_ip(cls, ip: str) -> bool:
        """Remove an IP from the notified mobile IPs set in a thread-safe manner.

        Args:
            ip: The IP address to remove

        Returns:
            Whether the IP was present and removed.
        """
        with cls.lock:
            if ip in cls.notified_mobile_ips:
                cls.notified_mobile_ips.remove(ip)
                return True
            return False

    @classmethod
    def clear_all_notified_ips(cls) -> None:
        """Clear all notified mobile IPs in a thread-safe manner."""
        with cls.lock:
            cls.notified_mobile_ips.clear()

    @classmethod
    def get_notified_ips_count(cls) -> int:
        """Get the count of notified mobile IPs in a thread-safe manner.

        Returns:
            The number of notified mobile IPs
        """
        with cls.lock:
            return len(cls.notified_mobile_ips)

    @classmethod
    def remove_notified_ips_batch(cls, ips: set[str]) -> int:
        """Remove multiple IPs from the notified mobile IPs set in a single thread-safe operation.

        Args:
            ips: Set of IP addresses to remove.

        Returns:
            The number of IPs that were actually removed.
        """
        with cls.lock:
            initial_count = len(cls.notified_mobile_ips)
            cls.notified_mobile_ips -= ips
            return initial_count - len(cls.notified_mobile_ips)

    @classmethod
    def get_notified_ips_copy(cls) -> set[str]:
        """Get a copy of the notified mobile IPs set in a thread-safe manner.

        Returns:
            A copy of the notified mobile IPs set
        """
        with cls.lock:
            return cls.notified_mobile_ips.copy()


class VPNWarnings:
    """Track which IPs have triggered the VPN detection warning."""

    lock: ClassVar = Lock()
    notified_vpn_ips: ClassVar[set[str]] = set()

    @classmethod
    def add_notified_ip(cls, ip: str) -> bool:
        """Add an IP to the notified VPN IPs set in a thread-safe manner.

        Args:
            ip: The IP address to add

        Returns:
            Whether the IP was newly added.
        """
        with cls.lock:
            if ip in cls.notified_vpn_ips:
                return False
            cls.notified_vpn_ips.add(ip)
            return True

    @classmethod
    def is_ip_notified(cls, ip: str) -> bool:
        """Check if an IP has already been notified for VPN detection.

        Args:
            ip: The IP address to check

        Returns:
            Whether the IP has been notified.
        """
        with cls.lock:
            return ip in cls.notified_vpn_ips

    @classmethod
    def remove_notified_ip(cls, ip: str) -> bool:
        """Remove an IP from the notified VPN IPs set in a thread-safe manner.

        Args:
            ip: The IP address to remove

        Returns:
            Whether the IP was present and removed.
        """
        with cls.lock:
            if ip in cls.notified_vpn_ips:
                cls.notified_vpn_ips.remove(ip)
                return True
            return False

    @classmethod
    def clear_all_notified_ips(cls) -> None:
        """Clear all notified VPN IPs in a thread-safe manner."""
        with cls.lock:
            cls.notified_vpn_ips.clear()

    @classmethod
    def get_notified_ips_count(cls) -> int:
        """Get the count of notified VPN IPs in a thread-safe manner.

        Returns:
            The number of notified VPN IPs
        """
        with cls.lock:
            return len(cls.notified_vpn_ips)

    @classmethod
    def remove_notified_ips_batch(cls, ips: set[str]) -> int:
        """Remove multiple IPs from the notified VPN IPs set in a single thread-safe operation.

        Args:
            ips: Set of IP addresses to remove.

        Returns:
            The number of IPs that were actually removed.
        """
        with cls.lock:
            initial_count = len(cls.notified_vpn_ips)
            cls.notified_vpn_ips -= ips
            return initial_count - len(cls.notified_vpn_ips)

    @classmethod
    def get_notified_ips_copy(cls) -> set[str]:
        """Get a copy of the notified VPN IPs set in a thread-safe manner.

        Returns:
            A copy of the notified VPN IPs set
        """
        with cls.lock:
            return cls.notified_vpn_ips.copy()


class HostingWarnings:
    """Track which IPs have triggered the hosting detection warning."""

    lock: ClassVar = Lock()
    notified_hosting_ips: ClassVar[set[str]] = set()

    @classmethod
    def add_notified_ip(cls, ip: str) -> bool:
        """Add an IP to the notified hosting IPs set in a thread-safe manner.

        Args:
            ip: The IP address to add

        Returns:
            Whether the IP was newly added.
        """
        with cls.lock:
            if ip in cls.notified_hosting_ips:
                return False
            cls.notified_hosting_ips.add(ip)
            return True

    @classmethod
    def is_ip_notified(cls, ip: str) -> bool:
        """Check if an IP has already been notified for hosting detection.

        Args:
            ip: The IP address to check

        Returns:
            Whether the IP has been notified.
        """
        with cls.lock:
            return ip in cls.notified_hosting_ips

    @classmethod
    def remove_notified_ip(cls, ip: str) -> bool:
        """Remove an IP from the notified hosting IPs set in a thread-safe manner.

        Args:
            ip: The IP address to remove

        Returns:
            Whether the IP was present and removed.
        """
        with cls.lock:
            if ip in cls.notified_hosting_ips:
                cls.notified_hosting_ips.remove(ip)
                return True
            return False

    @classmethod
    def clear_all_notified_ips(cls) -> None:
        """Clear all notified hosting IPs in a thread-safe manner."""
        with cls.lock:
            cls.notified_hosting_ips.clear()

    @classmethod
    def get_notified_ips_count(cls) -> int:
        """Get the count of notified hosting IPs in a thread-safe manner.

        Returns:
            The number of notified hosting IPs
        """
        with cls.lock:
            return len(cls.notified_hosting_ips)

    @classmethod
    def remove_notified_ips_batch(cls, ips: set[str]) -> int:
        """Remove multiple IPs from the notified hosting IPs set in a single thread-safe operation.

        Args:
            ips: Set of IP addresses to remove.

        Returns:
            The number of IPs that were actually removed.
        """
        with cls.lock:
            initial_count = len(cls.notified_hosting_ips)
            cls.notified_hosting_ips -= ips
            return initial_count - len(cls.notified_hosting_ips)

    @classmethod
    def get_notified_ips_copy(cls) -> set[str]:
        """Get a copy of the notified hosting IPs set in a thread-safe manner.

        Returns:
            A copy of the notified hosting IPs set
        """
        with cls.lock:
            return cls.notified_hosting_ips.copy()


@dataclass(kw_only=True, slots=True)
class GUIDetectionSettings:
    """Runtime GUI detection settings that persist during application execution but are not saved to settings file."""
    mobile_detection_enabled: ClassVar[bool] = False
    vpn_detection_enabled: ClassVar[bool] = False
    hosting_detection_enabled: ClassVar[bool] = False
    player_join_notifications_enabled: ClassVar[bool] = False
    player_rejoin_notifications_enabled: ClassVar[bool] = False
    player_leave_notifications_enabled: ClassVar[bool] = False
