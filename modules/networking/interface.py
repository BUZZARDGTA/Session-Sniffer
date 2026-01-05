"""Network interface models and registry.

This module provides dataclasses and utilities for managing network interface information,
including the Interface class, SelectedInterface, ARPEntry, and the AllInterfaces registry.
"""
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, NamedTuple, cast

from modules.networking.ctypes_adapters_info import IF_OPER_STATUS_NOT_PRESENT, MEDIA_CONNECT_STATE_DISCONNECTED, NETWORK_ADAPTER_DISABLED
from modules.networking.exceptions import InterfaceAlreadyExistsError

if TYPE_CHECKING:
    from collections.abc import Iterator


class ARPEntry(NamedTuple):
    """Represent a single ARP neighbor entry for an interface."""

    ip_address: str
    mac_address: str
    vendor_name: str | None = None


@dataclass(frozen=True, kw_only=True, slots=True)
class SelectedInterface:
    """Immutable snapshot of a user's chosen interface row."""
    name: str
    description: str
    device_name: str | None
    vendor_name: str | None
    ip_address: str | None
    mac_address: str | None
    is_arp: bool


@dataclass(kw_only=True, slots=True)
class Interface:  # pylint: disable=too-many-instance-attributes
    """Represent a network interface and its live capture-related stats."""

    index: int
    ip_enabled: bool
    state: int
    media_connect_state: int
    name: str
    packets_sent: int
    packets_recv: int
    transmit_link_speed: int
    receive_link_speed: int
    description: str
    ip_addresses: list[str] = field(default_factory=lambda: cast('list[str]', []))
    arp_entries: list[ARPEntry] = field(default_factory=lambda: cast('list[ARPEntry]', []))
    mac_address: str | None
    device_name: str | None
    vendor_name: str | None

    def add_arp_entry(self, arp_entry: ARPEntry) -> bool:
        """Add an ARP entry for the given interface."""
        if arp_entry in self.arp_entries:
            return False

        self.arp_entries.append(arp_entry)
        return True

    def get_arp_entries(self) -> list[ARPEntry]:
        """Get ARP entries for the given interface."""
        return self.arp_entries

    def is_interface_inactive(self) -> bool:
        """Determine if an interface is inactive based on lack of traffic, IP addresses, and identifying details."""
        # Check for obvious inactive states first
        inactive_conditions = [
            self.state in (NETWORK_ADAPTER_DISABLED, IF_OPER_STATUS_NOT_PRESENT),
            self.media_connect_state == MEDIA_CONNECT_STATE_DISCONNECTED,
            not self.ip_addresses,
            not self.ip_enabled and not self.ip_addresses,
            not self.transmit_link_speed and not self.receive_link_speed,
        ]

        if any(inactive_conditions):
            return True

        # Zero link speeds combined with no IP/traffic suggests inactive virtual adapters
        if (
            not self.transmit_link_speed
            and not self.receive_link_speed
            and not self.ip_addresses
            and not self.packets_sent
            and not self.packets_recv
        ):
            return True

        # Check if all identifying details and traffic data are missing
        return (
            not self.packets_sent
            and not self.packets_recv
            and not self.description
            and not self.ip_addresses
            and not self.arp_entries
        )


class AllInterfaces:
    """Store and query discovered network interfaces by index and name."""

    all_interfaces: ClassVar[dict[int, Interface]] = {}
    _name_map: ClassVar[dict[str, int]] = {}

    @classmethod
    def iterate(cls) -> Iterator[Interface]:
        """Yield each interface from `all_interfaces`.

        This is an iterator that will provide all interfaces stored in the dictionary.
        The iteration will be done over the dictionary values (the Interface objects).

        Yields:
            Each interface from `all_interfaces`.
        """
        yield from cls.all_interfaces.values()

    @classmethod
    def get_interface(cls, index: int) -> Interface | None:
        """Retrieve an interface by its `index`.

        Args:
            index: The index of the interface to retrieve.

        Returns:
            The interface matching the index, or None if not found.
        """
        return cls.all_interfaces.get(index)

    @classmethod
    def get_interface_by_name(cls, name: str) -> Interface | None:
        """Retrieve an interface by its `name`, case-insensitively.

        Args:
            name: The name of the interface to retrieve.

        Returns:
            The interface matching the name, or None if not found.
        """
        normalized_name = name.casefold()
        index = cls._name_map.get(normalized_name)
        if index is not None:
            return cls.get_interface(index)
        return None

    @classmethod
    def add_interface(cls, new_interface: Interface) -> Interface:
        """Add a new interface to the registry or raise if it exists.

        Args:
            new_interface: The interface object to add.

        Returns:
            The added interface.

        Raises:
            InterfaceAlreadyExistsError: If an interface with the same index already exists.
        """
        if new_interface.index in cls.all_interfaces:
            raise InterfaceAlreadyExistsError(new_interface.index, new_interface.name)

        cls.all_interfaces[new_interface.index] = new_interface
        if new_interface.name:
            cls._name_map[new_interface.name.casefold()] = new_interface.index
        return new_interface

    @classmethod
    def delete_interface(cls, index: int) -> bool:
        """Delete an interface by its `index`.

        Args:
            index: The index of the interface to delete.

        Returns:
            Whether an interface matching the index existed and was deleted.
        """
        interface = cls.all_interfaces.pop(index, None)
        if interface:
            if interface.name:
                cls._name_map.pop(interface.name.casefold(), None)
            return True
        return False
