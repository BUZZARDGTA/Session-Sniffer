"""Network interface models and registry.

This module provides dataclasses and utilities for managing network interface information,
including the Interface class, SelectedInterfaceRow, ARPEntry, and the AllInterfaces registry.
"""
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, NamedTuple

from session_sniffer.networking.ctypes_adapters_info import IF_OPER_STATUS_NOT_PRESENT, MEDIA_CONNECT_STATE_DISCONNECTED, NETWORK_ADAPTER_DISABLED
from session_sniffer.networking.exceptions import InterfaceAlreadyExistsError

if TYPE_CHECKING:
    from collections.abc import Iterator


# Display values for the Type column in the interface selection dialog.
INTERFACE_TYPE_INTERFACE = 'Interface'
INTERFACE_TYPE_NEIGHBOUR = 'Neighbour'
INTERFACE_TYPE_BRIDGED = 'Bridged'
INTERFACE_TYPE_SHARED = 'Shared'
INTERFACE_TYPE_SHARING = 'Sharing'


class ARPEntry(NamedTuple):
    """Represent a single ARP neighbor entry for an interface."""

    ip_address: str
    mac_address: str
    vendor_name: str | None = None


@dataclass(kw_only=True, slots=True)
class InterfaceIdentity:
    """Identity fields for a network interface."""

    index:        int
    name:         str
    description:  str
    mac_address:  str | None
    device_name:  str | None
    vendor_name:  str | None
    adapter_guid: str | None = None


@dataclass(kw_only=True, slots=True)
class InterfaceTraffic:
    """Traffic statistics for a network interface."""

    packets_sent:       int
    packets_recv:       int
    transmit_link_speed: int
    receive_link_speed:  int


@dataclass(kw_only=True, slots=True)
class Interface:
    """Represent a network interface and its live capture-related stats."""

    identity: InterfaceIdentity
    traffic: InterfaceTraffic
    ip_enabled: bool
    state: int
    media_connect_state: int
    interface_type: str = INTERFACE_TYPE_INTERFACE
    ip_addresses: list[str] = field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]
    gateway_addresses: list[str] = field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]
    arp_entries: list[ARPEntry] = field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]

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
            not self.traffic.transmit_link_speed and not self.traffic.receive_link_speed,
        ]

        if any(inactive_conditions):
            return True

        # Zero link speeds combined with no IP/traffic suggests inactive virtual adapters
        if (
            not self.traffic.transmit_link_speed
            and not self.traffic.receive_link_speed
            and not self.ip_addresses
            and not self.traffic.packets_sent
            and not self.traffic.packets_recv
        ):
            return True

        # Check if all identifying details and traffic data are missing
        return (
            not self.traffic.packets_sent
            and not self.traffic.packets_recv
            and not self.identity.description
            and not self.ip_addresses
            and not self.arp_entries
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class SelectedInterfaceRow:
    """Immutable reference to a user's chosen interface row.

    Holds only the live `Interface` object plus the row-specific selectors
    (`ip_address`, `is_arp`). Other commonly-needed fields are exposed as
    read-only properties that delegate to the live `Interface` so callers
    always see fresh data and we never duplicate state.
    """

    interface: Interface
    ip_address: str | None
    is_arp: bool

    @property
    def name(self) -> str:
        """Interface friendly name."""
        return self.interface.identity.name

    @property
    def description(self) -> str:
        """Interface description."""
        return self.interface.identity.description

    @property
    def device_name(self) -> str | None:
        r"""TShark device name (e.g. ``\Device\NPF_{GUID}``)."""
        return self.interface.identity.device_name

    @property
    def gateway_ip(self) -> str | None:
        """First gateway IP for this interface, if any."""
        return self.interface.gateway_addresses[0] if self.interface.gateway_addresses else None

    @property
    def mac_address(self) -> str | None:
        """MAC for this row: ARP-neighbor MAC when `is_arp`, else interface MAC."""
        if self.is_arp:
            return next(
                (arp.mac_address for arp in self.interface.arp_entries if arp.ip_address == self.ip_address),
                None,
            )
        return self.interface.identity.mac_address

    @property
    def vendor_name(self) -> str | None:
        """Vendor for this row: ARP-neighbor vendor when `is_arp`, else interface vendor."""
        if self.is_arp:
            return next(
                (arp.vendor_name for arp in self.interface.arp_entries if arp.ip_address == self.ip_address),
                None,
            )
        return self.interface.identity.vendor_name


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
        if new_interface.identity.index in cls.all_interfaces:
            raise InterfaceAlreadyExistsError(new_interface.identity.index, new_interface.identity.name)

        cls.all_interfaces[new_interface.identity.index] = new_interface
        if new_interface.identity.name:
            cls._name_map[new_interface.identity.name.casefold()] = new_interface.identity.index
        return new_interface

    @classmethod
    def clear(cls) -> None:
        """Remove all interfaces from the registry."""
        cls.all_interfaces.clear()
        cls._name_map.clear()

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
            if interface.identity.name:
                cls._name_map.pop(interface.identity.name.casefold(), None)
            return True
        return False
