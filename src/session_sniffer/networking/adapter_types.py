"""Data types and exceptions for Windows network adapter information."""

from dataclasses import field

from pydantic.dataclasses import dataclass


class GetAdaptersAddressesError(OSError):
    """Exception raised when GetAdaptersAddresses fails."""

    def __init__(self, error_code: int) -> None:
        """Initialize the exception with the error code."""
        super().__init__(f'GetAdaptersAddresses failed with error code: {error_code}')


@dataclass(frozen=True, kw_only=True, slots=True)
class AdapterIdentity:
    """Identity fields for a network adapter."""

    interface_index: int
    friendly_name: str
    description: str
    mac_address: str | None
    adapter_guid: str | None


@dataclass(frozen=True, kw_only=True, slots=True)
class AdapterStatus:
    """Status fields for a network adapter."""

    operational_status: int
    ip_enabled: bool
    media_connect_state: int


@dataclass(frozen=True, kw_only=True, slots=True)
class AdapterTraffic:
    """Traffic statistics for a network adapter."""

    packets_sent: int
    packets_recv: int
    transmit_link_speed: int
    receive_link_speed: int


@dataclass(frozen=True, kw_only=True, slots=True)
class AdapterData:
    """Represent Windows network adapter details used by the sniffer."""

    identity: AdapterIdentity
    status: AdapterStatus
    traffic: AdapterTraffic
    ipv4_addresses: list[str]
    gateway_addresses: list[str] = field(default_factory=list[str])
    neighbors: list[tuple[str | None, str | None]] = field(
        default_factory=list[tuple[str | None, str | None]],
    )
