"""Player data models for tracking remote players and their session metadata."""

import dataclasses
from dataclasses import dataclass
from datetime import datetime as datetime_type  # noqa: TC003
from threading import Event
from typing import TYPE_CHECKING, ClassVar, override

from session_sniffer.models.player_lookup import (
    PlayerCountryFlag,
    PlayerGeoLite2,
    PlayerIPAPI,
    PlayerIPLookup,
    PlayerLooky,
    PlayerModMenus,
    PlayerPing,
    PlayerReverseDNS,
    PlayerUserIPDetection,
)

# Re-export classes for backward compatibility
from session_sniffer.models.player_traffic import (
    PacketInfo,
    PlayerBandwidth,
    PlayerDateTime,
    PlayerPackets,
    PlayerPorts,
)
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.warnings import HostingWarnings, MobileWarnings, VPNWarnings
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.player.userip import UserIP

__all__ = [
    'PacketInfo',
    'Player',
    'PlayerBandwidth',
    'PlayerCountryFlag',
    'PlayerDateTime',
    'PlayerGeoLite2',
    'PlayerIPAPI',
    'PlayerIPLookup',
    'PlayerLooky',
    'PlayerModMenus',
    'PlayerPackets',
    'PlayerPing',
    'PlayerPorts',
    'PlayerReverseDNS',
    'PlayerUserIPDetection',
]


def _empty_usernames() -> list[str]:
    """Return a typed empty usernames list for dataclass defaults."""
    return []


@dataclass(slots=True)
class _PlayerLifecycleState:
    """Runtime lifecycle state for a player."""

    left_event: Event = dataclasses.field(default_factory=Event)
    rejoins: int = 0
    detection_checked: bool = False
    relay_monitor_started: bool = False
    usernames: list[str] = dataclasses.field(default_factory=_empty_usernames)
    userip_check_version: int = -1
    userip_check_positive: bool = False


@dataclass(slots=True)
class _PlayerTrafficState:
    """Packet, bandwidth, ports, and datetime tracking state for a player."""

    datetime: PlayerDateTime
    packets: PlayerPackets
    bandwidth: PlayerBandwidth
    ports: PlayerPorts


@dataclass(slots=True)
class _PlayerLookupState:
    """Lookup and network metadata for a player."""

    reverse_dns: PlayerReverseDNS = dataclasses.field(default_factory=PlayerReverseDNS)
    iplookup: PlayerIPLookup = dataclasses.field(default_factory=PlayerIPLookup)
    ping: PlayerPing = dataclasses.field(default_factory=PlayerPing)


@dataclass(slots=True)
class _PlayerOptionalState:
    """Optional enrichments that may be filled asynchronously."""

    country_flag: PlayerCountryFlag | None = None
    userip: UserIP | None = None
    userip_detection: PlayerUserIPDetection | None = None
    mod_menus: PlayerModMenus | None = None
    looky_system: PlayerLooky = dataclasses.field(default_factory=PlayerLooky)


class Player:
    """Represent a remote player identified by IP and derived session metadata."""

    ip: str
    left_event: Event
    usernames: list[str]
    detection_checked: bool
    relay_monitor_started: bool
    packets: PlayerPackets
    bandwidth: PlayerBandwidth
    ports: PlayerPorts
    reverse_dns: PlayerReverseDNS
    iplookup: PlayerIPLookup
    ping: PlayerPing
    country_flag: PlayerCountryFlag | None
    userip: UserIP | None
    userip_detection: PlayerUserIPDetection | None
    mod_menus: PlayerModMenus | None
    looky_system: PlayerLooky

    _LIFECYCLE_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            'left_event',
            'rejoins',
            'detection_checked',
            'relay_monitor_started',
            'usernames',
            'userip_check_version',
            'userip_check_positive',
        },
    )
    _TRAFFIC_FIELDS: ClassVar[frozenset[str]] = frozenset({'datetime', 'packets', 'bandwidth', 'ports'})
    _LOOKUP_FIELDS: ClassVar[frozenset[str]] = frozenset({'reverse_dns', 'iplookup', 'ping'})
    _OPTIONAL_FIELDS: ClassVar[frozenset[str]] = frozenset({'country_flag', 'userip', 'userip_detection', 'mod_menus', 'looky_system'})

    def __init__(self, *, ip: str, packet: PacketInfo) -> None:
        """Initialize a `Player` from the first observed packet.

        Args:
            ip: The player's IP address.
            packet: The first observed packet's metadata.
        """
        self.ip = ip
        self._lifecycle = _PlayerLifecycleState()
        self._traffic = _PlayerTrafficState(
            datetime=PlayerDateTime.from_packet_datetime(packet.datetime),
            packets=PlayerPackets.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host),
            bandwidth=PlayerBandwidth.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host),
            ports=PlayerPorts.from_packet_port(packet.port),
        )
        self._lookup = _PlayerLookupState()
        self._optional = _PlayerOptionalState()

    def __getattr__(self, name: str) -> object:
        """Provide backward-compatible attribute access for grouped state fields."""
        if name in self._LIFECYCLE_FIELDS:
            return getattr(self._lifecycle, name)
        if name in self._TRAFFIC_FIELDS:
            return getattr(self._traffic, name)
        if name in self._LOOKUP_FIELDS:
            return getattr(self._lookup, name)
        if name in self._OPTIONAL_FIELDS:
            return getattr(self._optional, name)
        raise AttributeError(name)

    @override
    def __setattr__(self, name: str, value: object) -> None:
        """Provide backward-compatible assignment for grouped state fields."""
        if name in {'ip', '_lifecycle', '_traffic', '_lookup', '_optional'}:
            object.__setattr__(self, name, value)
            return
        if name in self._LIFECYCLE_FIELDS:
            setattr(self._lifecycle, name, value)
            return
        if name in self._TRAFFIC_FIELDS:
            setattr(self._traffic, name, value)
            return
        if name in self._LOOKUP_FIELDS:
            setattr(self._lookup, name, value)
            return
        if name in self._OPTIONAL_FIELDS:
            setattr(self._optional, name, value)
            return
        object.__setattr__(self, name, value)

    @property
    def datetime(self) -> PlayerDateTime:
        """Access packet datetime tracking state with a concrete type."""
        return self._traffic.datetime

    @datetime.setter
    def datetime(self, value: PlayerDateTime) -> None:
        """Set packet datetime tracking state."""
        self._traffic.datetime = value

    @property
    def rejoins(self) -> int:
        """Number of times this player has rejoined the session."""
        return self._lifecycle.rejoins

    @rejoins.setter
    def rejoins(self, value: int) -> None:
        """Set the player's rejoin count."""
        self._lifecycle.rejoins = value

    def mark_as_seen(self, *, port: int, packet_datetime: datetime_type, packet_length: int, sent_by_local_host: bool) -> None:
        """Update per-player state from an observed packet."""
        self._traffic.datetime.last_seen = packet_datetime
        self._traffic.packets.increment(packet_length=packet_length, sent_by_local_host=sent_by_local_host)
        self._traffic.bandwidth.increment(packet_length=packet_length, sent_by_local_host=sent_by_local_host)

        if port != self._traffic.ports.last:
            if port not in self._traffic.ports.all:
                self._traffic.ports.all.append(port)

            if port in self._traffic.ports.middle:
                self._traffic.ports.middle.remove(port)

            if self._traffic.ports.last not in self._traffic.ports.middle and self._traffic.ports.last != self._traffic.ports.first:
                self._traffic.ports.middle.append(self._traffic.ports.last)

            self._traffic.ports.last = port

    def mark_as_rejoined(self, *, packet_datetime: datetime_type, packet_length: int, port: int, sent_by_local_host: bool) -> None:
        """Handle a player rejoin by resetting current-session counters."""
        self.left_event.clear()
        self.rejoins += 1
        self.detection_checked = False
        self.relay_monitor_started = False

        self.datetime.accumulate_session_to_total()
        self.datetime.last_rejoin = packet_datetime
        self.datetime.last_seen = packet_datetime
        self.packets.reset_current_session(packet_length=packet_length, sent_by_local_host=sent_by_local_host)
        self.bandwidth.reset_current_session(packet_length=packet_length, sent_by_local_host=sent_by_local_host)

        if Settings.gui_reset_ports_on_rejoins:
            self.ports.reset(port)

    def mark_as_left(self) -> None:
        """Mark the player as disconnected and move it to the disconnected registry."""
        self.left_event.set()

        self.datetime.set_session_time()
        self.packets.pps.reset()
        self.packets.ppm.reset()
        self.bandwidth.bps.reset()
        self.bandwidth.bpm.reset()

        PlayersRegistry.move_player_to_disconnected(self)

        # Clear IP from warning sets so detections will trigger again on rejoin
        MobileWarnings.remove_notified_ip(self.ip)
        VPNWarnings.remove_notified_ip(self.ip)
        HostingWarnings.remove_notified_ip(self.ip)
