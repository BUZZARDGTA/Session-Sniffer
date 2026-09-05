"""Player data models for tracking remote players and their session metadata."""

import dataclasses
from dataclasses import dataclass
from threading import Event
from typing import TYPE_CHECKING

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
from session_sniffer.models.player_traffic import (
    PacketInfo,
    PlayerBandwidth,
    PlayerDateTime,
    PlayerPackets,
    PlayerPorts,
)
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from datetime import datetime as datetime_type

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
    is_gta5_process: bool = False


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
    ps3_username: str | None = None


class Player:  # pylint: disable=too-many-public-methods
    """Represent a remote player identified by IP and derived session metadata."""

    def __init__(self, *, ip: str, packet: PacketInfo) -> None:
        """Initialize a `Player` from the first observed packet.

        Args:
            ip: The player's IP address.
            packet: The first observed packet's metadata.
        """
        self._ip = ip
        self._lifecycle = _PlayerLifecycleState()
        self._traffic = _PlayerTrafficState(
            datetime=PlayerDateTime.from_packet_datetime(packet.datetime),
            packets=PlayerPackets.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host),
            bandwidth=PlayerBandwidth.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host),
            ports=PlayerPorts.from_packet_port(packet.port),
        )
        self._lookup = _PlayerLookupState()
        self._optional = _PlayerOptionalState()

    @property
    def ip(self) -> str:
        """The player's IP address."""
        return self._ip

    @property
    def left_event(self) -> Event:
        """Disconnect event for this player."""
        return self._lifecycle.left_event

    @property
    def usernames(self) -> list[str]:
        """Known usernames associated with this player."""
        return self._lifecycle.usernames

    @usernames.setter
    def usernames(self, value: list[str]) -> None:
        self._lifecycle.usernames = value

    @property
    def detection_checked(self) -> bool:
        """Whether detection check has been performed."""
        return self._lifecycle.detection_checked

    @detection_checked.setter
    def detection_checked(self, value: bool) -> None:
        self._lifecycle.detection_checked = value

    @property
    def relay_monitor_started(self) -> bool:
        """Whether relay monitor thread was started."""
        return self._lifecycle.relay_monitor_started

    @relay_monitor_started.setter
    def relay_monitor_started(self, value: bool) -> None:
        self._lifecycle.relay_monitor_started = value

    @property
    def userip_check_version(self) -> int:
        """UserIP database version when last checked."""
        return self._lifecycle.userip_check_version

    @userip_check_version.setter
    def userip_check_version(self, value: int) -> None:
        self._lifecycle.userip_check_version = value

    @property
    def userip_check_positive(self) -> bool:
        """Whether the last UserIP check was positive."""
        return self._lifecycle.userip_check_positive

    @userip_check_positive.setter
    def userip_check_positive(self, value: bool) -> None:
        self._lifecycle.userip_check_positive = value

    @property
    def is_gta5_process(self) -> bool:
        """Whether this player's traffic matched the detected GTA5 process."""
        return self._lifecycle.is_gta5_process

    @is_gta5_process.setter
    def is_gta5_process(self, value: bool) -> None:
        self._lifecycle.is_gta5_process = value

    @property
    def datetime(self) -> PlayerDateTime:
        """Access packet datetime tracking state with a concrete type."""
        return self._traffic.datetime

    @datetime.setter
    def datetime(self, value: PlayerDateTime) -> None:
        """Set packet datetime tracking state."""
        self._traffic.datetime = value

    @property
    def packets(self) -> PlayerPackets:
        """Packet tracking counters for this player."""
        return self._traffic.packets

    @packets.setter
    def packets(self, value: PlayerPackets) -> None:
        self._traffic.packets = value

    @property
    def bandwidth(self) -> PlayerBandwidth:
        """Bandwidth tracking counters for this player."""
        return self._traffic.bandwidth

    @bandwidth.setter
    def bandwidth(self, value: PlayerBandwidth) -> None:
        self._traffic.bandwidth = value

    @property
    def ports(self) -> PlayerPorts:
        """Observed ports for this player."""
        return self._traffic.ports

    @ports.setter
    def ports(self, value: PlayerPorts) -> None:
        self._traffic.ports = value

    @property
    def reverse_dns(self) -> PlayerReverseDNS:
        """Reverse DNS lookup metadata for this player."""
        return self._lookup.reverse_dns

    @reverse_dns.setter
    def reverse_dns(self, value: PlayerReverseDNS) -> None:
        self._lookup.reverse_dns = value

    @property
    def iplookup(self) -> PlayerIPLookup:
        """IP lookup metadata (GeoLite2, IP-API) for this player."""
        return self._lookup.iplookup

    @iplookup.setter
    def iplookup(self, value: PlayerIPLookup) -> None:
        self._lookup.iplookup = value

    @property
    def ping(self) -> PlayerPing:
        """Ping measurement metadata for this player."""
        return self._lookup.ping

    @ping.setter
    def ping(self, value: PlayerPing) -> None:
        self._lookup.ping = value

    @property
    def country_flag(self) -> PlayerCountryFlag | None:
        """Country flag emoji/rendering data for this player."""
        return self._optional.country_flag

    @country_flag.setter
    def country_flag(self, value: PlayerCountryFlag | None) -> None:
        self._optional.country_flag = value

    @property
    def userip(self) -> UserIP | None:
        """Resolved UserIP database entry."""
        return self._optional.userip

    @userip.setter
    def userip(self, value: UserIP | None) -> None:
        self._optional.userip = value

    @property
    def userip_detection(self) -> PlayerUserIPDetection | None:
        """UserIP detection tracking state."""
        return self._optional.userip_detection

    @userip_detection.setter
    def userip_detection(self, value: PlayerUserIPDetection | None) -> None:
        self._optional.userip_detection = value

    @property
    def mod_menus(self) -> PlayerModMenus | None:
        """Detected mod menus for this player."""
        return self._optional.mod_menus

    @mod_menus.setter
    def mod_menus(self, value: PlayerModMenus | None) -> None:
        self._optional.mod_menus = value

    @property
    def ps3_username(self) -> str | None:
        """PlayStation username resolved from PS3 packet capture, if any."""
        return self._optional.ps3_username

    @ps3_username.setter
    def ps3_username(self, value: str | None) -> None:
        self._optional.ps3_username = value

    @property
    def looky_system(self) -> PlayerLooky:
        """Looky system tracking state."""
        return self._optional.looky_system

    @looky_system.setter
    def looky_system(self, value: PlayerLooky) -> None:
        self._optional.looky_system = value

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
