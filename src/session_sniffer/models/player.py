"""Player data models for tracking remote players and their session metadata."""

import copy
import dataclasses
from dataclasses import dataclass
from threading import Event
from typing import TYPE_CHECKING, Self

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
    PlayerJoin,
    PlayerPackets,
    PlayerPorts,
)
from session_sniffer.networking.third_party_servers import is_third_party_server_ip
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
    'PlayerJoin',
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
    session_id: int = 1
    detection_checked: bool = False
    relay_monitor_started: bool = False
    usernames: list[str] = dataclasses.field(default_factory=_empty_usernames)
    userip_check_version: int = -1
    userip_check_positive: bool = False
    is_gta5_process: bool = False
    is_rdr2_process: bool = False
    is_third_party_server: bool = False


@dataclass(slots=True)
class _PlayerTrafficState:
    """Packet, bandwidth, ports, datetime, and joins tracking state for a player."""

    datetime: PlayerDateTime
    packets: PlayerPackets
    bandwidth: PlayerBandwidth
    ports: PlayerPorts
    joins: list[PlayerJoin]


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

    def __init__(self, *, ip: str, packet: PacketInfo, session_id: int = 1) -> None:
        """Initialize a `Player` from the first observed packet.

        Args:
            ip: The player's IP address.
            packet: The first observed packet's metadata.
            session_id: The session sequence number during which this player joined.
        """
        self._ip = ip
        self._lifecycle = _PlayerLifecycleState(
            is_third_party_server=is_third_party_server_ip(ip),
            session_id=session_id,
        )
        initial_join = PlayerJoin(
            join_index=1,
            rejoin_number=0,
            joined_at=packet.datetime,
            last_seen=packet.datetime,
            ports=PlayerPorts.from_packet_port(packet.port),
            packets=PlayerPackets.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host),
            bandwidth=PlayerBandwidth.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host),
            is_active=True,
        )
        self._traffic = _PlayerTrafficState(
            datetime=PlayerDateTime.from_packet_datetime(packet.datetime),
            packets=PlayerPackets.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host),
            bandwidth=PlayerBandwidth.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host),
            ports=PlayerPorts.from_packet_port(packet.port),
            joins=[initial_join],
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
    def session_id(self) -> int:
        """The session sequence number during which this player last joined."""
        return self._lifecycle.session_id

    @session_id.setter
    def session_id(self, value: int) -> None:
        self._lifecycle.session_id = value

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
    def is_rdr2_process(self) -> bool:
        """Whether this player's traffic matched the detected RDR2 process."""
        return self._lifecycle.is_rdr2_process

    @is_rdr2_process.setter
    def is_rdr2_process(self, value: bool) -> None:
        self._lifecycle.is_rdr2_process = value

    @property
    def is_third_party_server(self) -> bool:
        """Whether this player's IP address belongs to a known third-party server range."""
        return self._lifecycle.is_third_party_server

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

    @property
    def joins(self) -> list[PlayerJoin]:
        """All observed join/rejoin sessions for this player."""
        return self._traffic.joins

    def mark_as_seen(self, *, port: int, packet_datetime: datetime_type, packet_length: int, sent_by_local_host: bool) -> None:
        """Update per-player state from an observed packet."""
        self._traffic.datetime.last_seen = max(self._traffic.datetime.last_seen, packet_datetime)
        self._traffic.packets.increment(packet_length=packet_length, sent_by_local_host=sent_by_local_host)
        self._traffic.bandwidth.increment(packet_length=packet_length, sent_by_local_host=sent_by_local_host)

        self._traffic.ports.add_port(port)

        if self._traffic.joins:
            self._traffic.joins[-1].mark_as_seen(
                port=port,
                packet_datetime=packet_datetime,
                packet_length=packet_length,
                sent_by_local_host=sent_by_local_host,
            )

    def mark_as_rejoined(
        self,
        *,
        packet_datetime: datetime_type,
        packet_length: int,
        port: int,
        sent_by_local_host: bool,
        session_id: int,
    ) -> None:
        """Handle a player rejoin by resetting current-session counters."""
        self.left_event.clear()
        self.rejoins += 1
        self.session_id = session_id
        self.detection_checked = False
        self.relay_monitor_started = False

        self.datetime.accumulate_session_to_total()
        self.datetime.last_rejoin = packet_datetime
        self.datetime.last_seen = packet_datetime
        self.packets.reset_current_session(packet_length=packet_length, sent_by_local_host=sent_by_local_host)
        self.bandwidth.reset_current_session(packet_length=packet_length, sent_by_local_host=sent_by_local_host)

        if Settings.gui_reset_ports_on_rejoins:
            self.ports.reset(port)

        if self._traffic.joins and self._traffic.joins[-1].is_active:
            self._traffic.joins[-1].mark_as_left()

        new_join = PlayerJoin(
            join_index=len(self._traffic.joins) + 1,
            rejoin_number=self.rejoins,
            joined_at=packet_datetime,
            last_seen=packet_datetime,
            ports=PlayerPorts.from_packet_port(port),
            packets=PlayerPackets.from_packet_direction(packet_length=packet_length, sent_by_local_host=sent_by_local_host),
            bandwidth=PlayerBandwidth.from_packet_direction(packet_length=packet_length, sent_by_local_host=sent_by_local_host),
            is_active=True,
        )
        self._traffic.joins.append(new_join)

    def mark_as_left(self) -> None:
        """Mark the player as disconnected and move it to the disconnected registry."""
        self.left_event.set()

        self.datetime.set_session_time()
        self.packets.pps.reset()
        self.packets.ppm.reset()
        self.bandwidth.bps.reset()
        self.bandwidth.bpm.reset()

        if self._traffic.joins:
            self._traffic.joins[-1].mark_as_left()

        PlayersRegistry.move_player_to_disconnected(self)

    def snapshot(self, *, session_id: int | None = None) -> Self:
        """Create an immutable snapshot clone of this player for a given session."""
        clone = copy.copy(self)
        frozen_lifecycle = _PlayerLifecycleState(
            left_event=Event(),
            rejoins=self._lifecycle.rejoins,
            session_id=session_id if session_id is not None else self._lifecycle.session_id,
            detection_checked=self._lifecycle.detection_checked,
            relay_monitor_started=self._lifecycle.relay_monitor_started,
            usernames=list(self._lifecycle.usernames),
            userip_check_version=self._lifecycle.userip_check_version,
            userip_check_positive=self._lifecycle.userip_check_positive,
            is_gta5_process=self._lifecycle.is_gta5_process,
            is_rdr2_process=self._lifecycle.is_rdr2_process,
            is_third_party_server=self._lifecycle.is_third_party_server,
        )
        frozen_lifecycle.left_event.set()
        frozen_traffic = _PlayerTrafficState(
            datetime=self._traffic.datetime.snapshot(),
            packets=self._traffic.packets.snapshot(),
            bandwidth=self._traffic.bandwidth.snapshot(),
            ports=self._traffic.ports.snapshot(),
            joins=list(self._traffic.joins),
        )
        object.__setattr__(clone, '_lifecycle', frozen_lifecycle)
        object.__setattr__(clone, '_traffic', frozen_traffic)
        return clone
