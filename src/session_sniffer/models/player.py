"""Player data models for tracking remote players and their session metadata."""

import copy
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


class Player:
    """Represent a remote player identified by IP and derived session metadata."""

    __slots__ = (
        '_ip',
        'bandwidth',
        'country_flag',
        'datetime',
        'detection_checked',
        'iplookup',
        'is_gta5_process',
        'is_rdr2_process',
        'is_third_party_server',
        'joins',
        'left_event',
        'looky_system',
        'mod_menus',
        'packets',
        'ping',
        'ports',
        'ps3_username',
        'rejoins',
        'relay_monitor_started',
        'reverse_dns',
        'session_id',
        'userip',
        'userip_check_positive',
        'userip_check_version',
        'userip_detection',
        'usernames',
    )

    bandwidth: PlayerBandwidth
    country_flag: PlayerCountryFlag | None
    datetime: PlayerDateTime
    detection_checked: bool
    iplookup: PlayerIPLookup
    is_gta5_process: bool
    is_rdr2_process: bool
    is_third_party_server: bool
    joins: list[PlayerJoin]
    left_event: Event
    looky_system: PlayerLooky
    mod_menus: PlayerModMenus | None
    packets: PlayerPackets
    ping: PlayerPing
    ports: PlayerPorts
    ps3_username: str | None
    rejoins: int
    relay_monitor_started: bool
    reverse_dns: PlayerReverseDNS
    session_id: int
    userip: UserIP | None
    userip_check_positive: bool
    userip_check_version: int
    userip_detection: PlayerUserIPDetection | None
    usernames: list[str]

    def __init__(self, *, ip: str, packet: PacketInfo, session_id: int = 1) -> None:
        """Initialize a `Player` from the first observed packet.

        Args:
            ip: The player's IP address.
            packet: The first observed packet's metadata.
            session_id: The session sequence number during which this player joined.
        """
        self._ip = ip
        self.left_event = Event()
        self.rejoins = 0
        self.session_id = session_id
        self.detection_checked = False
        self.relay_monitor_started = False
        self.usernames = []
        self.userip_check_version = -1
        self.userip_check_positive = False
        self.is_gta5_process = False
        self.is_rdr2_process = False
        self.is_third_party_server = is_third_party_server_ip(ip)

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
        self.datetime = PlayerDateTime.from_packet_datetime(packet.datetime)
        self.packets = PlayerPackets.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host)
        self.bandwidth = PlayerBandwidth.from_packet_direction(packet_length=packet.length, sent_by_local_host=packet.sent_by_local_host)
        self.ports = PlayerPorts.from_packet_port(packet.port)
        self.joins = [initial_join]

        self.reverse_dns = PlayerReverseDNS()
        self.iplookup = PlayerIPLookup()
        self.ping = PlayerPing()

        self.country_flag = None
        self.userip = None
        self.userip_detection = None
        self.mod_menus = None
        self.looky_system = PlayerLooky()
        self.ps3_username = None

    @property
    def ip(self) -> str:
        """The player's IP address."""
        return self._ip

    def mark_as_seen(self, *, port: int, packet_datetime: datetime_type, packet_length: int, sent_by_local_host: bool) -> None:
        """Update per-player state from an observed packet."""
        self.datetime.last_seen = max(self.datetime.last_seen, packet_datetime)
        self.packets.increment(packet_length=packet_length, sent_by_local_host=sent_by_local_host)
        self.bandwidth.increment(packet_length=packet_length, sent_by_local_host=sent_by_local_host)

        self.ports.add_port(port)

        if self.joins:
            self.joins[-1].mark_as_seen(
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

        if self.joins and self.joins[-1].is_active:
            self.joins[-1].mark_as_left()

        new_join = PlayerJoin(
            join_index=len(self.joins) + 1,
            rejoin_number=self.rejoins,
            joined_at=packet_datetime,
            last_seen=packet_datetime,
            ports=PlayerPorts.from_packet_port(port),
            packets=PlayerPackets.from_packet_direction(packet_length=packet_length, sent_by_local_host=sent_by_local_host),
            bandwidth=PlayerBandwidth.from_packet_direction(packet_length=packet_length, sent_by_local_host=sent_by_local_host),
            is_active=True,
        )
        self.joins.append(new_join)

    def mark_as_left(self) -> None:
        """Mark the player as disconnected and move it to the disconnected registry."""
        self.left_event.set()

        self.datetime.set_session_time()
        self.packets.pps.reset()
        self.packets.ppm.reset()
        self.bandwidth.bps.reset()
        self.bandwidth.bpm.reset()

        if self.joins:
            self.joins[-1].mark_as_left()

        PlayersRegistry.move_player_to_disconnected(self)

    def snapshot(self, *, session_id: int | None = None) -> Self:
        """Create an immutable snapshot clone of this player for a given session."""
        clone = copy.copy(self)
        clone_left_event = Event()
        clone_left_event.set()
        clone.left_event = clone_left_event
        if session_id is not None:
            clone.session_id = session_id
        clone.usernames = list(self.usernames)
        clone.datetime = self.datetime.snapshot()
        clone.packets = self.packets.snapshot()
        clone.bandwidth = self.bandwidth.snapshot()
        clone.ports = self.ports.snapshot()
        clone.joins = list(self.joins)
        return clone
