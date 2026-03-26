"""Player data models for tracking remote players and their session metadata."""

import dataclasses
import time
from dataclasses import dataclass
from threading import Event, Thread
from typing import TYPE_CHECKING, Literal, NamedTuple, Self

from session_sniffer.exceptions import PlayerDateTimeCorruptionError

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from PyQt6.QtGui import QIcon, QPixmap

    from session_sniffer.player.userip import UserIP


BANDWIDTH_MB_THRESHOLD = 1_048_576  # 1 MB in bytes
BANDWIDTH_KB_THRESHOLD = 1024  # 1 KB in bytes


@dataclass(kw_only=True, slots=True)
class PlayerReverseDNS:
    """Store reverse DNS lookup state for a player."""

    is_initialized: bool = False

    hostname: str = '...'


@dataclass(kw_only=True, slots=True)
class PlayerPackets:
    """Class to manage player packet counts and statistics.

    Attributes:
        total_exchanged: Total packets exchanged with the player across all sessions.
        exchanged: Packets exchanged with the player in current session (received + sent).
        total_received: Total packets received from the player across all sessions.
        received: Packets received from the player in current session.
        total_sent: Total packets sent to the player across all sessions.
        sent: Packets sent to the player in current session.
        pps: Packets Per Second rate calculator.
        ppm: Packets Per Minute rate calculator.
    """

    @dataclass(kw_only=True, slots=True)
    class PPS:
        """Class to manage player Packets Per Second (PPS) calculations.

        Attributes:
            is_first_calculation: True until the first rate calculation completes.
            last_update_time: Timestamp of the last rate calculation.
            accumulated_packets: Number of packets counted since last calculation.
            calculated_rate: The final PPS value to display (Packets Per Second).
        """
        is_first_calculation: bool = True
        last_update_time: float = dataclasses.field(default_factory=time.monotonic)
        accumulated_packets: int = 0
        calculated_rate: int = 0

        def calculate_and_update_rate(self) -> None:
            """Calculate rate from accumulated packets and reset counter."""
            self.is_first_calculation = False
            self.calculated_rate = self.accumulated_packets
            self.accumulated_packets = 0
            self.last_update_time = time.monotonic()

        def reset(self) -> None:
            """Resets the PlayerPPS to its initial state."""
            self.is_first_calculation = True
            self.last_update_time = time.monotonic()
            self.accumulated_packets = 0
            self.calculated_rate = 0

    @dataclass(kw_only=True, slots=True)
    class PPM:
        """Class to manage player Packets Per Minute (PPM) calculations.

        Attributes:
            is_first_calculation: True until the first rate calculation completes.
            last_update_time: Timestamp of the last rate calculation.
            accumulated_packets: Number of packets counted since last calculation.
            calculated_rate: The final PPM value to display (Packets Per Minute).
        """
        is_first_calculation: bool = True
        last_update_time: float = dataclasses.field(default_factory=time.monotonic)
        accumulated_packets: int = 0
        calculated_rate: int = 0

        def calculate_and_update_rate(self) -> None:
            """Calculate rate from accumulated packets and reset counter."""
            self.is_first_calculation = False
            self.calculated_rate = self.accumulated_packets
            self.accumulated_packets = 0
            self.last_update_time = time.monotonic()

        def reset(self) -> None:
            """Resets the PlayerPPM to its initial state."""
            self.is_first_calculation = True
            self.last_update_time = time.monotonic()
            self.accumulated_packets = 0
            self.calculated_rate = 0

    total_exchanged: int = 1
    exchanged: int = 1

    total_received: int = 0
    received: int = 0
    total_sent: int = 0
    sent: int = 0

    pps: PPS = dataclasses.field(default_factory=PPS)
    ppm: PPM = dataclasses.field(default_factory=PPM)

    @classmethod
    def from_packet_direction(cls, *, sent_by_local_host: bool) -> Self:
        """Create `PlayerPackets` from initial packet direction.

        Args:
            sent_by_local_host: Whether the initial packet was sent by local host

        Returns:
            New instance initialized for the packet direction.
        """
        if sent_by_local_host:
            return cls(
                total_exchanged=1,
                exchanged=1,

                total_received=0,
                received=0,
                total_sent=1,
                sent=1,

                pps=cls.PPS(accumulated_packets=1),
                ppm=cls.PPM(accumulated_packets=1),
            )
        return cls(
            total_exchanged=1,
            exchanged=1,

            total_received=1,
            received=1,
            total_sent=0,
            sent=0,

            pps=cls.PPS(accumulated_packets=1),
            ppm=cls.PPM(accumulated_packets=1),
        )

    def increment(self, *, sent_by_local_host: bool) -> None:
        """Increment packet counts based on packet direction.

        Args:
            sent_by_local_host: Whether the packet was sent by local host
        """
        self.total_exchanged += 1
        self.exchanged += 1

        if sent_by_local_host:
            self.total_sent += 1
            self.sent += 1
        else:
            self.total_received += 1
            self.received += 1

        self.pps.accumulated_packets += 1
        self.ppm.accumulated_packets += 1

    def reset_current_session(self, *, sent_by_local_host: bool) -> None:
        """Reset current session packet counts (for rejoins).

        Args:
            sent_by_local_host: Whether the rejoin packet was sent by local host
        """
        self.total_exchanged += 1
        self.exchanged = 1

        if sent_by_local_host:
            self.total_sent += 1
            self.sent = 1
            self.received = 0
        else:
            self.sent = 0
            self.total_received += 1
            self.received = 1

        self.pps.reset()
        self.pps.accumulated_packets = 1
        self.ppm.reset()
        self.ppm.accumulated_packets = 1


@dataclass(kw_only=True, slots=True)
class PlayerBandwidth:
    """Class to manage player bandwidth (upload/download) totals and rate calculations.

    Attributes:
        total_exchanged: Total bytes exchanged with the player across all sessions.
        exchanged: Bytes exchanged with the player in current session (download + upload).
        total_download: Total bytes downloaded from the player across all sessions.
        download: Bytes downloaded from the player in current session.
        total_upload: Total bytes uploaded to the player across all sessions.
        upload: Bytes uploaded to the player in current session.
        bps: Bytes Per Second rate calculator.
        bpm: Bytes Per Minute rate calculator.
    """

    @dataclass(kw_only=True, slots=True)
    class BPS:
        """Class to manage player Bytes Per Second (BPS) calculations.

        Attributes:
            is_first_calculation: True until the first rate calculation completes.
            last_update_time: Timestamp of the last rate calculation.
            accumulated_bytes: Number of bytes counted since last calculation.
            calculated_rate: The final BPS value to display (Bytes Per Second).
        """
        is_first_calculation: bool = True
        last_update_time: float = dataclasses.field(default_factory=time.monotonic)
        accumulated_bytes: int = 0
        calculated_rate: int = 0

        def calculate_and_update_rate(self) -> None:
            """Calculate rate from accumulated bytes and reset counter."""
            self.is_first_calculation = False
            self.calculated_rate = self.accumulated_bytes
            self.accumulated_bytes = 0
            self.last_update_time = time.monotonic()

        def reset(self) -> None:
            """Resets the BPS to its initial state."""
            self.is_first_calculation = True
            self.last_update_time = time.monotonic()
            self.accumulated_bytes = 0
            self.calculated_rate = 0

    @dataclass(kw_only=True, slots=True)
    class BPM:
        """Class to manage player Bytes Per Minute (BPM) calculations.

        Attributes:
            is_first_calculation: True until the first rate calculation completes.
            last_update_time: Timestamp of the last rate calculation.
            accumulated_bytes: Number of bytes counted since last calculation.
            calculated_rate: The final BPM value to display (Bytes Per Minute).
        """
        is_first_calculation: bool = True
        last_update_time: float = dataclasses.field(default_factory=time.monotonic)
        accumulated_bytes: int = 0
        calculated_rate: int = 0

        def calculate_and_update_rate(self) -> None:
            """Calculate rate from accumulated bytes and reset counter."""
            self.is_first_calculation = False
            self.calculated_rate = self.accumulated_bytes
            self.accumulated_bytes = 0
            self.last_update_time = time.monotonic()

        def reset(self) -> None:
            """Resets the BPM to its initial state."""
            self.is_first_calculation = True
            self.last_update_time = time.monotonic()
            self.accumulated_bytes = 0
            self.calculated_rate = 0

    total_exchanged: int = 0
    exchanged: int = 0

    total_download: int = 0
    download: int = 0
    total_upload: int = 0
    upload: int = 0

    bps: BPS = dataclasses.field(default_factory=BPS)
    bpm: BPM = dataclasses.field(default_factory=BPM)

    @classmethod
    def from_packet_direction(cls, *, packet_length: int, sent_by_local_host: bool) -> Self:
        """Create `PlayerBandwidth` from initial packet direction.

        Args:
            packet_length: The length of the initial packet in bytes
            sent_by_local_host: Whether the initial packet was sent by local host

        Returns:
            New instance initialized for the packet direction.
        """
        if sent_by_local_host:
            return cls(
                total_exchanged=packet_length,
                exchanged=packet_length,

                total_download=0,
                download=0,
                total_upload=packet_length,
                upload=packet_length,

                bps=cls.BPS(accumulated_bytes=packet_length),
                bpm=cls.BPM(accumulated_bytes=packet_length),
            )
        return cls(
            total_exchanged=packet_length,
            exchanged=packet_length,

            total_download=packet_length,
            download=packet_length,
            total_upload=0,
            upload=0,

            bps=cls.BPS(accumulated_bytes=packet_length),
            bpm=cls.BPM(accumulated_bytes=packet_length),
        )

    def increment(self, *, packet_length: int, sent_by_local_host: bool) -> None:
        """Increment bandwidth counts based on packet direction.

        Args:
            packet_length: The length of the packet in bytes
            sent_by_local_host: Whether the packet was sent by local host
        """
        self.total_exchanged += packet_length
        self.exchanged += packet_length

        if sent_by_local_host:
            self.total_upload += packet_length
            self.upload += packet_length
        else:
            self.total_download += packet_length
            self.download += packet_length

        self.bps.accumulated_bytes += packet_length
        self.bpm.accumulated_bytes += packet_length

    def reset_current_session(self, *, packet_length: int, sent_by_local_host: bool) -> None:
        """Reset current session bandwidth counts (for rejoins).

        Args:
            packet_length: The length of the rejoin packet in bytes
            sent_by_local_host: Whether the rejoin packet was sent by local host
        """
        self.total_exchanged += packet_length
        self.exchanged = packet_length

        if sent_by_local_host:
            self.total_upload += packet_length
            self.upload = packet_length
            self.download = 0
        else:
            self.total_download += packet_length
            self.upload = 0
            self.download = packet_length

        self.bps.reset()
        self.bps.accumulated_bytes = packet_length
        self.bpm.reset()
        self.bpm.accumulated_bytes = packet_length

    @staticmethod
    def format_bytes(total_bytes: int) -> str:
        """Format bytes to human-readable string."""
        if total_bytes >= BANDWIDTH_MB_THRESHOLD:
            return f'{total_bytes / BANDWIDTH_MB_THRESHOLD:.1f} MB'
        if total_bytes >= BANDWIDTH_KB_THRESHOLD:
            return f'{total_bytes / BANDWIDTH_KB_THRESHOLD:.1f} KB'
        return f'{total_bytes} B'


@dataclass(kw_only=True, slots=True)
class PlayerPorts:
    """Track observed ports for a player within a session."""

    all: list[int]
    first: int
    middle: list[int]
    last: int

    @classmethod
    def from_packet_port(cls, port: int) -> Self:
        """Create a new ports tracker from the first observed port."""
        return cls(
            all=[port],
            first=port,
            middle=[],
            last=port,
        )

    def reset(self, port: int) -> None:
        """Reset tracked ports back to a single observed port."""
        self.all.clear()
        self.all.append(port)
        self.first = port
        self.middle.clear()
        self.last = port


@dataclass(kw_only=True, slots=True)
class PlayerDateTime:
    """Track per-player timestamps and compute session durations."""

    first_seen: datetime
    last_rejoin: datetime
    last_seen: datetime
    total_session_time: timedelta | None
    session_time: timedelta | None

    def set_session_time(self) -> None:
        """Finalize and store the session duration.

        Calculates the duration between when the player last joined and was last seen,
        then stores it. Called when a player disconnects to freeze their session duration.
        """
        self.session_time = self.last_seen - self.last_rejoin

    def accumulate_session_to_total(self) -> None:
        """Add finalized session duration to the cumulative total and clear current session.

        Transfers the completed session duration into the running total across all sessions,
        then clears the current session duration to prepare for tracking a new session.
        Only accumulates if a session has been finalized.
        """
        if self.session_time is not None:
            if self.total_session_time is None:
                self.total_session_time = self.session_time
            else:
                self.total_session_time += self.session_time
            self.session_time = None

    def get_session_time(self) -> timedelta:
        """Return current session duration.

        Returns:
            The session duration. For disconnected players, returns the stored
                duration from their last session. For connected players, calculates the
                live duration from when they joined until their last activity.
        """
        if self.last_rejoin > self.last_seen:
            raise PlayerDateTimeCorruptionError(str(self.last_rejoin), str(self.last_seen))
        if self.session_time is None:
            return self.last_seen - self.last_rejoin
        return self.session_time

    def get_total_session_time(self) -> timedelta:
        """Return total cumulative session duration across all sessions.

        Returns:
            Sum of all completed sessions plus the current session.
                For connected players, includes their ongoing session time.
                For disconnected players, includes their completed final session.
        """
        if self.last_rejoin > self.last_seen:
            raise PlayerDateTimeCorruptionError(str(self.last_rejoin), str(self.last_seen))
        if self.total_session_time is None:
            if self.session_time is None:
                return self.last_seen - self.last_rejoin
            return self.session_time
        if self.session_time is None:
            return self.total_session_time + (self.last_seen - self.last_rejoin)
        return self.total_session_time + self.session_time

    @classmethod
    def from_packet_datetime(cls, packet_datetime: datetime) -> Self:
        """Create a PlayerDateTime instance from a packet timestamp.

        Args:
            packet_datetime: The timestamp of the first packet from the player.

        Returns:
            New instance initialized with packet timestamp values.
        """
        return cls(
            first_seen=packet_datetime,
            last_rejoin=packet_datetime,
            last_seen=packet_datetime,
            total_session_time=None,
            session_time=None,
        )


@dataclass(kw_only=True, slots=True)
class PlayerGeoLite2:
    """Store GeoLite2 lookup state and cached values for a player."""

    is_initialized: bool = False

    country: str = '...'
    country_code: str = '...'
    city: str = '...'
    asn: str = '...'


@dataclass(kw_only=True, slots=True)
class PlayerIPAPI:
    """Store IP-API lookup state and cached values for a player."""

    is_initialized: bool = False

    continent: str = '...'
    continent_code: str = '...'
    country: str = '...'
    country_code: str = '...'
    region: str = '...'
    region_code: str = '...'
    city: str = '...'
    district: str = '...'
    zip_code: str = '...'
    lat: Literal['...', 'N/A'] | float | int = '...'
    lon: Literal['...', 'N/A'] | float | int = '...'
    time_zone: str = '...'
    offset: Literal['...', 'N/A'] | int = '...'
    currency: str = '...'
    org: str = '...'
    isp: str = '...'
    asn: str = '...'
    as_name: str = '...'
    mobile: Literal['...', 'N/A'] | bool = '...'
    proxy: Literal['...', 'N/A'] | bool = '...'
    hosting: Literal['...', 'N/A'] | bool = '...'


class PlayerCountryFlag(NamedTuple):
    """Hold the rendered country flag assets for a player."""

    pixmap: QPixmap
    icon: QIcon


@dataclass(kw_only=True, slots=True)
class PlayerIPLookup:
    """Group multiple IP lookup providers for a player."""

    geolite2: PlayerGeoLite2 = dataclasses.field(default_factory=PlayerGeoLite2)
    ipapi: PlayerIPAPI = dataclasses.field(default_factory=PlayerIPAPI)


@dataclass(kw_only=True, slots=True)
class PlayerPing:
    """Store ping lookup state and cached RTT/packet stats for a player."""

    is_initialized: bool = False

    is_pinging: Literal['...'] | bool = '...'
    ping_times: Literal['...'] | list[float] = '...'
    packets_transmitted: Literal['...'] | int | None = '...'
    packets_received: Literal['...'] | int | None = '...'
    packet_duplicates: Literal['...'] | int | None = '...'
    packet_loss: Literal['...'] | float | None = '...'
    packet_errors: Literal['...'] | int | None = '...'
    rtt_min: Literal['...'] | float | None = '...'
    rtt_avg: Literal['...'] | float | None = '...'
    rtt_max: Literal['...'] | float | None = '...'
    rtt_mdev: Literal['...'] | float | None = '...'


@dataclass(kw_only=True, slots=True)
class PlayerUserIPDetection:
    """Store user-IP detection metadata for a player."""

    time: str
    date_time: str

    as_processed_task: bool = True
    type: Literal['Static IP'] = 'Static IP'


def _empty_usernames() -> list[str]:
    """Return a typed empty usernames list for dataclass defaults."""
    return []


@dataclass(kw_only=True, slots=True)
class PlayerModMenus:
    """Store parsed mod menu usernames associated with a player."""

    usernames: list[str] = dataclasses.field(default_factory=_empty_usernames)


class Player:
    """Represent a remote player identified by IP and derived session metadata."""

    def __init__(self, *, ip: str, packet_datetime: datetime, packet_length: int, port: int, sent_by_local_host: bool) -> None:  # pylint: disable=too-many-arguments
        """Initialize a `Player` from the first observed packet.

        Args:
            ip: The player's IP address.
            packet_datetime: Timestamp of the packet used to create the player.
            packet_length: Length of the packet in bytes.
            port: Source/destination port observed for the player.
            sent_by_local_host: Whether the packet direction is from the local host.
        """
        self.ip = ip
        self.left_event = Event()
        self.rejoins = 0
        self.usernames: list[str] = []

        self.datetime = PlayerDateTime.from_packet_datetime(packet_datetime)
        self.packets = PlayerPackets.from_packet_direction(sent_by_local_host=sent_by_local_host)
        self.bandwidth = PlayerBandwidth.from_packet_direction(packet_length=packet_length, sent_by_local_host=sent_by_local_host)
        self.ports = PlayerPorts.from_packet_port(port)
        self.reverse_dns = PlayerReverseDNS()
        self.iplookup = PlayerIPLookup()
        self.ping = PlayerPing()

        self.country_flag: PlayerCountryFlag | None = None
        self.userip: UserIP | None = None
        self.userip_detection: PlayerUserIPDetection | None = None
        self.mod_menus: PlayerModMenus | None = None

    def mark_as_seen(self, *, port: int, packet_datetime: datetime, packet_length: int, sent_by_local_host: bool) -> None:
        """Update per-player state from an observed packet."""
        self.datetime.last_seen = packet_datetime
        self.packets.increment(sent_by_local_host=sent_by_local_host)
        self.bandwidth.increment(packet_length=packet_length, sent_by_local_host=sent_by_local_host)

        if port != self.ports.last:
            if port not in self.ports.all:
                self.ports.all.append(port)

            if port in self.ports.middle:
                self.ports.middle.remove(port)

            if self.ports.last not in self.ports.middle and self.ports.last != self.ports.first:
                self.ports.middle.append(self.ports.last)

            self.ports.last = port

    def mark_as_rejoined(self, *, packet_datetime: datetime, packet_length: int, port: int, sent_by_local_host: bool) -> None:
        """Handle a player rejoin by resetting current-session counters."""
        from session_sniffer.settings import Settings  # noqa: PLC0415

        self.left_event.clear()
        self.rejoins += 1

        self.datetime.accumulate_session_to_total()
        self.datetime.last_rejoin = packet_datetime
        self.datetime.last_seen = packet_datetime
        self.packets.reset_current_session(sent_by_local_host=sent_by_local_host)
        self.bandwidth.reset_current_session(packet_length=packet_length, sent_by_local_host=sent_by_local_host)

        if Settings.GUI_RESET_PORTS_ON_REJOINS:
            self.ports.reset(port)

    def mark_as_left(self) -> None:
        """Mark the player as disconnected and move it to the disconnected registry."""
        from session_sniffer.background.tasks import process_userip_task  # noqa: PLC0415
        from session_sniffer.player.registry import PlayersRegistry  # noqa: PLC0415
        from session_sniffer.player.warnings import HostingWarnings, MobileWarnings, VPNWarnings  # noqa: PLC0415

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

        if self.userip_detection and self.userip_detection.as_processed_task:
            self.userip_detection.as_processed_task = False
            Thread(
                target=process_userip_task,
                name=f'ProcessUserIPTask-{self.ip}-disconnected',
                args=(self, 'disconnected'), daemon=True,
            ).start()
