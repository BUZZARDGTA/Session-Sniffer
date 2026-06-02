"""Player data models for tracking remote players and their session metadata."""

import dataclasses
import time
from dataclasses import dataclass
from datetime import datetime as datetime_type
from threading import Event, Lock
from typing import TYPE_CHECKING, ClassVar, Literal, NamedTuple, Self, override

from PyQt6.QtGui import QIcon, QImage, QPixmap

from session_sniffer.exceptions import PlayerDateTimeCorruptionError
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.warnings import HostingWarnings, MobileWarnings, VPNWarnings
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from datetime import timedelta as timedelta_type

    from session_sniffer.player.userip import UserIP


BANDWIDTH_GB_THRESHOLD = 1_073_741_824  # 1 GB in bytes
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

    exchanged: int = 1

    total_received: int = 0
    received: int = 0
    total_sent: int = 0
    sent: int = 0

    pps: PPS = dataclasses.field(default_factory=PPS)
    ppm: PPM = dataclasses.field(default_factory=PPM)

    @property
    def total_exchanged(self) -> int:
        """Total packets exchanged across all sessions."""
        return self.total_received + self.total_sent

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
                exchanged=1,

                total_received=0,
                received=0,
                total_sent=1,
                sent=1,

                pps=cls.PPS(accumulated_packets=1),
                ppm=cls.PPM(accumulated_packets=1),
            )
        return cls(
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

    exchanged: int = 0

    total_download: int = 0
    download: int = 0
    total_upload: int = 0
    upload: int = 0

    bps: BPS = dataclasses.field(default_factory=BPS)
    bpm: BPM = dataclasses.field(default_factory=BPM)

    @property
    def total_exchanged(self) -> int:
        """Total bytes exchanged across all sessions."""
        return self.total_download + self.total_upload

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
                exchanged=packet_length,

                total_download=0,
                download=0,
                total_upload=packet_length,
                upload=packet_length,

                bps=cls.BPS(accumulated_bytes=packet_length),
                bpm=cls.BPM(accumulated_bytes=packet_length),
            )
        return cls(
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
        if total_bytes >= BANDWIDTH_GB_THRESHOLD:
            return f'{total_bytes / BANDWIDTH_GB_THRESHOLD:.1f} GB'
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

    first_seen: datetime_type
    last_rejoin: datetime_type
    last_seen: datetime_type
    total_session_time: timedelta_type | None
    session_time: timedelta_type | None

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

    def get_session_time(self) -> timedelta_type:
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

    def get_total_session_time(self) -> timedelta_type:
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
    def from_packet_datetime(cls, packet_datetime: datetime_type) -> Self:
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


def _default_ipapi_values() -> dict[str, object]:
    """Return default placeholder values for IP-API lookup fields."""
    return {
        'continent': '...',
        'continent_code': '...',
        'country': '...',
        'country_code': '...',
        'region': '...',
        'region_code': '...',
        'city': '...',
        'district': '...',
        'zip_code': '...',
        'lat': '...',
        'lon': '...',
        'time_zone': '...',
        'offset': '...',
        'currency': '...',
        'org': '...',
        'isp': '...',
        'asn': '...',
        'as_name': '...',
        'mobile': '...',
        'proxy': '...',
        'hosting': '...',
    }


def _default_ping_values() -> dict[str, object]:
    """Return default placeholder values for ping lookup fields."""
    return {
        'is_pinging': '...',
        'ping_times': '...',
        'packets_transmitted': '...',
        'packets_received': '...',
        'packet_duplicates': '...',
        'packet_loss': '...',
        'packet_errors': '...',
        'rtt_min': '...',
        'rtt_avg': '...',
        'rtt_max': '...',
        'rtt_mdev': '...',
    }


@dataclass(kw_only=True, slots=True)
class PlayerIPAPI:  # pylint: disable=too-many-public-methods
    """Store IP-API lookup state and cached values for a player."""

    _FIELD_NAMES: ClassVar[frozenset[str]] = frozenset(_default_ipapi_values())

    is_initialized: bool = False

    _values: dict[str, object] = dataclasses.field(default_factory=_default_ipapi_values)

    def __getattr__(self, name: str) -> object:
        """Provide backward-compatible dotted attribute access for IP-API fields."""
        if name in self._FIELD_NAMES:
            return self._values[name]
        raise AttributeError(name)

    @override
    def __setattr__(self, name: str, value: object) -> None:
        """Provide backward-compatible dotted attribute assignment for IP-API fields."""
        if name in {'is_initialized', '_values'}:
            object.__setattr__(self, name, value)
            return
        if name in self._FIELD_NAMES:
            self._values[name] = value
            return
        object.__setattr__(self, name, value)

    def update_fields(self, data: dict[str, object]) -> None:
        """Batch-update IP-API lookup fields from a pre-validated mapping."""
        self._values.update(data)

    @property
    def continent(self) -> str:
        """Return the continent string from the IP-API lookup result."""
        return str(self._values['continent'])

    @property
    def continent_code(self) -> str:
        """Return the continent code string from the IP-API lookup result."""
        return str(self._values['continent_code'])

    @property
    def country(self) -> str:
        """Return the country string from the IP-API lookup result."""
        return str(self._values['country'])

    @property
    def country_code(self) -> str:
        """Return the country code string from the IP-API lookup result."""
        return str(self._values['country_code'])

    @property
    def region(self) -> str:
        """Return the region string from the IP-API lookup result."""
        return str(self._values['region'])

    @property
    def region_code(self) -> str:
        """Return the region code string from the IP-API lookup result."""
        return str(self._values['region_code'])

    @property
    def city(self) -> str:
        """Return the city string from the IP-API lookup result."""
        return str(self._values['city'])

    @property
    def district(self) -> str:
        """Return the district string from the IP-API lookup result."""
        return str(self._values['district'])

    @property
    def zip_code(self) -> str:
        """Return the ZIP code string from the IP-API lookup result."""
        return str(self._values['zip_code'])

    @property
    def lat(self) -> float | str:
        """Return the latitude from the IP-API lookup result."""
        v = self._values['lat']
        return float(v) if isinstance(v, (int, float)) else str(v)

    @property
    def lon(self) -> float | str:
        """Return the longitude from the IP-API lookup result."""
        v = self._values['lon']
        return float(v) if isinstance(v, (int, float)) else str(v)

    @property
    def time_zone(self) -> str:
        """Return the time zone string from the IP-API lookup result."""
        return str(self._values['time_zone'])

    @property
    def offset(self) -> int | str:
        """Return the UTC offset from the IP-API lookup result."""
        v = self._values['offset']
        return int(v) if isinstance(v, (int, float)) else str(v)

    @property
    def currency(self) -> str:
        """Return the currency string from the IP-API lookup result."""
        return str(self._values['currency'])

    @property
    def org(self) -> str:
        """Return the organization string from the IP-API lookup result."""
        return str(self._values['org'])

    @property
    def as_name(self) -> str:
        """Return the AS name string from the IP-API lookup result."""
        return str(self._values['as_name'])

    @property
    def isp(self) -> str:
        """Return the ISP string from the IP-API lookup result."""
        return str(self._values['isp'])

    @property
    def asn(self) -> str:
        """Return the ASN string from the IP-API lookup result."""
        return str(self._values['asn'])

    @property
    def mobile(self) -> bool | str:
        """Return the mobile flag from the IP-API lookup result."""
        v = self._values['mobile']
        return bool(v) if isinstance(v, bool) else str(v)

    @property
    def proxy(self) -> bool | str:
        """Return the proxy flag from the IP-API lookup result."""
        v = self._values['proxy']
        return bool(v) if isinstance(v, bool) else str(v)

    @property
    def hosting(self) -> bool | str:
        """Return the hosting flag from the IP-API lookup result."""
        v = self._values['hosting']
        return bool(v) if isinstance(v, bool) else str(v)


class PlayerCountryFlag:
    """Hold the rendered country flag assets for a player.

    The QImage is created from a background thread (safe), while QPixmap/QIcon
    are lazily created on first access from the GUI thread (required by Qt).
    """

    __slots__ = ('_icon', '_image', '_pixmap')

    def __init__(self, image: QImage) -> None:
        """Initialize with a QImage (safe to create from any thread)."""
        self._image: QImage = image
        self._pixmap: QPixmap | None = None
        self._icon: QIcon | None = None

    @property
    def pixmap(self) -> QPixmap:
        """Return the QPixmap, creating it lazily (must be called from GUI thread)."""
        if self._pixmap is None:
            self._pixmap = QPixmap.fromImage(self._image)
        return self._pixmap

    @property
    def icon(self) -> QIcon:
        """Return the QIcon, creating it lazily (must be called from GUI thread)."""
        if self._icon is None:
            self._icon = QIcon(self.pixmap)
        return self._icon


@dataclass(kw_only=True, slots=True)
class PlayerIPLookup:
    """Group multiple IP lookup providers for a player."""

    geolite2: PlayerGeoLite2 = dataclasses.field(default_factory=PlayerGeoLite2)
    ipapi: PlayerIPAPI = dataclasses.field(default_factory=PlayerIPAPI)


@dataclass(kw_only=True, slots=True)
class PlayerPing:
    """Store ping lookup state and cached RTT/packet stats for a player."""

    _FIELD_NAMES: ClassVar[frozenset[str]] = frozenset(_default_ping_values())

    is_initialized: bool = False

    _values: dict[str, object] = dataclasses.field(default_factory=_default_ping_values)

    def __getattr__(self, name: str) -> object:
        """Provide backward-compatible dotted attribute access for ping fields."""
        if name in self._FIELD_NAMES:
            return self._values[name]
        raise AttributeError(name)

    @override
    def __setattr__(self, name: str, value: object) -> None:
        """Provide backward-compatible dotted attribute assignment for ping fields."""
        if name in {'is_initialized', '_values'}:
            object.__setattr__(self, name, value)
            return
        if name in self._FIELD_NAMES:
            self._values[name] = value
            return
        object.__setattr__(self, name, value)

    def update_fields(self, data: dict[str, object]) -> None:
        """Batch-update ping lookup fields from a pre-validated mapping."""
        self._values.update(data)


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


@dataclass(kw_only=True, slots=True)
class PlayerLooky:
    """Store Looky System IP-to-player lookup state for a player."""

    is_initialized: bool = False
    needs_refresh: bool = False
    last_fetched_at: float = 0.0
    usernames: list[str] = dataclasses.field(default_factory=list[str])
    rockstarids: list[int] = dataclasses.field(default_factory=list[int])
    lock: Lock = dataclasses.field(default_factory=Lock)


@dataclass(slots=True)
class _PlayerLifecycleState:
    """Runtime lifecycle state for a player."""

    left_event: Event = dataclasses.field(default_factory=Event)
    rejoins: int = 0
    protection_checked: bool = False
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


class PacketInfo(NamedTuple):
    """Bundle the fields from a single observed packet."""

    datetime: datetime_type
    length: int
    port: int
    sent_by_local_host: bool


class Player:
    """Represent a remote player identified by IP and derived session metadata."""

    ip: str
    left_event: Event
    usernames: list[str]
    protection_checked: bool
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

    _LIFECYCLE_FIELDS: ClassVar[frozenset[str]] = frozenset({
        'left_event', 'rejoins', 'protection_checked', 'relay_monitor_started',
        'usernames', 'userip_check_version', 'userip_check_positive',
    })
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
            packets=PlayerPackets.from_packet_direction(sent_by_local_host=packet.sent_by_local_host),
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
        self._traffic.packets.increment(sent_by_local_host=sent_by_local_host)
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
        self.protection_checked = False
        self.relay_monitor_started = False

        self.datetime.accumulate_session_to_total()
        self.datetime.last_rejoin = packet_datetime
        self.datetime.last_seen = packet_datetime
        self.packets.reset_current_session(sent_by_local_host=sent_by_local_host)
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
