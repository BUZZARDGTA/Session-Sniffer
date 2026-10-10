"""Lookup and external metadata tracking data structures for a player."""

import dataclasses
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from typing import ClassVar, Literal, override

from PySide6.QtGui import QIcon, QImage, QPixmap


@dataclass(kw_only=True, slots=True)
class PlayerReverseDNS:
    """Store reverse DNS lookup state for a player."""

    is_initialized: bool = False

    hostname: str = '...'


@dataclass(kw_only=True, slots=True)
class PlayerGeoLite2:
    """Store GeoLite2 lookup state and cached values for a player."""

    is_initialized: bool = False

    country: str = '...'
    country_code: str = '...'
    city: str = '...'
    asn: str = '...'


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
    lat: float | str = '...'
    lon: float | str = '...'
    time_zone: str = '...'
    offset: int | str = '...'
    currency: str = '...'
    org: str = '...'
    isp: str = '...'
    asn: str = '...'
    as_name: str = '...'
    mobile: bool | str = '...'
    proxy: bool | str = '...'
    hosting: bool | str = '...'

    def update_fields(self, data: dict[str, object]) -> None:
        """Batch-update IP-API lookup fields from a pre-validated mapping."""
        for key, value in data.items():
            setattr(self, key, value)


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
    last_seens: list[datetime] = dataclasses.field(default_factory=list[datetime])
    lock: Lock = dataclasses.field(default_factory=Lock)
