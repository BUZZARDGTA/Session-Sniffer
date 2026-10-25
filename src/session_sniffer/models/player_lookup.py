"""Lookup and external metadata tracking data structures for a player."""

import dataclasses
import time
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from typing import TYPE_CHECKING, Literal

from PySide6.QtGui import QIcon, QImage, QPixmap

if TYPE_CHECKING:
    from collections.abc import Sequence

    from session_sniffer.models.looky_system import LookyPlayer
    from session_sniffer.networking.endpoint_ping_manager import PingResult


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

    is_initialized: bool = False

    is_pinging: bool | str = '...'
    ping_times: list[float] | str = '...'
    packets_transmitted: int | str | None = '...'
    packets_received: int | str | None = '...'
    packet_duplicates: int | str | None = '...'
    packet_loss: float | str | None = '...'
    packet_errors: int | str | None = '...'
    rtt_min: float | str | None = '...'
    rtt_avg: float | str | None = '...'
    rtt_max: float | str | None = '...'
    rtt_mdev: float | str | None = '...'

    def update_fields(self, data: dict[str, object]) -> None:
        """Batch-update ping lookup fields from a pre-validated mapping."""
        for key, value in data.items():
            setattr(self, key, value)

    def apply_result(self, ping_result: PingResult) -> None:
        """Update ping fields, pinging status, and initialization state from *ping_result*."""
        self.update_fields(ping_result._asdict())
        self.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
        self.is_initialized = True


@dataclass(kw_only=True, slots=True)
class PlayerUserIPDetection:
    """Store user-IP detection metadata for a player."""

    time: str
    date_time: str

    as_processed_task: bool = True
    type: Literal['Static IP', 'Username'] = 'Static IP'


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
    as_userip_checked: bool = False
    last_fetched_at: float = 0.0
    usernames: list[str] = dataclasses.field(default_factory=list[str])
    rockstarids: list[int] = dataclasses.field(default_factory=list[int])
    last_seens: list[datetime] = dataclasses.field(default_factory=list[datetime])
    lock: Lock = dataclasses.field(default_factory=Lock)

    def mark_fetched(self) -> None:
        """Mark the lookup state as initialized and recently fetched under the lock."""
        with self.lock:
            self.needs_refresh = False
            self.last_fetched_at = time.monotonic()
            self.is_initialized = True

    def apply_results(self, results: Sequence[LookyPlayer], *, force_reset_userip_checked: bool = False) -> list[LookyPlayer]:
        """Deduplicate *results* by `(name, rockstarid)` and update the lookup fields under the lock."""
        unique_results: list[LookyPlayer] = []
        seen_pairs: set[tuple[str, int]] = set()
        for entry in results:
            pair = (entry.name, entry.rockstarid)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                unique_results.append(entry)
        new_usernames = [entry.name.strip() for entry in unique_results if entry.name and entry.name.strip()]
        with self.lock:
            if force_reset_userip_checked or new_usernames != self.usernames:
                self.as_userip_checked = False
            self.usernames = new_usernames
            self.rockstarids = [entry.rockstarid for entry in unique_results]
            self.last_seens = [entry.last_seen for entry in unique_results]
            self.needs_refresh = False
            self.last_fetched_at = time.monotonic()
            self.is_initialized = True
        return unique_results
