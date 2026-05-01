"""Type definitions for the rendering core and GUI update payloads."""

from collections import deque
from dataclasses import dataclass
from threading import Condition, Lock
from typing import TYPE_CHECKING, ClassVar, NamedTuple

from PyQt6.QtGui import QColor

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    import geoip2.database

_MAX_LATENCY_ENTRIES = 5000


class PaginationState:
    """Thread-safe pagination state shared between the GUI and the worker thread."""

    _lock: ClassVar[Lock] = Lock()
    _connected_rows_per_page: ClassVar[int] = 0
    _disconnected_rows_per_page: ClassVar[int] = 0
    _connected_page: ClassVar[int] = 1
    _disconnected_page: ClassVar[int] = 1

    @classmethod
    def set_connected(cls, *, rows_per_page: int, page: int) -> None:
        """Set connected-table pagination state."""
        with cls._lock:
            cls._connected_rows_per_page = rows_per_page
            cls._connected_page = page

    @classmethod
    def set_disconnected(cls, *, rows_per_page: int, page: int) -> None:
        """Set disconnected-table pagination state."""
        with cls._lock:
            cls._disconnected_rows_per_page = rows_per_page
            cls._disconnected_page = page

    @classmethod
    def set_connected_page(cls, page: int) -> None:
        """Set only the connected-table current page."""
        with cls._lock:
            cls._connected_page = page

    @classmethod
    def set_disconnected_page(cls, page: int) -> None:
        """Set only the disconnected-table current page."""
        with cls._lock:
            cls._disconnected_page = page

    @classmethod
    def get(cls) -> tuple[int, int, int, int]:
        """Return (connected_rows_per_page, connected_page, disconnected_rows_per_page, disconnected_page)."""
        with cls._lock:
            return (
                cls._connected_rows_per_page,
                cls._connected_page,
                cls._disconnected_rows_per_page,
                cls._disconnected_page,
            )


class CaptureState:  # pylint: disable=too-few-public-methods
    """Runtime state derived from the active capture interface."""
    vpn_mode_enabled: ClassVar[bool] = False
    is_arp_interface: ClassVar[bool] = False


class TsharkStats:  # pylint: disable=too-few-public-methods
    """Statistics and data tracking for TShark packet capture performance."""
    packets_latencies: ClassVar[deque[tuple[datetime, timedelta]]] = deque(maxlen=_MAX_LATENCY_ENTRIES)
    restarted_times: ClassVar[int] = 0
    global_bandwidth: ClassVar[int] = 0
    global_download: ClassVar[int] = 0
    global_upload: ClassVar[int] = 0
    global_bps_rate: ClassVar[int] = 0
    global_pps_rate: ClassVar[int] = 0


class CellColor(NamedTuple):
    """Hold foreground and background colors for a table cell."""
    foreground: QColor
    background: QColor


class SessionTableSnapshot(NamedTuple):
    """Immutable snapshot of connected/disconnected table rows + cell colors."""
    connected_num: int
    connected_rows: tuple[tuple[str, ...], ...]
    connected_colors: tuple[tuple[CellColor, ...], ...]
    disconnected_num: int
    disconnected_rows: tuple[tuple[str, ...], ...]
    disconnected_colors: tuple[tuple[CellColor, ...], ...]


class GUIUpdatePayload(NamedTuple):
    """Payload containing all data needed for GUI updates."""
    snapshot_version: int
    column_config: GUIColumnConfig
    header_text: str
    status_capture_text: str
    status_config_text: str
    status_issues_text: str
    status_performance_text: str
    connected_rows_with_colors: list[tuple[list[str], list[CellColor]]]
    disconnected_rows_with_colors: list[tuple[list[str], list[CellColor]]]
    connected_num: int
    disconnected_num: int
    connected_rows_per_page: int
    disconnected_rows_per_page: int
    connected_page: int
    disconnected_page: int
    connected_total_pages: int
    disconnected_total_pages: int


@dataclass(frozen=True, slots=True)
class GUIColumnConfig:
    """Column visibility and name config for both tables."""
    connected_shown_columns: set[str]
    disconnected_shown_columns: set[str]
    connected_column_names: list[str]
    disconnected_column_names: list[str]


@dataclass(frozen=True, slots=True)
class GUIStatusTexts:
    """Header and status-bar text strings for the GUI."""
    header_text: str
    status_capture_text: str
    status_config_text: str
    status_issues_text: str
    status_performance_text: str


@dataclass(frozen=True, slots=True)
class GUITableData:
    """Row/color data for a single session table (connected or disconnected)."""
    num_cols: int
    num_rows: int
    rows: tuple[tuple[str, ...], ...]
    colors: tuple[tuple[CellColor, ...], ...]


@dataclass(frozen=True, slots=True)
class GUIRenderingSnapshot:
    """A single published GUI rendering snapshot.

    Built off-thread, then published by replacement (no shared mutation).
    """
    column_config: GUIColumnConfig
    status: GUIStatusTexts
    connected: GUITableData
    disconnected: GUITableData


class GUIRenderingState:
    """Atomically published rendering state using a version counter and Condition for multi-consumer waits."""

    _lock: ClassVar[Lock] = Lock()
    _condition: ClassVar[Condition] = Condition(_lock)
    _current: ClassVar[GUIRenderingSnapshot | None] = None
    _version: ClassVar[int] = 0  # Incremented each time a new snapshot is published

    @classmethod
    def publish_rendering_snapshot(cls, snapshot: GUIRenderingSnapshot) -> None:
        """Publish a fully-built snapshot by replacement."""
        with cls._condition:
            if cls._current is snapshot:  # Early exit if nothing changed
                return

            cls._current = snapshot
            cls._version += 1
            cls._condition.notify_all()  # wake all consumers only if snapshot changed

    @classmethod
    def wait_rendering_snapshot(
        cls,
        *,
        timeout: float,
        last_seen_version: int = 0,
    ) -> tuple[GUIRenderingSnapshot | None, int]:
        """Wait for a new snapshot if it's newer than last_seen_version.

        Returns:
            Tuple of (snapshot, version). Snapshot is None if timeout occurs.
        """
        with cls._condition:
            if not cls._condition.wait_for(
                lambda: cls._version != last_seen_version,
                timeout=timeout,
            ):
                return None, last_seen_version

            return cls._current, cls._version

    @classmethod
    def get_version(cls) -> int:
        """Return the current snapshot version in a thread-safe manner."""
        with cls._condition:
            return cls._version


@dataclass(frozen=True, slots=True)
class GeoIP2Readers:
    """Container for GeoIP2 database readers."""
    enabled: bool
    asn_reader: geoip2.database.Reader | None
    city_reader: geoip2.database.Reader | None
    country_reader: geoip2.database.Reader | None
