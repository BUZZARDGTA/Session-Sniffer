"""Type definitions for the rendering core and GUI update payloads."""

from collections import deque
from dataclasses import dataclass
from threading import Condition, Lock
from typing import TYPE_CHECKING, ClassVar, NamedTuple

from PyQt6.QtGui import QColor

from session_sniffer.networking.interface import INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_SHARING
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from datetime import datetime, timedelta
    from pathlib import Path

    import geoip2.database

    from session_sniffer.gta5.process import GTA5Status

_MAX_LATENCY_ENTRIES = 3600  # default; resized to Settings.gui_rate_graph_max_history after startup


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


class SearchState:
    """Thread-safe search filter text and column shared between the GUI and the worker thread."""

    _lock: ClassVar[Lock] = Lock()
    _connected_text: ClassVar[str] = ''
    _disconnected_text: ClassVar[str] = ''
    _connected_col: ClassVar[int] = -1  # -1 = all columns
    _disconnected_col: ClassVar[int] = -1
    _version: ClassVar[int] = 0

    @classmethod
    def set_connected(cls, text: str, column: int) -> None:
        """Update the connected-table search text and column, then bump the version."""
        with cls._lock:
            cls._connected_text = text
            cls._connected_col = column
            cls._version += 1

    @classmethod
    def set_disconnected(cls, text: str, column: int) -> None:
        """Update the disconnected-table search text and column, then bump the version."""
        with cls._lock:
            cls._disconnected_text = text
            cls._disconnected_col = column
            cls._version += 1

    @classmethod
    def get(cls) -> tuple[str, int, str, int, int]:
        """Return (connected_text, connected_col, disconnected_text, disconnected_col, version)."""
        with cls._lock:
            return cls._connected_text, cls._connected_col, cls._disconnected_text, cls._disconnected_col, cls._version


class CaptureState:
    """Runtime state derived from the active capture interface."""

    vpn_mode_enabled: ClassVar[bool] = False
    is_neighbour_interface: ClassVar[bool] = False
    interface_name: ClassVar[str] = ''
    interface_ip: ClassVar[str] = ''
    interface_type: ClassVar[str] = ''
    discord_rpc_connected: ClassVar[bool] = False
    gta5_is_running: ClassVar[bool] = False
    gta5_is_enhanced: ClassVar[bool] = False
    gta5_is_legacy: ClassVar[bool] = False
    gta5_just_started: ClassVar[bool] = False
    gta5_path: ClassVar[Path | None] = None
    gta5_pid: ClassVar[int | None] = None
    gta5_is_suspended: ClassVar[bool] = False

    @classmethod
    def apply_interface_names(cls, *, is_neighbour: bool, name: str, ip: str, interface_type: str) -> None:
        """Set the four interface-identity fields atomically."""
        cls.is_neighbour_interface = is_neighbour
        cls.interface_name = name
        cls.interface_ip = ip
        cls.interface_type = interface_type

    @classmethod
    def is_local_capture(cls) -> bool:
        """Return `True` when the capture targets traffic from this machine.

        Local capture allows GTA5 process control and other local-process actions.
        Returns `False` when ARP spoofing is enabled, a neighbour adapter is selected,
        or the interface is a bridged/sharing adapter (each of which captures another
        machine's traffic). `Shared` is treated as local — it captures this host's traffic.
        """
        return not (Settings.capture_arp_spoofing or cls.is_neighbour_interface or cls.interface_type in (INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_SHARING))

    @classmethod
    def update_gta5_status(cls, status: GTA5Status) -> None:
        """Update GTA5 running/suspended state and set `gta5_just_started` on the first detected launch."""
        if status.is_running and not cls.gta5_is_running:
            cls.gta5_just_started = True
        cls.gta5_is_running = status.is_running
        cls.gta5_is_enhanced = status.is_enhanced
        cls.gta5_is_legacy = status.is_legacy
        cls.gta5_path = status.path
        cls.gta5_pid = status.pid
        cls.gta5_is_suspended = status.is_suspended


class CaptureStats:
    """Statistics and data tracking for packet capture performance."""

    packets_latencies: ClassVar[deque[tuple[datetime, timedelta]]] = deque(maxlen=_MAX_LATENCY_ENTRIES)
    capture_health_samples: ClassVar[deque[tuple[float, int, int]]] = deque(maxlen=_MAX_LATENCY_ENTRIES)
    total_packets_captured: ClassVar[int] = 0
    capture_started_at: ClassVar[float] = 0.0
    restarted_times: ClassVar[int] = 0
    global_bandwidth: ClassVar[int] = 0
    global_download: ClassVar[int] = 0
    global_upload: ClassVar[int] = 0
    global_bps_rate: ClassVar[int] = 0
    global_bpm_rate: ClassVar[int] = 0
    global_pps_rate: ClassVar[int] = 0
    global_avg_latency_ms: ClassVar[float] = 0.0
    app_cpu_percent: ClassVar[float] = 0.0
    app_memory_mb: ClassVar[float] = 0.0
    app_disk_read_rate_mb: ClassVar[float] = 0.0
    app_disk_write_rate_mb: ClassVar[float] = 0.0
    app_disk_read_total_mb: ClassVar[float] = 0.0
    app_disk_write_total_mb: ClassVar[float] = 0.0
    packets_dropped: ClassVar[int] = 0
    peak_bps_rate: ClassVar[int] = 0
    peak_bpm_rate: ClassVar[int] = 0
    peak_pps_rate: ClassVar[int] = 0

    @classmethod
    def resize_history_deques(cls, maxlen: int) -> None:
        """Replace the history deques with new ones sized to `maxlen`."""
        cls.packets_latencies = deque(maxlen=maxlen)
        cls.capture_health_samples = deque(maxlen=maxlen)

    @classmethod
    def reset_on_interface_switch(cls) -> None:
        """Reset all per-capture counters and clear history buffers on an interface switch."""
        cls.restarted_times = 0
        cls.packets_latencies.clear()
        cls.capture_health_samples.clear()
        cls.global_bandwidth = 0
        cls.global_download = 0
        cls.global_upload = 0
        cls.global_bps_rate = 0
        cls.global_bpm_rate = 0
        cls.global_pps_rate = 0


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
