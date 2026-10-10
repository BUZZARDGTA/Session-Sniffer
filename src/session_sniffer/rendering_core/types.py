"""Type definitions for the rendering core and GUI update payloads."""

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from threading import Condition, Lock
from typing import TYPE_CHECKING, ClassVar, NamedTuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from session_sniffer.background.events import gui_closed__event
from session_sniffer.networking.interface import INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_SHARING
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from datetime import datetime, timedelta
    from pathlib import Path

    import geoip2.database

    from session_sniffer.capture.process import TargetProcessStatus
    from session_sniffer.gta5.process import GTA5Status
    from session_sniffer.rdr2.process import RDR2Status

_MAX_LATENCY_ENTRIES = 3600  # default; resized to Settings.gui_rate_graph_max_history after startup


class PaginationState:
    """Thread-safe pagination state shared between the GUI and the worker thread."""

    _lock: ClassVar[Lock] = Lock()
    _connected_rows_per_page: ClassVar[int] = 0
    _disconnected_rows_per_page: ClassVar[int] = 0
    _connected_page: ClassVar[int] = 1
    _disconnected_page: ClassVar[int] = 1
    _version: ClassVar[int] = 0

    @classmethod
    def set_connected(cls, *, rows_per_page: int, page: int) -> None:
        """Set connected-table pagination state."""
        with cls._lock:
            if cls._connected_rows_per_page == rows_per_page and cls._connected_page == page:
                return
            cls._connected_rows_per_page = rows_per_page
            cls._connected_page = page
            cls._version += 1
        GUIRenderingState.wake()

    @classmethod
    def set_disconnected(cls, *, rows_per_page: int, page: int) -> None:
        """Set disconnected-table pagination state."""
        with cls._lock:
            if cls._disconnected_rows_per_page == rows_per_page and cls._disconnected_page == page:
                return
            cls._disconnected_rows_per_page = rows_per_page
            cls._disconnected_page = page
            cls._version += 1
        GUIRenderingState.wake()

    @classmethod
    def set_connected_page(cls, page: int) -> None:
        """Set only the connected-table current page."""
        with cls._lock:
            if cls._connected_page == page:
                return
            cls._connected_page = page
            cls._version += 1
        GUIRenderingState.wake()

    @classmethod
    def set_disconnected_page(cls, page: int) -> None:
        """Set only the disconnected-table current page."""
        with cls._lock:
            if cls._disconnected_page == page:
                return
            cls._disconnected_page = page
            cls._version += 1
        GUIRenderingState.wake()

    @classmethod
    def get(cls) -> tuple[int, int, int, int, int]:
        """Return (connected_rows_per_page, connected_page, disconnected_rows_per_page, disconnected_page, version)."""
        with cls._lock:
            return (
                cls._connected_rows_per_page,
                cls._connected_page,
                cls._disconnected_rows_per_page,
                cls._disconnected_page,
                cls._version,
            )


class SearchState:
    """Thread-safe search filter query and target column shared between the GUI and the worker thread."""

    _lock: ClassVar[Lock] = Lock()
    _text: ClassVar[str] = ''
    _column_name: ClassVar[str] = ''
    _version: ClassVar[int] = 0

    @classmethod
    def set_search(cls, text: str, column_name: str) -> None:
        """Update global search query and target column name, then bump the version."""
        with cls._lock:
            if cls._text == text and cls._column_name == column_name:
                return
            cls._text = text
            cls._column_name = column_name
            cls._version += 1
        GUIRenderingState.wake()

    @classmethod
    def get(cls) -> tuple[str, str, int]:
        """Return (text, column_name, version)."""
        with cls._lock:
            return cls._text, cls._column_name, cls._version

    @classmethod
    def get_text(cls) -> str:
        """Return the active search query text."""
        with cls._lock:
            return cls._text

    @classmethod
    def get_column_name(cls) -> str:
        """Return the active search column name."""
        with cls._lock:
            return cls._column_name


class SessionFilterState:
    """Thread-safe session filter state for the disconnected players table."""

    FILTER_ALL: ClassVar[int] = -1
    FILTER_CURRENT: ClassVar[int] = 0

    _lock: ClassVar[Lock] = Lock()
    _selected_session: ClassVar[int] = -1
    _version: ClassVar[int] = 0

    @classmethod
    def set_selected_session(cls, *, session_id: int) -> None:
        """Update which session to filter by, then bump the version and wake renderer."""
        with cls._lock:
            if cls._selected_session == session_id:
                return
            cls._selected_session = session_id
            cls._version += 1
        GUIRenderingState.wake()

    @classmethod
    def get(cls) -> tuple[int, int]:
        """Return (selected_session, version)."""
        with cls._lock:
            return cls._selected_session, cls._version

    @classmethod
    def get_selected_session(cls) -> int:
        """Return the currently filtered session identifier (-1 = All, 0 = Current, >0 = Specific)."""
        with cls._lock:
            return cls._selected_session

    @classmethod
    def get_version(cls) -> int:
        """Return the current version counter."""
        with cls._lock:
            return cls._version

    @classmethod
    def bump_version(cls) -> None:
        """Increment the session filter version to trigger a UI refresh."""
        with cls._lock:
            cls._version += 1
        GUIRenderingState.wake()


class TableMergeState:
    """Thread-safe runtime table merge state shared between the GUI and the renderer thread."""

    _lock: ClassVar[Lock] = Lock()
    _override: ClassVar[bool | None] = None
    _version: ClassVar[int] = 0

    @classmethod
    def is_merged(cls) -> bool:
        """Return `True` if connected and disconnected tables are currently merged."""
        with cls._lock:
            if cls._override is not None:
                return cls._override
            return not Settings.gui_disconnected_players_enabled

    @classmethod
    def set_merged(cls, *, merged: bool) -> None:
        """Set whether tables should be merged without saving to settings."""
        with cls._lock:
            if cls._override == merged:
                return
            cls._override = merged
            cls._version += 1
        wake_rendering_core()
        GUIRenderingState.wake()

    @classmethod
    def toggle(cls) -> bool:
        """Toggle table merge state and return the new state."""
        with cls._lock:
            current = cls._override if cls._override is not None else not Settings.gui_disconnected_players_enabled
            cls._override = not current
            cls._version += 1
            new_state = cls._override
        wake_rendering_core()
        GUIRenderingState.wake()
        return new_state

    @classmethod
    def reset_override(cls) -> None:
        """Reset runtime override so table mode follows the persistent setting."""
        with cls._lock:
            if cls._override is None:
                return
            cls._override = None
            cls._version += 1
        wake_rendering_core()
        GUIRenderingState.wake()

    @classmethod
    def get_version(cls) -> int:
        """Return the current version counter."""
        with cls._lock:
            return cls._version


class SortState:
    """Thread-safe table sort configuration shared between the GUI and the worker thread."""

    _lock: ClassVar[Lock] = Lock()
    _connected_column_name: ClassVar[str] = Settings.gui_connected_table_sort_column
    _connected_order: ClassVar[Qt.SortOrder] = Qt.SortOrder.AscendingOrder if Settings.gui_connected_table_sort_order == 'Ascending' else Qt.SortOrder.DescendingOrder
    _disconnected_column_name: ClassVar[str] = Settings.gui_disconnected_table_sort_column
    _disconnected_order: ClassVar[Qt.SortOrder] = Qt.SortOrder.AscendingOrder if Settings.gui_disconnected_table_sort_order == 'Ascending' else Qt.SortOrder.DescendingOrder
    _version: ClassVar[int] = 0

    @classmethod
    def set_connected(cls, *, column_name: str, order: Qt.SortOrder) -> None:
        """Update connected-table sort configuration, then bump the version."""
        with cls._lock:
            if cls._connected_column_name == column_name and cls._connected_order == order:
                return
            cls._connected_column_name = column_name
            cls._connected_order = order
            cls._version += 1
        GUIRenderingState.wake()

    @classmethod
    def set_disconnected(cls, *, column_name: str, order: Qt.SortOrder) -> None:
        """Update disconnected-table sort configuration, then bump the version."""
        with cls._lock:
            if cls._disconnected_column_name == column_name and cls._disconnected_order == order:
                return
            cls._disconnected_column_name = column_name
            cls._disconnected_order = order
            cls._version += 1
        GUIRenderingState.wake()

    @classmethod
    def get(cls) -> tuple[str, Qt.SortOrder, str, Qt.SortOrder, int]:
        """Return (connected_column_name, connected_order, disconnected_column_name, disconnected_order, version)."""
        with cls._lock:
            return cls._connected_column_name, cls._connected_order, cls._disconnected_column_name, cls._disconnected_order, cls._version


class CaptureState:
    """Runtime state derived from the active capture interface."""

    _lock: ClassVar[Lock] = Lock()

    is_neighbour_interface: ClassVar[bool] = False
    interface_name: ClassVar[str] = ''
    interface_ip: ClassVar[str] = ''
    interface_type: ClassVar[str] = ''
    discord_rpc_connected: ClassVar[bool] = False
    target_process_name: ClassVar[str | None] = None
    target_process_running: ClassVar[bool] = False
    target_process_path: ClassVar[Path | None] = None
    target_process_pid: ClassVar[int | None] = None
    target_process_udp_ports: ClassVar[frozenset[int]] = frozenset[int]()
    gta5_is_running: ClassVar[bool] = False
    gta5_is_enhanced: ClassVar[bool] = False
    gta5_is_legacy: ClassVar[bool] = False
    gta5_just_started: ClassVar[bool] = False
    gta5_path: ClassVar[Path | None] = None
    gta5_pid: ClassVar[int | None] = None
    gta5_is_suspended: ClassVar[bool] = False
    gta5_udp_ports: ClassVar[frozenset[int]] = frozenset[int]()
    rdr2_is_running: ClassVar[bool] = False
    rdr2_just_started: ClassVar[bool] = False
    rdr2_path: ClassVar[Path | None] = None
    rdr2_pid: ClassVar[int | None] = None
    rdr2_is_suspended: ClassVar[bool] = False
    rdr2_udp_ports: ClassVar[frozenset[int]] = frozenset[int]()

    @classmethod
    def apply_interface_names(cls, *, is_neighbour: bool, name: str, ip: str, interface_type: str) -> None:
        """Set the four interface-identity fields atomically."""
        with cls._lock:
            cls.is_neighbour_interface = is_neighbour
            cls.interface_name = name
            cls.interface_ip = ip
            cls.interface_type = interface_type

    @classmethod
    def is_local_capture(cls) -> bool:
        """Return `True` when the capture targets traffic from this machine.

        Local capture allows game process control and other local-process actions.
        Returns `False` when ARP spoofing is enabled, a neighbour adapter is selected,
        or the interface is a bridged/sharing adapter (each of which captures another
        machine's traffic). `Shared` is treated as local — it captures this host's traffic.
        """
        with cls._lock:
            return not (Settings.capture_arp_spoofing or cls.is_neighbour_interface or cls.interface_type in (INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_SHARING))

    @classmethod
    def is_scanning_gta5_process(cls) -> bool:
        """Return `True` if local capture is actively filtering traffic on the running GTA V process."""
        with cls._lock:
            is_local = not (Settings.capture_arp_spoofing or cls.is_neighbour_interface or cls.interface_type in (INTERFACE_TYPE_BRIDGED, INTERFACE_TYPE_SHARING))
            tracked_name = Settings.capture_filter_process_name
            is_targeting_gta5 = (
                Settings.capture_filter_process_pid == cls.gta5_pid
                or (
                    Settings.capture_filter_process_track_by_name
                    and tracked_name is not None
                    and tracked_name.lower() in ('gta5.exe', 'gta5_enhanced.exe')
                )
            )
            return (
                is_local
                and cls.gta5_is_running
                and cls.gta5_pid is not None
                and is_targeting_gta5
            )

    @classmethod
    def update_target_process_status(cls, status: TargetProcessStatus) -> None:
        """Update target process running state, PID, path, and UDP socket ports."""
        with cls._lock:
            cls.target_process_name = status.name
            cls.target_process_running = status.is_running
            cls.target_process_path = status.path
            cls.target_process_pid = status.pid
            cls.target_process_udp_ports = status.udp_ports

    @classmethod
    def update_gta5_status(cls, status: GTA5Status) -> None:
        """Update GTA5 running/suspended state and set `gta5_just_started` on the first detected launch."""
        with cls._lock:
            if status.is_running and not cls.gta5_is_running:
                cls.gta5_just_started = True
            cls.gta5_is_running = status.is_running
            cls.gta5_is_enhanced = status.is_enhanced
            cls.gta5_is_legacy = status.is_legacy
            cls.gta5_path = status.path
            cls.gta5_pid = status.pid
            cls.gta5_is_suspended = status.is_suspended
            cls.gta5_udp_ports = status.udp_ports

    @classmethod
    def update_rdr2_status(cls, status: RDR2Status) -> None:
        """Update RDR2 running/suspended state and set `rdr2_just_started` on the first detected launch."""
        with cls._lock:
            if status.is_running and not cls.rdr2_is_running:
                cls.rdr2_just_started = True
            cls.rdr2_is_running = status.is_running
            cls.rdr2_path = status.path
            cls.rdr2_pid = status.pid
            cls.rdr2_is_suspended = status.is_suspended
            cls.rdr2_udp_ports = status.udp_ports


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
    app_peak_cpu_percent: ClassVar[float] = 0.0
    app_memory_mb: ClassVar[float] = 0.0
    app_peak_memory_mb: ClassVar[float] = 0.0
    app_active_threads: ClassVar[int] = 0
    app_peak_threads: ClassVar[int] = 0
    app_disk_read_rate_mb: ClassVar[float] = 0.0
    app_disk_write_rate_mb: ClassVar[float] = 0.0
    app_disk_read_total_mb: ClassVar[float] = 0.0
    app_disk_write_total_mb: ClassVar[float] = 0.0
    packets_dropped: ClassVar[int] = 0
    packets_overflow_dropped: ClassVar[int] = 0
    peak_bps_rate: ClassVar[int] = 0
    peak_bpm_rate: ClassVar[int] = 0
    peak_pps_rate: ClassVar[int] = 0

    @classmethod
    def resize_history_deques(cls, maxlen: int) -> None:
        """Replace the history deques with new ones sized to `maxlen`."""
        cls.packets_latencies = deque(maxlen=maxlen)
        cls.capture_health_samples = deque(maxlen=maxlen)

    @classmethod
    def reset_capture_stats(cls) -> None:
        """Reset all per-capture packet counters and peak rates when clearing session data."""
        cls.total_packets_captured = 0
        cls.peak_bps_rate = 0
        cls.peak_bpm_rate = 0
        cls.peak_pps_rate = 0
        cls.global_bandwidth = 0
        cls.global_download = 0
        cls.global_upload = 0
        cls.global_bps_rate = 0
        cls.global_bpm_rate = 0
        cls.global_pps_rate = 0
        cls.global_avg_latency_ms = 0.0
        cls.packets_dropped = 0
        cls.packets_overflow_dropped = 0
        cls.packets_latencies.clear()
        cls.capture_health_samples.clear()

    @classmethod
    def recalculate_total_packets(cls) -> None:
        """Recalculate total captured packets from current players in registry."""
        from session_sniffer.player.registry import PlayersRegistry  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

        cls.total_packets_captured = (
            sum(player.packets.total_exchanged for player in PlayersRegistry.get_players_map().values())
            + cls.packets_overflow_dropped
        )

    @classmethod
    def reset_on_interface_switch(cls) -> None:
        """Reset all per-capture counters and clear history buffers on an interface switch."""
        cls.restarted_times = 0
        cls.reset_capture_stats()


class CellColor(NamedTuple):
    """Hold foreground and background colors for a table cell."""

    foreground: QColor
    background: QColor | None


class SessionTableSnapshot(NamedTuple):
    """Immutable snapshot of connected/disconnected table rows + cell colors."""

    connected_count: int
    connected_rows_with_colors: tuple[tuple[tuple[str, ...], tuple[CellColor, ...]], ...]
    disconnected_count: int
    disconnected_rows_with_colors: tuple[tuple[tuple[str, ...], tuple[CellColor, ...]], ...]
    past_sessions_with_colors: dict[int, tuple[tuple[tuple[str, ...], tuple[CellColor, ...]], ...]]


class GUIUpdatePayload(NamedTuple):
    """Payload containing all data needed for GUI updates."""

    snapshot_version: int
    column_config: GUIColumnConfig
    header_text: str
    status_capture_text: str
    status_config_text: str
    status_issues_text: str
    status_performance_text: str
    connected_rows_with_colors: Sequence[tuple[tuple[str, ...], tuple[CellColor, ...]]]
    disconnected_rows_with_colors: Sequence[tuple[tuple[str, ...], tuple[CellColor, ...]]]
    connected_count: int
    disconnected_count: int
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

    column_count: int
    row_count: int
    rows_with_colors: tuple[tuple[tuple[str, ...], tuple[CellColor, ...]], ...]


@dataclass(frozen=True, slots=True)
class GUIRenderingSnapshot:
    """A single published GUI rendering snapshot.

    Built off-thread, then published by replacement (no shared mutation).
    """

    column_config: GUIColumnConfig
    status: GUIStatusTexts
    connected: GUITableData
    disconnected: GUITableData
    past_sessions: dict[int, GUITableData]


class GUIRenderingState:
    """Atomically published rendering state using a version counter and Condition for multi-consumer waits."""

    _lock: ClassVar[Lock] = Lock()
    _condition: ClassVar[Condition] = Condition(_lock)
    _current: ClassVar[GUIRenderingSnapshot | None] = None
    _version: ClassVar[int] = 0  # Incremented each time a new snapshot is published
    _wake_generation: ClassVar[int] = 0

    @classmethod
    def wake(cls) -> None:
        """Wake waiting consumers immediately without a new snapshot."""
        with cls._condition:
            cls._wake_generation += 1
            cls._condition.notify_all()

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
        timeout: float | None = None,
        last_seen_version: int = 0,
    ) -> tuple[GUIRenderingSnapshot | None, int]:
        """Wait for a new snapshot if it's newer than last_seen_version, or wake on external requests.

        Returns:
            Tuple of (snapshot, version). Snapshot is None if timeout occurs or wake was requested.
        """
        with cls._condition:
            start_wake_gen = cls._wake_generation
            if not cls._condition.wait_for(
                lambda: cls._version != last_seen_version or cls._wake_generation != start_wake_gen or gui_closed__event.is_set(),
                timeout=timeout,
            ):
                return None, last_seen_version

            return (cls._current if cls._version != last_seen_version else None), cls._version

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
