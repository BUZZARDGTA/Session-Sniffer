"""Type definitions for the rendering core and GUI update payloads."""

from dataclasses import dataclass
from threading import Condition, Lock
from typing import TYPE_CHECKING, ClassVar, NamedTuple

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    import geoip2.database
    from PyQt6.QtGui import QColor


@dataclass(kw_only=True, slots=True)
class TsharkStats:
    """Statistics and data tracking for TShark packet capture performance."""
    packets_latencies: ClassVar[list[tuple[datetime, timedelta]]] = []
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
    header_text: str
    status_capture_text: str
    status_config_text: str
    status_issues_text: str
    status_performance_text: str
    connected_rows_with_colors: list[tuple[list[str], list[CellColor]]]
    disconnected_rows_with_colors: list[tuple[list[str], list[CellColor]]]
    connected_num: int
    disconnected_num: int


@dataclass(frozen=True, slots=True)
class GUIRenderingSnapshot:
    """A single published GUI rendering snapshot.

    Built off-thread, then published by replacement (no shared mutation).
    """

    # Column config
    connected_hidden_columns: set[str]
    disconnected_hidden_columns: set[str]
    connected_column_names: list[str]
    disconnected_column_names: list[str]

    # Header + status
    header_text: str
    status_capture_text: str
    status_config_text: str
    status_issues_text: str
    status_performance_text: str

    # Connected table
    connected_num_cols: int
    connected_num_rows: int
    connected_rows: tuple[tuple[str, ...], ...]
    connected_colors: tuple[tuple[CellColor, ...], ...]

    # Disconnected table
    disconnected_num_cols: int
    disconnected_num_rows: int
    disconnected_rows: tuple[tuple[str, ...], ...]
    disconnected_colors: tuple[tuple[CellColor, ...], ...]


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
