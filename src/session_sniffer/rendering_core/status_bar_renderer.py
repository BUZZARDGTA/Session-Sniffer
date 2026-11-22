"""Status bar section rendering helpers for the desktop GUI and embedded web server."""

import os
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from session_sniffer.capture.arp_spoofing import ArpSpoofingController
from session_sniffer.capture.process import (
    get_current_process_cpu_time,
    get_current_process_io_bytes,
    get_current_process_memory_mb,
)
from session_sniffer.i18n import tr
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import (
    CaptureState,
    CaptureStats,
    StatusBarItem,
    StatusBarSectionData,
    StatusBarTone,
)
from session_sniffer.settings import Settings

_BYTES_PER_MB = 1024**2

_CPU_COUNT: int = os.cpu_count() or 1
_LATENCY_DISPLAY_WINDOW_SECONDS = 60
_MIN_RATE_INTERVAL_SECONDS = 0.2


@dataclass(slots=True)
class _CPUState:
    last_cpu_time: float = field(default_factory=get_current_process_cpu_time)
    last_timestamp: float = field(default_factory=time.monotonic)


@dataclass(slots=True)
class _IOState:
    read_bytes: int = 0
    write_bytes: int = 0
    timestamp: float = field(default_factory=time.monotonic)


@dataclass(slots=True)
class _LatencyState:
    last_nonzero_ms: float = 0.0
    last_nonzero_ts: float = 0.0


_initial_io_bytes = get_current_process_io_bytes()
_CPU_STATE = _CPUState()
_IO_STATE = _IOState(read_bytes=_initial_io_bytes[0], write_bytes=_initial_io_bytes[1])
_LATENCY_STATE = _LatencyState()


def reset_status_bar_latency() -> None:
    """Reset the recorded last non-zero latency state."""
    _LATENCY_STATE.last_nonzero_ms = 0.0
    _LATENCY_STATE.last_nonzero_ts = 0.0


if TYPE_CHECKING:
    from session_sniffer.capture.packet_capture import PacketCapture
    from session_sniffer.discord.rpc import DiscordRPC


@dataclass(frozen=True, slots=True)
class StatusBarCaptureInfo:
    """Capture-related settings for the status bar."""

    ip_address: str
    feature_set: str | None
    overflow_timer: int


@dataclass(frozen=True, slots=True)
class StatusBarCaptureStats:
    """Capture statistics for the status bar."""

    restarted_times: int
    last_nonzero_latency_ms: float
    last_nonzero_latency_ts: float


@dataclass(frozen=True, slots=True)
class StatusBarUserIPInfo:
    """UserIP database issue counts for the status bar."""

    conflict_ip_count: int


@dataclass(frozen=True, slots=True)
class StatusBarInterfaceInfo:
    """Network interface info for the status bar."""

    name: str
    is_neighbour_interface: bool
    arp_spoofing: bool
    arp_spoofing_running: bool


@dataclass(frozen=True, slots=True)
class StatusBarSystemInfo:
    """System-level metrics for the status bar."""

    discord_presence_enabled: bool
    discord_rpc_connected: bool


@dataclass(frozen=True, slots=True)
class StatusBarSnapshot:
    """Snapshot of global values used to compose status sections."""

    capture: StatusBarCaptureInfo
    capture_stats: StatusBarCaptureStats
    userip: StatusBarUserIPInfo
    interface: StatusBarInterfaceInfo
    system: StatusBarSystemInfo


def _compute_disk_io_rates() -> None:
    """Compute per-direction disk I/O rates and totals, updating `CaptureStats` in place."""
    read_bytes, write_bytes = get_current_process_io_bytes()
    CaptureStats.app_disk_read_total_mb = read_bytes / _BYTES_PER_MB
    CaptureStats.app_disk_write_total_mb = write_bytes / _BYTES_PER_MB
    now = time.monotonic()
    delta_time = now - _IO_STATE.timestamp
    if delta_time < _MIN_RATE_INTERVAL_SECONDS:
        return
    delta_read = read_bytes - _IO_STATE.read_bytes
    delta_write = write_bytes - _IO_STATE.write_bytes
    _IO_STATE.read_bytes = read_bytes
    _IO_STATE.write_bytes = write_bytes
    _IO_STATE.timestamp = now
    CaptureStats.app_disk_read_rate_mb = max(0.0, delta_read) / delta_time / _BYTES_PER_MB
    CaptureStats.app_disk_write_rate_mb = max(0.0, delta_write) / delta_time / _BYTES_PER_MB


def _capture_global_state(capture: PacketCapture, discord_rpc_manager: DiscordRPC | None) -> StatusBarSnapshot:
    """Capture global state atomically to avoid race conditions."""
    discord_rpc_connected = False
    if Settings.discord_presence:
        discord_rpc_connected = discord_rpc_manager.connection_status.is_set() if discord_rpc_manager is not None else CaptureState.discord_rpc_connected

    now = time.monotonic()
    delta_time = now - _CPU_STATE.last_timestamp
    if delta_time >= _MIN_RATE_INTERVAL_SECONDS:
        current_cpu_time = get_current_process_cpu_time()
        delta_cpu = current_cpu_time - _CPU_STATE.last_cpu_time
        _CPU_STATE.last_cpu_time = current_cpu_time
        _CPU_STATE.last_timestamp = now
        CaptureStats.app_cpu_percent = min(100.0, (max(0.0, delta_cpu) / delta_time / _CPU_COUNT) * 100.0)
        CaptureStats.app_peak_cpu_percent = min(100.0, max(CaptureStats.app_peak_cpu_percent, CaptureStats.app_cpu_percent))

    CaptureStats.app_memory_mb = get_current_process_memory_mb()
    CaptureStats.app_peak_memory_mb = max(CaptureStats.app_peak_memory_mb, CaptureStats.app_memory_mb)
    CaptureStats.app_active_threads = threading.active_count()
    CaptureStats.app_peak_threads = max(CaptureStats.app_peak_threads, CaptureStats.app_active_threads)
    _compute_disk_io_rates()
    CaptureStats.packets_dropped = capture.get_pcap_drop_count() or 0

    if CaptureStats.global_avg_latency_ms > 0.0:
        _LATENCY_STATE.last_nonzero_ms = CaptureStats.global_avg_latency_ms
        _LATENCY_STATE.last_nonzero_ts = time.monotonic()

    return StatusBarSnapshot(
        capture=StatusBarCaptureInfo(
            ip_address=capture.config.interface.ip_address,
            feature_set=Settings.capture_feature_set,
            overflow_timer=Settings.capture_overflow_timer,
        ),
        capture_stats=StatusBarCaptureStats(
            restarted_times=CaptureStats.restarted_times,
            last_nonzero_latency_ms=_LATENCY_STATE.last_nonzero_ms,
            last_nonzero_latency_ts=_LATENCY_STATE.last_nonzero_ts,
        ),
        userip=StatusBarUserIPInfo(
            conflict_ip_count=len(UserIPDatabases.notified_ip_conflicts),
        ),
        interface=StatusBarInterfaceInfo(
            name=capture.config.interface.name,
            is_neighbour_interface=capture.config.interface.is_neighbour,
            arp_spoofing=Settings.capture_arp_spoofing,
            arp_spoofing_running=ArpSpoofingController.is_running(),
        ),
        system=StatusBarSystemInfo(
            discord_presence_enabled=Settings.discord_presence,
            discord_rpc_connected=discord_rpc_connected,
        ),
    )


_INTERFACE_NAME_MAX_LEN = 20


def _strip_trailing_colon(label: str) -> str:
    """Remove trailing ASCII/CJK colons and adjacent spaces from a localized status label."""
    return label.rstrip(':\uff1a \u00a0\u202f')


def _format_interface_name(raw_name: str) -> str:
    if len(raw_name) > _INTERFACE_NAME_MAX_LEN:
        return raw_name[:_INTERFACE_NAME_MAX_LEN] + '…'
    return raw_name


def _resolve_target_process_label() -> str:
    return (
        CaptureState.target_process_name
        or (Settings.capture_filter_process_name if Settings.capture_filter_process_track_by_name else None)
        or (tr('PID {pid}', pid=Settings.capture_filter_process_pid) if Settings.capture_filter_process_pid > 0 else tr('Target Process'))
    )


def _resolve_latency_metrics(snapshot: StatusBarSnapshot) -> tuple[str, StatusBarTone]:
    has_latency = snapshot.capture_stats.last_nonzero_latency_ts > 0 and time.monotonic() - snapshot.capture_stats.last_nonzero_latency_ts < _LATENCY_DISPLAY_WINDOW_SECONDS
    display_latency_ms = snapshot.capture_stats.last_nonzero_latency_ms if has_latency else 0.0

    if not has_latency or snapshot.capture.overflow_timer <= 0:
        latency_tone: StatusBarTone = 'muted'
    else:
        display_latency_seconds = display_latency_ms / 1000
        if display_latency_seconds >= 0.90 * snapshot.capture.overflow_timer:
            latency_tone = 'danger'
        elif display_latency_seconds >= 0.75 * snapshot.capture.overflow_timer:
            latency_tone = 'warning'
        else:
            latency_tone = 'success'

    latency_text = tr('{latency}ms', latency=round(display_latency_ms, 1)) if has_latency else tr('— ms')
    return latency_text, latency_tone


def _build_status_sections(snapshot: StatusBarSnapshot) -> tuple[StatusBarSectionData, ...]:
    """Build structured, theme-neutral status bar sections for the desktop GUI and embedded web panel."""
    capture_items = (
        StatusBarItem(
            label=_strip_trailing_colon(tr('Interface:')),
            value=_format_interface_name(snapshot.interface.name),
            tone='success',
            dot=True,
        ),
        StatusBarItem(
            label=_strip_trailing_colon(tr('IP:')),
            value=snapshot.capture.ip_address,
            tone='neutral',
            mono=True,
        ),
    )

    config_items: list[StatusBarItem] = []
    if snapshot.interface.arp_spoofing:
        config_items.append(
            StatusBarItem(
                label=_strip_trailing_colon(tr('ARP Spoofing:')),
                value=tr('Running') if snapshot.interface.arp_spoofing_running else tr('Stopped'),
                tone='success' if snapshot.interface.arp_spoofing_running else 'danger',
                dot=True,
            ),
        )
    elif snapshot.interface.is_neighbour_interface:
        config_items.append(
            StatusBarItem(
                label=_strip_trailing_colon(tr('ARP:')),
                value=tr('Enabled'),
                tone='success',
                dot=True,
            ),
        )

    if snapshot.system.discord_presence_enabled:
        config_items.append(
            StatusBarItem(
                label=_strip_trailing_colon(tr('Discord:')),
                value=tr('Connected') if snapshot.system.discord_rpc_connected else tr('Waiting'),
                tone='success' if snapshot.system.discord_rpc_connected else 'warning',
                dot=True,
            ),
        )

    if snapshot.capture.feature_set is not None:
        config_items.append(
            StatusBarItem(
                label=_strip_trailing_colon(tr('Feature Set:')),
                value=snapshot.capture.feature_set,
                tone='accent',
            ),
        )

    if Settings.is_process_filter_active() and CaptureState.is_local_capture():
        config_items.append(
            StatusBarItem(
                label=_strip_trailing_colon(tr('Target:')),
                value=_resolve_target_process_label(),
                tone='success' if CaptureState.target_process_running else 'danger',
                dot=True,
            ),
        )

    if not config_items:
        config_items.append(StatusBarItem(label='', value=tr('Default'), tone='muted'))

    sections: list[StatusBarSectionData] = [
        StatusBarSectionData(key='capture', title=_strip_trailing_colon(tr('Capture:')), items=capture_items),
        StatusBarSectionData(key='config', title=_strip_trailing_colon(tr('Config:')), items=tuple(config_items)),
    ]

    if snapshot.userip.conflict_ip_count:
        sections.append(
            StatusBarSectionData(
                key='issues',
                title=_strip_trailing_colon(tr('UserIP Issues:')),
                items=(
                    StatusBarItem(
                        label='',
                        value=tr('Conflicts: {count}', count=snapshot.userip.conflict_ip_count),
                        tone='danger',
                        dot=True,
                    ),
                ),
            ),
        )

    latency_text, latency_tone = _resolve_latency_metrics(snapshot)
    performance_items: list[StatusBarItem] = [
        StatusBarItem(
            label=_strip_trailing_colon(tr('Latency:')),
            value=latency_text,
            tone=latency_tone,
            mono=True,
            dot=True,
        ),
    ]
    if snapshot.capture_stats.restarted_times:
        performance_items.append(
            StatusBarItem(
                label=_strip_trailing_colon(tr('Restarts:')),
                value=str(snapshot.capture_stats.restarted_times),
                tone='danger',
                mono=True,
            ),
        )
    sections.append(
        StatusBarSectionData(
            key='performance',
            title=_strip_trailing_colon(tr('Performance:')),
            items=tuple(performance_items),
        ),
    )

    return tuple(sections)


def build_gui_status_sections(
    *,
    capture: PacketCapture,
    discord_rpc_manager: DiscordRPC | None,
) -> tuple[StatusBarSectionData, ...]:
    """Generate structured telemetry sections for the desktop GUI and embedded web server status bars."""
    snapshot = _capture_global_state(capture, discord_rpc_manager)
    return _build_status_sections(snapshot)
