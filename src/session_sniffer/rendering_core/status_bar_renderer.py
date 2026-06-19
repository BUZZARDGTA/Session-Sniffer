"""Status bar section rendering helpers for the GUI."""

import enum
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import psutil

from session_sniffer.guis.colors import StatusBarColors, ThresholdColors
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import CaptureStats
from session_sniffer.settings import Settings

_BYTES_PER_MB = 1024**2

_PROCESS = psutil.Process()
_CPU_COUNT: int = psutil.cpu_count() or 1
_LATENCY_DISPLAY_WINDOW_SECS = 60


@dataclass(slots=True)
class _IOState:
    counters: _pio = field(default_factory=_PROCESS.io_counters)
    timestamp: float = field(default_factory=time.monotonic)


@dataclass(slots=True)
class _LatencyState:
    last_nonzero_ms: float = 0.0
    last_nonzero_ts: float = 0.0


_IO_STATE = _IOState()
_LATENCY_STATE = _LatencyState()

if TYPE_CHECKING:
    from psutil._ntuples import pio as _pio

    from session_sniffer.capture.packet_capture import PacketCapture
    from session_sniffer.discord.rpc import DiscordRPC


@dataclass(frozen=True, slots=True)
class StatusBarCaptureInfo:
    """Capture-related settings for the status bar."""

    ip_address: str
    game_preset: str | None
    overflow_timer: int


@dataclass(frozen=True, slots=True)
class StatusBarCaptureStats:
    """Capture statistics for the status bar."""

    global_bandwidth: int
    global_download: int
    global_upload: int
    global_bps_rate: int
    global_pps_rate: int
    restarted_times: int
    avg_latency_ms: float
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


@dataclass(frozen=True, slots=True)
class StatusBarSystemInfo:
    """System-level metrics for the status bar."""

    memory_mb: float
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


class StatusBarThresholds(enum.IntEnum):
    """Performance thresholds for color coding."""

    BPS_CRITICAL = 3_000_000
    BPS_WARNING = 1_000_000
    PPS_CRITICAL = 1500
    PPS_WARNING = 1000
    MEMORY_HIGH = 500
    MEMORY_MEDIUM = 300


def _compute_disk_io_rates() -> None:
    """Compute per-direction disk I/O rates and totals, updating `CaptureStats` in place."""
    try:
        io = _PROCESS.io_counters()
    except psutil.AccessDenied:
        return
    CaptureStats.app_disk_read_total_mb = io.read_bytes / _BYTES_PER_MB
    CaptureStats.app_disk_write_total_mb = io.write_bytes / _BYTES_PER_MB
    now = time.monotonic()
    dt = now - _IO_STATE.timestamp
    if dt <= 0.0:
        return
    delta_read = io.read_bytes - _IO_STATE.counters.read_bytes
    delta_write = io.write_bytes - _IO_STATE.counters.write_bytes
    _IO_STATE.counters = io
    _IO_STATE.timestamp = now
    CaptureStats.app_disk_read_rate_mb = max(0.0, delta_read) / dt / _BYTES_PER_MB
    CaptureStats.app_disk_write_rate_mb = max(0.0, delta_write) / dt / _BYTES_PER_MB


def _capture_global_state(capture: PacketCapture, discord_rpc_manager: DiscordRPC | None) -> StatusBarSnapshot:
    """Capture global state atomically to avoid race conditions."""
    discord_rpc_connected = False
    if Settings.discord_presence and discord_rpc_manager is not None:
        discord_rpc_connected = discord_rpc_manager.connection_status.is_set()

    CaptureStats.app_cpu_percent = _PROCESS.cpu_percent(interval=None) / _CPU_COUNT
    CaptureStats.app_memory_mb = _PROCESS.memory_info().rss / _BYTES_PER_MB
    _compute_disk_io_rates()
    CaptureStats.packets_dropped = capture.get_pcap_drop_count() or 0

    if CaptureStats.global_avg_latency_ms > 0.0:
        _LATENCY_STATE.last_nonzero_ms = CaptureStats.global_avg_latency_ms
        _LATENCY_STATE.last_nonzero_ts = time.monotonic()

    return StatusBarSnapshot(
        capture=StatusBarCaptureInfo(
            ip_address=capture.config.interface.ip_address,
            game_preset=Settings.capture_game_preset,
            overflow_timer=Settings.capture_overflow_timer,
        ),
        capture_stats=StatusBarCaptureStats(
            global_bandwidth=CaptureStats.global_bandwidth,
            global_download=CaptureStats.global_download,
            global_upload=CaptureStats.global_upload,
            global_bps_rate=CaptureStats.global_bps_rate,
            global_pps_rate=CaptureStats.global_pps_rate,
            restarted_times=CaptureStats.restarted_times,
            avg_latency_ms=CaptureStats.global_avg_latency_ms,
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
        ),
        system=StatusBarSystemInfo(
            memory_mb=CaptureStats.app_memory_mb,
            discord_presence_enabled=Settings.discord_presence,
            discord_rpc_connected=discord_rpc_connected,
        ),
    )


_INTERFACE_NAME_MAX_LEN = 20


def _build_capture_section(snapshot: StatusBarSnapshot) -> str:
    interface_name = snapshot.interface.name
    if len(interface_name) > _INTERFACE_NAME_MAX_LEN:
        interface_name = interface_name[:_INTERFACE_NAME_MAX_LEN] + '…'
    return (
        f'<span style="font-size: 11px;">'
        f'<span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">📡 Capture:</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Interface:</span> '
        f'<span style="color: {StatusBarColors.ENABLED};">{interface_name}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">IP:</span> '
        f'<span style="color: {StatusBarColors.ENABLED};">{snapshot.capture.ip_address}</span>'
        f'</span>'
    )


def _build_config_section(snapshot: StatusBarSnapshot, *, vpn_mode_enabled: bool, discord_rpc_manager: DiscordRPC | None) -> str:
    parts: list[str] = []

    if snapshot.interface.is_neighbour_interface:
        arp_label = 'Enabled (Spoofing)' if snapshot.interface.arp_spoofing else 'Enabled'
        parts.append(
            f'<span style="color: {StatusBarColors.LABEL_ACCENT};">ARP:</span> <span style="color: {StatusBarColors.ENABLED};">{arp_label}</span>',
        )

    if vpn_mode_enabled:
        parts.append(
            f'<span style="color: {StatusBarColors.LABEL_ACCENT};">VPN:</span> <span style="color: {StatusBarColors.ENABLED};">Enabled</span>',
        )

    if snapshot.capture.game_preset is not None:
        parts.append(
            f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Game Preset:</span> '
            f'<span style="color: {StatusBarColors.SECONDARY_ACCENT};">{snapshot.capture.game_preset}</span>',
        )

    if snapshot.system.discord_presence_enabled and discord_rpc_manager is not None:
        rpc_color = StatusBarColors.ENABLED if snapshot.system.discord_rpc_connected else StatusBarColors.DISABLED
        rpc_status = 'Connected' if snapshot.system.discord_rpc_connected else 'Waiting'
        parts.append(
            f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Discord:</span> <span style="color: {rpc_color};">{rpc_status}</span>',
        )

    divider = f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
    body = divider.join(parts)
    return f'<span style="font-size: 11px;"><span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">⚙️ Config:</span> {body}</span>'


def _build_userip_issues_section(snapshot: StatusBarSnapshot) -> str:
    if not snapshot.userip.conflict_ip_count:
        return ''

    issues: list[str] = []
    if snapshot.userip.conflict_ip_count:
        issues.append(f'<span style="color: {StatusBarColors.DISABLED};">⚠️ Conflicts: {snapshot.userip.conflict_ip_count}</span>')

    divider = f' <span style="color: {StatusBarColors.DIVIDER};"> • </span> '
    return f'<span style="color: {StatusBarColors.DISABLED}; font-weight: bold;">🧯 UserIP Issues:</span> {divider.join(issues)}'


def _build_performance_section(snapshot: StatusBarSnapshot) -> str:
    has_latency = snapshot.capture_stats.last_nonzero_latency_ts > 0 and time.monotonic() - snapshot.capture_stats.last_nonzero_latency_ts < _LATENCY_DISPLAY_WINDOW_SECS
    display_latency_ms = snapshot.capture_stats.last_nonzero_latency_ms if has_latency else 0.0

    latency_color: StatusBarColors | ThresholdColors
    if not has_latency or snapshot.capture.overflow_timer <= 0:
        latency_color = StatusBarColors.DIVIDER
    else:
        display_latency_seconds = display_latency_ms / 1000
        if display_latency_seconds >= 0.90 * snapshot.capture.overflow_timer:
            latency_color = ThresholdColors.CRITICAL
        elif display_latency_seconds >= 0.75 * snapshot.capture.overflow_timer:
            latency_color = ThresholdColors.WARNING
        else:
            latency_color = ThresholdColors.HEALTHY
    restart_color: ThresholdColors = ThresholdColors.HEALTHY if not snapshot.capture_stats.restarted_times else ThresholdColors.CRITICAL
    latency_text = f'{round(display_latency_ms, 1)}ms' if has_latency else '— ms'

    restarts_display = (
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Restarts:</span> '
        f'<span style="color: {restart_color};">{snapshot.capture_stats.restarted_times}</span>'
        if snapshot.capture_stats.restarted_times
        else ''
    )

    return (
        f'<span style="font-size: 11px;">'
        f'<span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">⚡ Performance:</span> '
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Latency:</span> '
        f'<span style="color: {latency_color};">{latency_text}</span>'
        f'{restarts_display}'
        f'</span>'
    )


def build_gui_status_text(
    *,
    capture: PacketCapture,
    vpn_mode_enabled: bool,
    discord_rpc_manager: DiscordRPC | None,
) -> tuple[str, str, str, str]:
    """Generate status bar text content for all sections."""
    snapshot = _capture_global_state(capture, discord_rpc_manager)

    capture_section = _build_capture_section(snapshot)
    config_section = _build_config_section(snapshot, vpn_mode_enabled=vpn_mode_enabled, discord_rpc_manager=discord_rpc_manager)
    userip_issues_section = _build_userip_issues_section(snapshot)
    performance_section = _build_performance_section(snapshot)

    return capture_section, config_section, userip_issues_section, performance_section
