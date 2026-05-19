"""Status bar section rendering helpers for the GUI."""

import enum
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import psutil

from session_sniffer.constants.external import LOCAL_TZ
from session_sniffer.guis.colors import StatusBarColors, ThresholdColors
from session_sniffer.models.player import PlayerBandwidth
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.rendering_core.types import CaptureStats
from session_sniffer.settings import Settings

_BYTES_PER_MB = 1024 ** 2

if TYPE_CHECKING:
    from session_sniffer.capture.packet_capture import PacketCapture
    from session_sniffer.discord.rpc import DiscordRPC


@dataclass(frozen=True, slots=True)
class StatusBarCaptureInfo:
    """Capture-related settings for the status bar."""
    ip_address: str
    program_preset: str | None
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
    packets_latencies: list[tuple[datetime, timedelta]]  # snapshot copy from deque


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


def _capture_global_state(capture: PacketCapture, discord_rpc_manager: DiscordRPC | None) -> StatusBarSnapshot:
    """Capture global state atomically to avoid race conditions."""
    discord_rpc_connected = False
    if Settings.discord_presence and discord_rpc_manager is not None:
        discord_rpc_connected = discord_rpc_manager.connection_status.is_set()

    return StatusBarSnapshot(
        capture=StatusBarCaptureInfo(
            ip_address=capture.config.interface.ip_address,
            program_preset=Settings.capture_program_preset,
            overflow_timer=Settings.capture_overflow_timer,
        ),
        capture_stats=StatusBarCaptureStats(
            global_bandwidth=CaptureStats.global_bandwidth,
            global_download=CaptureStats.global_download,
            global_upload=CaptureStats.global_upload,
            global_bps_rate=CaptureStats.global_bps_rate,
            global_pps_rate=CaptureStats.global_pps_rate,
            restarted_times=CaptureStats.restarted_times,
            packets_latencies=list(CaptureStats.packets_latencies),
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
            memory_mb=psutil.Process().memory_info().rss / _BYTES_PER_MB,
            discord_presence_enabled=Settings.discord_presence,
            discord_rpc_connected=discord_rpc_connected,
        ),
    )


def _calculate_latency(packets_latencies: list[tuple[datetime, timedelta]]) -> tuple[float, float]:
    """Calculate average packet latency for the most recent 1-second window."""
    one_second_ago = datetime.now(tz=LOCAL_TZ) - timedelta(seconds=1)
    recent_packets: list[tuple[datetime, timedelta]] = [(pkt_time, pkt_latency) for pkt_time, pkt_latency in packets_latencies if pkt_time >= one_second_ago]

    if recent_packets:
        total_latency_seconds = sum((pkt_latency.total_seconds() for _, pkt_latency in recent_packets), 0.0)
        avg_latency_seconds = total_latency_seconds / len(recent_packets)
        avg_latency_rounded = float(round(avg_latency_seconds, 1))
    else:
        avg_latency_seconds = 0.0
        avg_latency_rounded = 0.0

    return avg_latency_seconds, avg_latency_rounded


def _build_capture_section(snapshot: StatusBarSnapshot) -> str:
    return (
        f'<span style="font-size: 11px;">'
        f'<span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">📡 Capture:</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Interface:</span> '
        f'<span style="color: {StatusBarColors.ENABLED};">{snapshot.interface.name}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">IP:</span> '
        f'<span style="color: {StatusBarColors.ENABLED};">{snapshot.capture.ip_address}</span>'
        f'</span>'
    )


def _build_config_section(snapshot: StatusBarSnapshot, *, vpn_mode_enabled: bool, discord_rpc_manager: DiscordRPC | None) -> str:
    arp_label = ('Enabled (Spoofing)' if snapshot.interface.arp_spoofing else 'Enabled') if snapshot.interface.is_neighbour_interface else 'Disabled'
    is_vpn_enabled = 'Enabled' if vpn_mode_enabled else 'Disabled'
    arp_color = StatusBarColors.ENABLED if snapshot.interface.is_neighbour_interface else StatusBarColors.DISABLED
    vpn_color = StatusBarColors.ENABLED if is_vpn_enabled == 'Enabled' else StatusBarColors.DISABLED

    discord_display = ''
    if snapshot.system.discord_presence_enabled and discord_rpc_manager is not None:
        rpc_color = StatusBarColors.ENABLED if snapshot.system.discord_rpc_connected else StatusBarColors.DISABLED
        rpc_status = 'Connected' if snapshot.system.discord_rpc_connected else 'Waiting'
        discord_display = (
            f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
            f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Discord:</span> '
            f'<span style="color: {rpc_color};">{rpc_status}</span>'
        )

    return (
        f'<span style="font-size: 11px;">'
        f'<span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">⚙️ Config:</span> '
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">ARP:</span> '
        f'<span style="color: {arp_color};">{arp_label}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">VPN:</span> '
        f'<span style="color: {vpn_color};">{is_vpn_enabled}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Preset:</span> '
        f'<span style="color: {StatusBarColors.SECONDARY_ACCENT};">{snapshot.capture.program_preset}</span>'
        f'{discord_display}'
        f'</span>'
    )


def _build_userip_issues_section(snapshot: StatusBarSnapshot) -> str:
    if not snapshot.userip.conflict_ip_count:
        return ''

    issues: list[str] = []
    if snapshot.userip.conflict_ip_count:
        issues.append(f'<span style="color: {StatusBarColors.DISABLED};">⚠️ Conflicts: {snapshot.userip.conflict_ip_count}</span>')

    divider = f' <span style="color: {StatusBarColors.DIVIDER};"> • </span> '
    return (
        f'<span style="color: {StatusBarColors.DISABLED}; font-weight: bold;">🧯 UserIP Issues:</span> '
        f'{divider.join(issues)}'
    )


def _build_performance_section(snapshot: StatusBarSnapshot, *, avg_latency_seconds: float, avg_latency_rounded: float) -> str:
    latency_color = (ThresholdColors.CRITICAL if avg_latency_seconds >= 0.90 * snapshot.capture.overflow_timer
                     else ThresholdColors.WARNING if avg_latency_seconds >= 0.75 * snapshot.capture.overflow_timer
                     else ThresholdColors.HEALTHY)
    bps_color = (ThresholdColors.CRITICAL if snapshot.capture_stats.global_bps_rate >= StatusBarThresholds.BPS_CRITICAL
                 else ThresholdColors.WARNING if snapshot.capture_stats.global_bps_rate >= StatusBarThresholds.BPS_WARNING
                 else ThresholdColors.HEALTHY)
    pps_color = (ThresholdColors.CRITICAL if snapshot.capture_stats.global_pps_rate >= StatusBarThresholds.PPS_CRITICAL
                 else ThresholdColors.WARNING if snapshot.capture_stats.global_pps_rate >= StatusBarThresholds.PPS_WARNING
                 else ThresholdColors.HEALTHY)
    memory_color = (ThresholdColors.CRITICAL if snapshot.system.memory_mb >= StatusBarThresholds.MEMORY_HIGH
                    else ThresholdColors.WARNING if snapshot.system.memory_mb >= StatusBarThresholds.MEMORY_MEDIUM
                    else ThresholdColors.HEALTHY)
    restart_color = ThresholdColors.HEALTHY if not snapshot.capture_stats.restarted_times else ThresholdColors.CRITICAL

    return (
        f'<span style="font-size: 11px;">'
        f'<span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">⚡ Performance:</span> '
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Latency:</span> '
        f'<span style="color: {latency_color};">{avg_latency_rounded}s</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">BPS:</span> '
        f'<span style="color: {bps_color};">{PlayerBandwidth.format_bytes(snapshot.capture_stats.global_bps_rate)}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">PPS:</span> '
        f'<span style="color: {pps_color};">{snapshot.capture_stats.global_pps_rate}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">RAM:</span> '
        f'<span style="color: {memory_color};">{int(snapshot.system.memory_mb)} MB</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Restarts:</span> '
        f'<span style="color: {restart_color};">{snapshot.capture_stats.restarted_times}</span>'
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
    avg_latency_seconds, avg_latency_rounded = _calculate_latency(snapshot.capture_stats.packets_latencies)

    capture_section = _build_capture_section(snapshot)
    config_section = _build_config_section(snapshot, vpn_mode_enabled=vpn_mode_enabled, discord_rpc_manager=discord_rpc_manager)
    userip_issues_section = _build_userip_issues_section(snapshot)
    performance_section = _build_performance_section(
        snapshot,
        avg_latency_seconds=avg_latency_seconds,
        avg_latency_rounded=avg_latency_rounded,
    )

    return capture_section, config_section, userip_issues_section, performance_section
