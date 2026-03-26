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
from session_sniffer.rendering_core.types import TsharkStats
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from session_sniffer.capture.tshark_capture import PacketCapture
    from session_sniffer.discord.rpc import DiscordRPC


@dataclass(frozen=True, slots=True)
class StatusBarSnapshot:
    """Snapshot of global values used to compose status sections."""

    capture_ip_address: str | None
    capture_program_preset: str | None
    capture_overflow_timer: float
    discord_presence_enabled: bool

    tshark_global_bandwidth: int
    tshark_global_download: int
    tshark_global_upload: int
    tshark_global_bps_rate: int
    tshark_global_pps_rate: int
    tshark_restarted_times: int
    tshark_packets_latencies: list[tuple[datetime, timedelta]]

    userip_invalid_ip_count: int
    userip_conflict_ip_count: int
    userip_corrupted_settings_count: int

    interface_name: str
    interface_is_arp: bool

    memory_mb: float
    discord_rpc_connected: bool


class StatusBarThresholds(enum.IntEnum):
    """Performance thresholds for color coding."""

    BANDWIDTH_CRITICAL = 1_000_000_000
    BANDWIDTH_WARNING = 500_000_000
    DOWNLOAD_CRITICAL = 500_000_000
    DOWNLOAD_WARNING = 250_000_000
    UPLOAD_CRITICAL = 500_000_000
    UPLOAD_WARNING = 250_000_000
    BPS_CRITICAL = 3_000_000
    BPS_WARNING = 1_000_000
    PPS_CRITICAL = 1500
    PPS_WARNING = 1000
    MEMORY_HIGH = 500
    MEMORY_MEDIUM = 300


def _capture_global_state(capture: PacketCapture, discord_rpc_manager: DiscordRPC | None) -> StatusBarSnapshot:
    """Capture global state atomically to avoid race conditions."""
    discord_rpc_connected = False
    if Settings.DISCORD_PRESENCE and discord_rpc_manager is not None:
        discord_rpc_connected = discord_rpc_manager.connection_status.is_set()

    return StatusBarSnapshot(
        capture_ip_address=Settings.CAPTURE_IP_ADDRESS,
        capture_program_preset=Settings.CAPTURE_PROGRAM_PRESET,
        capture_overflow_timer=Settings.CAPTURE_OVERFLOW_TIMER,
        discord_presence_enabled=Settings.DISCORD_PRESENCE,
        tshark_global_bandwidth=TsharkStats.global_bandwidth,
        tshark_global_download=TsharkStats.global_download,
        tshark_global_upload=TsharkStats.global_upload,
        tshark_global_bps_rate=TsharkStats.global_bps_rate,
        tshark_global_pps_rate=TsharkStats.global_pps_rate,
        tshark_restarted_times=TsharkStats.restarted_times,
        tshark_packets_latencies=list(TsharkStats.packets_latencies),
        userip_invalid_ip_count=len(UserIPDatabases.notified_ip_invalid),
        userip_conflict_ip_count=len(UserIPDatabases.notified_ip_conflicts),
        userip_corrupted_settings_count=len(UserIPDatabases.notified_settings_corrupted),
        interface_name=capture.config.interface.name,
        interface_is_arp=capture.config.interface.is_arp,
        memory_mb=psutil.Process().memory_info().rss / 1024 / 1024,
        discord_rpc_connected=discord_rpc_connected,
    )


def _calculate_latency(packets_latencies: list[tuple[datetime, timedelta]]) -> tuple[float, float]:
    """Calculate average packet latency for the most recent 1-second window."""
    one_second_ago = datetime.now(tz=LOCAL_TZ) - timedelta(seconds=1)
    recent_packets = [(pkt_time, pkt_latency) for pkt_time, pkt_latency in packets_latencies if pkt_time >= one_second_ago]

    TsharkStats.packets_latencies[:] = recent_packets

    if recent_packets:
        total_latency_seconds = sum(pkt_latency.total_seconds() for _, pkt_latency in recent_packets)
        avg_latency_seconds = total_latency_seconds / len(recent_packets)
        avg_latency_rounded = round(avg_latency_seconds, 1)
    else:
        avg_latency_seconds = 0.0
        avg_latency_rounded = 0.0

    return avg_latency_seconds, avg_latency_rounded


def _build_capture_section(snapshot: StatusBarSnapshot) -> str:
    displayed_ip = snapshot.capture_ip_address or 'N/A'
    return (
        f'<span style="font-size: 11px;">'
        f'<span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">📡 Capture:</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Interface:</span> '
        f'<span style="color: {StatusBarColors.ENABLED};">{snapshot.interface_name}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">IP:</span> '
        f'<span style="color: {StatusBarColors.ENABLED};">{displayed_ip}</span>'
        f'</span>'
    )


def _build_config_section(snapshot: StatusBarSnapshot, *, vpn_mode_enabled: bool, discord_rpc_manager: DiscordRPC | None) -> str:
    is_arp_enabled = 'Enabled' if snapshot.interface_is_arp else 'Disabled'
    is_vpn_enabled = 'Enabled' if vpn_mode_enabled else 'Disabled'
    arp_color = StatusBarColors.ENABLED if is_arp_enabled == 'Enabled' else StatusBarColors.DISABLED
    vpn_color = StatusBarColors.ENABLED if is_vpn_enabled == 'Enabled' else StatusBarColors.DISABLED

    discord_display = ''
    if snapshot.discord_presence_enabled and discord_rpc_manager is not None:
        rpc_color = StatusBarColors.ENABLED if snapshot.discord_rpc_connected else StatusBarColors.DISABLED
        rpc_status = 'Connected' if snapshot.discord_rpc_connected else 'Waiting'
        discord_display = (
            f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
            f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Discord:</span> '
            f'<span style="color: {rpc_color};">{rpc_status}</span>'
        )

    return (
        f'<span style="font-size: 11px;">'
        f'<span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">⚙️ Config:</span> '
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">ARP:</span> '
        f'<span style="color: {arp_color};">{is_arp_enabled}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">VPN:</span> '
        f'<span style="color: {vpn_color};">{is_vpn_enabled}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Preset:</span> '
        f'<span style="color: {StatusBarColors.SECONDARY_ACCENT};">{snapshot.capture_program_preset}</span>'
        f'{discord_display}'
        f'</span>'
    )


def _build_userip_issues_section(snapshot: StatusBarSnapshot) -> str:
    if not any([snapshot.userip_invalid_ip_count, snapshot.userip_conflict_ip_count, snapshot.userip_corrupted_settings_count]):
        return ''

    issues: list[str] = []
    if snapshot.userip_invalid_ip_count:
        issues.append(f'<span style="color: {StatusBarColors.DISABLED};">❌ Invalid IPs: {snapshot.userip_invalid_ip_count}</span>')
    if snapshot.userip_conflict_ip_count:
        issues.append(f'<span style="color: {StatusBarColors.DISABLED};">⚠️ Conflicts: {snapshot.userip_conflict_ip_count}</span>')
    if snapshot.userip_corrupted_settings_count:
        issues.append(f'<span style="color: {StatusBarColors.DISABLED};">🔧 Corrupted: {snapshot.userip_corrupted_settings_count}</span>')

    divider = f' <span style="color: {StatusBarColors.DIVIDER};"> • </span> '
    return (
        f'<span style="color: {StatusBarColors.DISABLED}; font-weight: bold;">🧯 UserIP Issues:</span> '
        f'{divider.join(issues)}'
    )


def _build_performance_section(snapshot: StatusBarSnapshot, *, avg_latency_seconds: float, avg_latency_rounded: float) -> str:
    latency_color = (ThresholdColors.CRITICAL if avg_latency_seconds >= 0.90 * snapshot.capture_overflow_timer
                     else ThresholdColors.WARNING if avg_latency_seconds >= 0.75 * snapshot.capture_overflow_timer
                     else ThresholdColors.HEALTHY)
    bandwidth_color = (ThresholdColors.CRITICAL if snapshot.tshark_global_bandwidth >= StatusBarThresholds.BANDWIDTH_CRITICAL
                       else ThresholdColors.WARNING if snapshot.tshark_global_bandwidth >= StatusBarThresholds.BANDWIDTH_WARNING
                       else ThresholdColors.HEALTHY)
    download_color = (ThresholdColors.CRITICAL if snapshot.tshark_global_download >= StatusBarThresholds.DOWNLOAD_CRITICAL
                      else ThresholdColors.WARNING if snapshot.tshark_global_download >= StatusBarThresholds.DOWNLOAD_WARNING
                      else ThresholdColors.HEALTHY)
    upload_color = (ThresholdColors.CRITICAL if snapshot.tshark_global_upload >= StatusBarThresholds.UPLOAD_CRITICAL
                    else ThresholdColors.WARNING if snapshot.tshark_global_upload >= StatusBarThresholds.UPLOAD_WARNING
                    else ThresholdColors.HEALTHY)
    bps_color = (ThresholdColors.CRITICAL if snapshot.tshark_global_bps_rate >= StatusBarThresholds.BPS_CRITICAL
                 else ThresholdColors.WARNING if snapshot.tshark_global_bps_rate >= StatusBarThresholds.BPS_WARNING
                 else ThresholdColors.HEALTHY)
    pps_color = (ThresholdColors.CRITICAL if snapshot.tshark_global_pps_rate >= StatusBarThresholds.PPS_CRITICAL
                 else ThresholdColors.WARNING if snapshot.tshark_global_pps_rate >= StatusBarThresholds.PPS_WARNING
                 else ThresholdColors.HEALTHY)
    memory_color = (ThresholdColors.CRITICAL if snapshot.memory_mb >= StatusBarThresholds.MEMORY_HIGH
                    else ThresholdColors.WARNING if snapshot.memory_mb >= StatusBarThresholds.MEMORY_MEDIUM
                    else ThresholdColors.HEALTHY)
    restart_color = ThresholdColors.HEALTHY if not snapshot.tshark_restarted_times else ThresholdColors.CRITICAL

    return (
        f'<span style="font-size: 11px;">'
        f'<span style="color: {StatusBarColors.TITLE_ACCENT}; font-weight: bold;">⚡ Performance:</span> '
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Latency:</span> '
        f'<span style="color: {latency_color};">{avg_latency_rounded}s</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">↓↑:</span> '
        f'<span style="color: {bandwidth_color};">{PlayerBandwidth.format_bytes(snapshot.tshark_global_bandwidth)}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">↓:</span> '
        f'<span style="color: {download_color};">{PlayerBandwidth.format_bytes(snapshot.tshark_global_download)}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">↑:</span> '
        f'<span style="color: {upload_color};">{PlayerBandwidth.format_bytes(snapshot.tshark_global_upload)}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">BPS:</span> '
        f'<span style="color: {bps_color};">{PlayerBandwidth.format_bytes(snapshot.tshark_global_bps_rate)}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">PPS:</span> '
        f'<span style="color: {pps_color};">{snapshot.tshark_global_pps_rate}</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">RAM:</span> '
        f'<span style="color: {memory_color};">{int(snapshot.memory_mb)} MB</span> '
        f'<span style="color: {StatusBarColors.DIVIDER};"> • </span>'
        f'<span style="color: {StatusBarColors.LABEL_ACCENT};">Restarts:</span> '
        f'<span style="color: {restart_color};">{snapshot.tshark_restarted_times}</span>'
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
    avg_latency_seconds, avg_latency_rounded = _calculate_latency(snapshot.tshark_packets_latencies)

    capture_section = _build_capture_section(snapshot)
    config_section = _build_config_section(snapshot, vpn_mode_enabled=vpn_mode_enabled, discord_rpc_manager=discord_rpc_manager)
    userip_issues_section = _build_userip_issues_section(snapshot)
    performance_section = _build_performance_section(
        snapshot,
        avg_latency_seconds=avg_latency_seconds,
        avg_latency_rounded=avg_latency_rounded,
    )

    return capture_section, config_section, userip_issues_section, performance_section
