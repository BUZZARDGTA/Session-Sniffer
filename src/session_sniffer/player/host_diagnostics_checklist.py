"""Shared Session Host detection criteria checklist evaluation for desktop and web UIs."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from session_sniffer.i18n import tr, tr_plural
from session_sniffer.player.session_host import (
    MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
    SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS,
    SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS,
    SESSION_HOST_MAX_PACKETS_FOR_DETECTION,
)

if TYPE_CHECKING:
    from session_sniffer.player.session_host import HostDiagnosticsSnapshot

type ChecklistBadgeTone = Literal['success', 'warning', 'danger', 'accent', 'muted']


@dataclass(frozen=True, slots=True)
class HostChecklistItem:
    """Evaluated detection criterion row shared by the desktop dialog and web panel."""

    title: str
    passed: bool
    detail: str
    badge_text: str
    badge_tone: ChecklistBadgeTone


def _build_modmenu_checklist(snapshot: HostDiagnosticsSnapshot) -> list[HostChecklistItem]:
    source_name = snapshot.modmenu_source or tr('Mod Menu')
    host_ip = snapshot.modmenu_host_ip
    host_username = snapshot.modmenu_host_username

    if host_ip is not None:
        lua_passed = True
        username_suffix = f' (@{host_username})' if host_username is not None and host_username else ''
        lua_detail = tr(
            '{source} Lua plugin reported session host {host_ip}{username_suffix}',
            source=source_name,
            host_ip=host_ip,
            username_suffix=username_suffix,
        )
        lua_badge = tr('✓ {source} Lua', source=source_name)
        lua_tone: ChecklistBadgeTone = 'success'
    else:
        lua_passed = False
        lua_detail = snapshot.rejection_reason or snapshot.outcome
        lua_badge = tr('No Remote Host')
        lua_tone = 'warning'

    if snapshot.success and snapshot.detected_host_ip is not None:
        match_passed = True
        match_detail = tr(
            'Reported host {host_ip} matched an active GTA V UDP-confirmed P2P player in your session',
            host_ip=snapshot.detected_host_ip,
        )
        match_badge = tr('✓ Matched in Session')
        match_tone: ChecklistBadgeTone = 'success'
    elif host_ip is not None:
        match_passed = False
        match_detail = tr(
            'Reported host {host_ip} is not currently connected in confirmed GTA V P2P session traffic',
            host_ip=host_ip,
        )
        match_badge = tr('✕ Not Connected')
        match_tone = 'warning'
    else:
        p2p_count = snapshot.direct_p2p_players
        match_passed = False
        match_detail = tr_plural(
            '{count} direct P2P player currently connected in session',
            '{count} direct P2P players currently connected in session',
            p2p_count,
        )
        match_badge = tr('{count} Direct P2P', count=p2p_count)
        match_tone = 'accent' if p2p_count > 0 else 'muted'

    return [
        HostChecklistItem(
            title=tr('{source} Lua Plugin (Source of Truth)', source=source_name),
            passed=lua_passed,
            detail=lua_detail,
            badge_text=lua_badge,
            badge_tone=lua_tone,
        ),
        HostChecklistItem(
            title=tr('Direct P2P Session Match'),
            passed=match_passed,
            detail=match_detail,
            badge_text=match_badge,
            badge_tone=match_tone,
        ),
    ]


def _build_p2p_candidates_item(snapshot: HostDiagnosticsSnapshot) -> HostChecklistItem:
    p2p_count = snapshot.direct_p2p_players
    evaluated_count = snapshot.total_evaluated_players
    filtered_count = snapshot.filtered_server_ips

    if not evaluated_count:
        detail = tr('No players found in session')
    elif not p2p_count:
        detail = tr_plural(
            'All {count} connected endpoint is a game or relay server',
            'All {count} connected endpoints are game or relay servers',
            evaluated_count,
        )
    elif filtered_count > 0:
        candidates_phrase = tr_plural(
            '{count} direct P2P candidate identified',
            '{count} direct P2P candidates identified',
            p2p_count,
        )
        filtered_phrase = tr_plural(
            '{count} server filtered',
            '{count} servers filtered',
            filtered_count,
        )
        detail = tr('{candidates} ({filtered})', candidates=candidates_phrase, filtered=filtered_phrase)
    else:
        detail = tr_plural(
            '{count} direct P2P candidate identified in session',
            '{count} direct P2P candidates identified in session',
            p2p_count,
        )

    passed = p2p_count > 0
    return HostChecklistItem(
        title=tr('Direct P2P Candidates'),
        passed=passed,
        detail=detail,
        badge_text=tr('{count} Direct P2P', count=p2p_count) if passed else tr('0 Direct P2P'),
        badge_tone='success' if passed else 'danger',
    )


def _build_activity_item(snapshot: HostDiagnosticsSnapshot) -> HostChecklistItem:
    if snapshot.success:
        return HostChecklistItem(
            title=tr('Candidate Activity'),
            passed=True,
            detail=tr('Candidate is active and connected'),
            badge_text=tr('Active & Connected'),
            badge_tone='success',
        )
    if snapshot.candidates:
        active_count = sum(
            1 for candidate in snapshot.candidates if not candidate.is_pending_disconnection and not candidate.is_disconnected
        )
        if active_count > 0:
            return HostChecklistItem(
                title=tr('Candidate Activity'),
                passed=True,
                detail=tr_plural(
                    '{count} candidate active and connected',
                    '{count} candidates active and connected',
                    active_count,
                ),
                badge_text=tr('{count} Active', count=active_count),
                badge_tone='success',
            )
        return HostChecklistItem(
            title=tr('Candidate Activity'),
            passed=False,
            detail=tr('All candidates are disconnected or pending disconnection'),
            badge_text=tr('Disconnected'),
            badge_tone='danger',
        )
    return HostChecklistItem(
        title=tr('Candidate Activity'),
        passed=False,
        detail=tr('No candidates available to evaluate activity'),
        badge_text=tr('No Candidates'),
        badge_tone='muted',
    )


def _build_timing_item(snapshot: HostDiagnosticsSnapshot) -> HostChecklistItem:
    if snapshot.timing_gap_seconds is not None:
        gap_ms = snapshot.timing_gap_seconds * 1000
        gap_ms_str = f'{gap_ms:.1f}'
        gap_text = f'{snapshot.timing_gap_seconds:.3f}s' if snapshot.timing_gap_seconds >= 1.0 else f'{gap_ms:.1f}ms'
        if snapshot.success or SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS <= gap_ms <= SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS:
            return HostChecklistItem(
                title=tr('Connection Timing Window'),
                passed=True,
                detail=snapshot.timing_resolution
                or tr('Join separation ({gap_ms}ms) within valid window (50ms - 1,600ms)', gap_ms=gap_ms_str),
                badge_text=tr('✓ Within Window ({gap_ms}ms)', gap_ms=gap_ms_str),
                badge_tone='success',
            )
        if gap_ms < SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS:
            return HostChecklistItem(
                title=tr('Connection Timing Window'),
                passed=False,
                detail=snapshot.timing_resolution
                or tr('Ambiguous ({gap_ms}ms < 50ms): players connected simultaneously', gap_ms=gap_ms_str),
                badge_text=tr('✕ Too Close ({gap_ms}ms < 50ms)', gap_ms=gap_ms_str),
                badge_tone='warning',
            )
        return HostChecklistItem(
            title=tr('Connection Timing Window'),
            passed=False,
            detail=snapshot.timing_resolution
            or tr('Gap too large ({gap_text} > 1,600ms): candidates did not join together', gap_text=gap_text),
            badge_text=tr('✕ Exceeds Window ({gap_text} > 1600ms)', gap_text=gap_text),
            badge_tone='danger',
        )

    if snapshot.success or len(snapshot.candidates) == 1:
        return HostChecklistItem(
            title=tr('Connection Timing Window'),
            passed=True,
            detail=snapshot.timing_resolution or tr('Single candidate in session (timing comparison not required)'),
            badge_text=tr('Single Candidate'),
            badge_tone='accent',
        )
    return HostChecklistItem(
        title=tr('Connection Timing Window'),
        passed=False,
        detail=snapshot.timing_resolution or tr('No candidates available for timing comparison'),
        badge_text=tr('N/A'),
        badge_tone='muted',
    )


def _build_packet_threshold_item(snapshot: HostDiagnosticsSnapshot) -> HostChecklistItem:
    if snapshot.success:
        host_candidate = next(
            (candidate for candidate in snapshot.candidates if candidate.is_host),
            snapshot.candidates[0] if snapshot.candidates else None,
        )
        detail = (
            tr(
                'Candidate sent >= 9 packets ({sent}) and exchanged <= 1,000 ({exchanged})',
                sent=host_candidate.packets_sent,
                exchanged=host_candidate.packets_exchanged,
            )
            if host_candidate is not None
            else tr('Candidate packet counts within valid bounds (>= 9 sent, <= 1,000 exchanged)')
        )
        return HostChecklistItem(
            title=tr('Packet Threshold Criteria'),
            passed=True,
            detail=detail,
            badge_text=tr('Eligible Packets'),
            badge_tone='success',
        )
    if not snapshot.candidates:
        return HostChecklistItem(
            title=tr('Packet Threshold Criteria'),
            passed=False,
            detail=tr('No candidates to evaluate packet thresholds'),
            badge_text=tr('No Candidates'),
            badge_tone='muted',
        )

    has_under_sent = any(
        candidate.packet_status == 'Not enough sent' or candidate.packets_sent < MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST
        for candidate in snapshot.candidates
    )
    if has_under_sent:
        return HostChecklistItem(
            title=tr('Packet Threshold Criteria'),
            passed=False,
            detail=tr(
                'Candidate has not sent enough packets (>= {min_packets} required to rule out transient probes)',
                min_packets=MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
            ),
            badge_text=tr('✕ < {min_packets} Sent', min_packets=MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST),
            badge_tone='warning',
        )

    has_over_exchanged = any(
        candidate.packet_status == 'Exceeds maximum exchanged' or candidate.packets_exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION
        for candidate in snapshot.candidates
    )
    max_packets_str = f'{SESSION_HOST_MAX_PACKETS_FOR_DETECTION:,}'
    if has_over_exchanged:
        return HostChecklistItem(
            title=tr('Packet Threshold Criteria'),
            passed=False,
            detail=tr('Candidate exchanged > {max_packets} packets (session already in progress)', max_packets=max_packets_str),
            badge_text=tr('✕ > {max_packets} Exchanged', max_packets=max_packets_str),
            badge_tone='danger',
        )

    return HostChecklistItem(
        title=tr('Packet Threshold Criteria'),
        passed=True,
        detail=tr(
            'Candidate packet counts within valid bounds (>= {min_packets} sent, <= {max_packets} exchanged)',
            min_packets=MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
            max_packets=max_packets_str,
        ),
        badge_text=tr('Eligible Packets'),
        badge_tone='success',
    )


def build_host_diagnostics_checklist(snapshot: HostDiagnosticsSnapshot) -> list[HostChecklistItem]:
    """Compute the localized detection criteria checklist rows for *snapshot*."""
    if snapshot.modmenu_source is not None:
        return _build_modmenu_checklist(snapshot)
    return [
        _build_p2p_candidates_item(snapshot),
        _build_activity_item(snapshot),
        _build_timing_item(snapshot),
        _build_packet_threshold_item(snapshot),
    ]
