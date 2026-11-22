"""Read-only Session Host diagnostics JSON payload builder for the embedded web server."""

from datetime import datetime
from typing import TYPE_CHECKING

from session_sniffer.i18n import tr, tr_plural
from session_sniffer.player.host_diagnostics_checklist import build_host_diagnostics_checklist
from session_sniffer.player.session_host import SessionHost
from session_sniffer.rendering_core.country_flags import has_country_flag
from session_sniffer.text_utils import format_elapsed_time

if TYPE_CHECKING:
    from session_sniffer.player.session_host import HostCandidateDiagnostic, HostDiagnosticsSnapshot, HostHistoryEntry


def _normalize_flag_code(country_code: str) -> str:
    code = country_code.strip().upper()
    return code if has_country_flag(code) else ''


def _find_history_diagnostics(history: list[HostHistoryEntry], ip_address: str | None) -> HostDiagnosticsSnapshot | None:
    if ip_address is not None:
        matched = next((entry.diagnostics for entry in reversed(history) if entry.ip == ip_address and entry.diagnostics is not None), None)
        if matched is not None:
            return matched
    return next((entry.diagnostics for entry in reversed(history) if entry.diagnostics is not None), None)


def _resolve_diagnostics_snapshot(
    *,
    ip_address: str | None = None,
    session_id: int | None = None,
) -> HostDiagnosticsSnapshot | None:
    """Resolve the best matching recorded `HostDiagnosticsSnapshot` without mutating state."""
    if session_id is not None:
        return _find_history_diagnostics(SessionHost.get_history(session_id=session_id), ip_address)

    last_diag = SessionHost.last_diagnostics
    if ip_address is not None:
        if last_diag is not None and last_diag.detected_host_ip == ip_address:
            return last_diag
        return _find_history_diagnostics(SessionHost.get_history(), ip_address) or last_diag

    return last_diag or _find_history_diagnostics(SessionHost.get_history(), None)


def _serialize_candidate(index: int, candidate: HostCandidateDiagnostic) -> dict[str, object]:
    pills: list[dict[str, str]] = []
    if candidate.is_host:
        pills.append({'label': tr('✓ SESSION HOST'), 'tone': 'success'})
    if candidate.is_pending_disconnection:
        pills.append({'label': tr('Pending Disconnect'), 'tone': 'warning'})
    if candidate.is_relayed:
        pills.append({'label': tr('Relayed'), 'tone': 'accent'})
    if candidate.is_disconnected:
        pills.append({'label': tr('Disconnected'), 'tone': 'muted'})

    packet_status_map = {
        'Authoritative (Mod Menu Lua)': (tr('✓ Mod Menu Lua'), 'success'),
        'Connected P2P': (tr('Connected P2P'), 'accent'),
        'Eligible': (tr('✓ Eligible'), 'success'),
        'Not enough sent': (tr('✕ < 9 Sent'), 'warning'),
    }
    packet_badge, packet_tone = packet_status_map.get(candidate.packet_status, (tr('✕ > 1000 Exchanged'), 'danger'))

    now = datetime.now(tz=candidate.last_rejoin.tzinfo)
    rejoin_str = candidate.last_rejoin.strftime('%H:%M:%S.%f')[:-3]
    elapsed_str = format_elapsed_time(now - candidate.last_rejoin)

    return {
        'index': index,
        'ip': candidate.ip,
        'usernames': list(candidate.usernames),
        'country_code': _normalize_flag_code(candidate.country_code),
        'is_host': candidate.is_host,
        'pills': pills,
        'metrics': [
            {
                'label': tr('Last Rejoin:'),
                'value': tr('{rejoin_str} ({elapsed_str} ago)', rejoin_str=rejoin_str, elapsed_str=elapsed_str),
                'ltr': True,
            },
            {
                'label': tr('Packets Sent:'),
                'value': f'{candidate.packets_sent:,}',
                'ltr': True,
                'badge': packet_badge,
                'badge_tone': packet_tone,
            },
            {
                'label': tr('Packets Received / Exchanged:'),
                'value': tr(
                    '{recv} recv / {total} total',
                    recv=f'{candidate.packets_received:,}',
                    total=f'{candidate.packets_exchanged:,}',
                ),
                'ltr': True,
            },
        ],
    }


def build_host_diagnostics_payload(
    *,
    ip_address: str | None = None,
    session_id: int | None = None,
) -> dict[str, object]:
    """Build the localized JSON payload for `GET /api/host-diagnostics`."""
    snapshot = _resolve_diagnostics_snapshot(ip_address=ip_address, session_id=session_id)
    if snapshot is None:
        empty_message = (
            tr('No session host detection diagnostics were recorded for host {ip}.', ip=ip_address)
            if ip_address is not None
            else tr('No session host detection diagnostics are available yet.')
        )
        return {
            'available': False,
            'message': empty_message,
        }

    is_success = snapshot.success and bool(snapshot.detected_host_ip)
    evaluated_items = build_host_diagnostics_checklist(snapshot)
    checklist_items = [
        {
            'title': item.title,
            'passed': item.passed,
            'status_label': tr('PASS') if item.passed else tr('FAIL'),
            'detail': item.detail,
            'badge': item.badge_text,
            'tone': item.badge_tone,
        }
        for item in evaluated_items
    ]
    passed_count = sum(1 for item in evaluated_items if item.passed)
    total_count = len(evaluated_items)
    if passed_count == total_count:
        checklist_tone = 'success'
    elif passed_count > 0:
        checklist_tone = 'warning'
    else:
        checklist_tone = 'danger'

    filtered_servers_payload: dict[str, str] | None = None
    if snapshot.filtered_servers:
        filtered_count = len(snapshot.filtered_servers)
        filtered_servers_payload = {
            'title': tr_plural(
                'Filtered Game & Relay Server ({count})',
                'Filtered Game & Relay Servers ({count})',
                filtered_count,
            ),
            'text': ', '.join(
                tr('{server_ip} ({exchanged} pkts)', server_ip=server_ip, exchanged=exchanged)
                for server_ip, exchanged in snapshot.filtered_servers
            ),
        }

    return {
        'available': True,
        'success': is_success,
        'hero': {
            'title': tr('Session Host Detected') if is_success else tr('Host Not Detected'),
            'ip': snapshot.detected_host_ip or '',
            'usernames': list(snapshot.detected_host_usernames),
            'country_code': _normalize_flag_code(snapshot.detected_host_country_code),
            'reason': '' if is_success else (snapshot.rejection_reason or snapshot.outcome),
            'evaluated_at': tr('Evaluation performed at {time}', time=snapshot.timestamp.strftime('%H:%M:%S')),
        },
        'stats': [
            {'label': tr('Total Evaluated'), 'value': str(snapshot.total_evaluated_players), 'tone': 'accent'},
            {'label': tr('Direct P2P Players'), 'value': str(snapshot.direct_p2p_players), 'tone': 'success'},
            {'label': tr('Filtered Server IPs'), 'value': str(snapshot.filtered_server_ips), 'tone': 'muted'},
        ],
        'checklist': {
            'title': tr('Detection Criteria Checklist'),
            'summary': tr('{passed}/{total} Passed', passed=passed_count, total=total_count),
            'tone': checklist_tone,
            'items': checklist_items,
        },
        'candidates': {
            'title': tr('Evaluated Candidates ({count})', count=len(snapshot.candidates)),
            'empty_text': tr('No direct peer-to-peer player candidates were evaluated in this session.'),
            'items': [_serialize_candidate(index, candidate) for index, candidate in enumerate(snapshot.candidates, start=1)],
        },
        'filtered_servers': filtered_servers_payload,
        'raw_details': snapshot.raw_details,
    }
