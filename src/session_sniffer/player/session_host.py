"""Session host detection, diagnostic snapshots, and candidate tracking."""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from heapq import nsmallest
from operator import attrgetter
from typing import TYPE_CHECKING, ClassVar

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.exceptions import UnexpectedPlayerCountError
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.text_utils import format_elapsed_time, pluralize

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

logger = logging.getLogger(__name__)

MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST = 9
MAXIMUM_PACKETS_FOR_RELAY_SESSION_HOST = 40
SESSION_HOST_MAX_PACKETS_FOR_DETECTION = 1000
SESSION_HOST_CANDIDATE_PLAYERS_COUNT = 2
SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS = 50
SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS = 1600
SESSION_HOST_SEARCH_TIMEOUT_SECONDS = 30
SESSION_HOST_STARTUP_WINDOW_SECONDS = 1.0
_SESSION_HOST_AMBIGUITY_MIN_TD = timedelta(milliseconds=SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS)
_SESSION_HOST_AMBIGUITY_MAX_TD = timedelta(milliseconds=SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS)


@dataclass(slots=True)
class HostCandidateDiagnostic:
    """Diagnostic details for a candidate evaluated during session host detection."""

    ip: str
    usernames: list[str]
    country_code: str
    last_rejoin: datetime
    packets_sent: int
    packets_received: int
    packets_exchanged: int
    packet_status: str
    is_host: bool
    is_pending_disconnection: bool
    is_relayed: bool
    is_disconnected: bool


@dataclass(slots=True)
class HostDiagnosticsSnapshot:
    """Comprehensive diagnostic snapshot from a session host detection evaluation."""

    timestamp: datetime
    success: bool
    outcome: str
    rejection_reason: str | None
    detected_host_ip: str | None
    detected_host_usernames: list[str]
    detected_host_country_code: str
    total_evaluated_players: int
    direct_p2p_players: int
    filtered_server_ips: int
    timing_gap_seconds: float | None
    timing_resolution: str | None
    candidates: list[HostCandidateDiagnostic]
    filtered_servers: list[tuple[str, int]]
    raw_details: str


@dataclass(slots=True)
class HostHistoryEntry:
    """Snapshot of a session host at the time of detection."""

    ip: str
    detected_at: datetime
    country_code: str
    diagnostics: HostDiagnosticsSnapshot | None = None
    session_id: int | None = None

    @property
    def dialog_key(self) -> str:
        """Return the unique dialog key for this host history entry."""
        return f'host_history_{self.ip}_{self.detected_at.isoformat()}'


@dataclass(slots=True)
class _DetectionEvaluationResult:
    """Internal evaluation outcome and details for session host detection."""

    outcome: str
    rejection_reason: str | None = None
    detected_host: Player | None = None
    timing_gap: float | None = None


def _build_host_diagnostics_snapshot(
    session_players: list[Player],
    candidates: list[Player],
    result: _DetectionEvaluationResult,
) -> HostDiagnosticsSnapshot:
    """Build a structured diagnostic snapshot and raw formatted details for session host detection."""
    now = datetime.now(tz=LOCAL_TZ)
    p2p_players = [player for player in session_players if not player.is_third_party_server]

    candidate_diagnostics: list[HostCandidateDiagnostic] = []
    for player in candidates:
        if player.packets.sent < MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST:
            packets_status = 'Not enough sent'
        elif player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION:
            packets_status = 'Exceeds maximum exchanged'
        else:
            packets_status = 'Eligible'

        country = (
            player.iplookup.geolite2.country_code
            if player.iplookup.geolite2.country_code not in {'...', 'N/A'}
            else player.iplookup.ipapi.country_code
        )

        candidate_diagnostics.append(
            HostCandidateDiagnostic(
                ip=player.ip,
                usernames=list(player.usernames),
                country_code=country,
                last_rejoin=player.datetime.last_rejoin,
                packets_sent=player.packets.sent,
                packets_received=player.packets.received,
                packets_exchanged=player.packets.exchanged,
                packet_status=packets_status,
                is_host=result.detected_host is not None and player.ip == result.detected_host.ip,
                is_pending_disconnection=player in SessionHost.players_pending_for_disconnection,
                is_relayed=not bool(player.packets.received),
                is_disconnected=player.left_event.is_set(),
            )
        )

    filtered_servers = [
        (player.ip, player.packets.exchanged)
        for player in session_players
        if player.is_third_party_server
    ]

    timing_resolution: str | None = None
    if result.timing_gap is not None:
        gap_milliseconds = result.timing_gap * 1000
        time_difference_text = f'{result.timing_gap:.3f}s ({gap_milliseconds:.1f}ms)' if result.timing_gap >= 1.0 else f'{gap_milliseconds:.1f}ms'
        if SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS <= gap_milliseconds <= SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS:
            timing_resolution = (
                '2 candidates were evaluated, and candidate #1 joined earlier\n'
                f'within the valid timing window ({SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS}ms - {SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS}ms).'
            )
        elif gap_milliseconds < SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS:
            timing_resolution = (
                f'Rejected — {gap_milliseconds:.1f}ms gap is below the {SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS}ms minimum threshold\n'
                '(players connected almost simultaneously, timing is ambiguous).'
            )
        else:
            timing_resolution = (
                f'Rejected — {time_difference_text} gap exceeds the {SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS}ms maximum threshold\n'
                '(candidate #1 joined too far ahead of candidate #2).'
            )
    elif len(candidates) == 1:
        timing_resolution = 'Only 1 non-server player was present, so timing comparison was skipped.'

    timing_resolution_summary = timing_resolution.replace('\n', ' ') if timing_resolution is not None else ''

    lines: list[str] = [
        '=== Session Host Detection Diagnostics ===',
        f'Outcome: {result.outcome}',
        '',
        '--- Session Overview ---',
        f'- Total Evaluated Players: {len(session_players)}',
        f'- Direct P2P Players: {len(p2p_players)}',
        f'- Filtered Server IPs: {len(session_players) - len(p2p_players)}',
        '',
        '--- Detection Criteria ---',
        f'- Candidate Timing Gap Window: {SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS}ms - {SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS}ms',
        f'- Minimum Sent Packets Required: {MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST}',
        f'- Maximum Exchanged Packets Limit: {SESSION_HOST_MAX_PACKETS_FOR_DETECTION}',
    ]

    if result.timing_gap is not None:
        gap_milliseconds = result.timing_gap * 1000
        time_difference_text = f'{result.timing_gap:.3f}s ({gap_milliseconds:.1f}ms)' if result.timing_gap >= 1.0 else f'{gap_milliseconds:.1f}ms'
        lines.extend([
            '',
            '--- Timing Analysis ---',
            f'- Time Difference: {time_difference_text}',
            f'- Timing Gap Resolution: {timing_resolution_summary}',
        ])
    elif len(candidates) == 1:
        lines.extend([
            '',
            '--- Timing Analysis ---',
            f'- Sole P2P Player: {timing_resolution_summary}',
        ])

    if candidates:
        lines.extend([
            '',
            '--- Evaluated Candidates ---',
        ])
        for index, player in enumerate(candidates, start=1):
            rejoin_time = player.datetime.last_rejoin.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            rejoin_ago = format_elapsed_time(now - player.datetime.last_rejoin)
            if player.packets.sent < MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST:
                packets_status_text = 'Not enough sent'
            elif player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION:
                packets_status_text = 'Exceeds maximum exchanged'
            else:
                packets_status_text = 'Enough'
            username_suffix = f' ({", ".join(player.usernames)})' if player.usernames else ''
            candidate_lines = [
                f'Candidate #{index}:',
                f'  IP Address: {player.ip}{username_suffix}',
                f'  Last Rejoin: {rejoin_time} ({rejoin_ago} ago)',
                f'  Packets Sent: {player.packets.sent} ({packets_status_text})',
                f'  Packets Received: {player.packets.received}',
                f'  Packets Exchanged: {player.packets.exchanged}',
            ]
            if player in SessionHost.players_pending_for_disconnection:
                candidate_lines.append('  Note: Pending Disconnection')
            if not player.packets.received:
                candidate_lines.append('  Note: Relayed (0 received packets)')
            if player.left_event.is_set():
                candidate_lines.append('  Note: Disconnected')
            lines.extend(candidate_lines)

    if filtered_servers:
        lines.extend([
            '',
            '--- Filtered Server List ---',
            *(f'  - {server_ip} ({exchanged} packets)' for server_ip, exchanged in filtered_servers),
        ])

    detected_host = result.detected_host
    host_ip = detected_host.ip if detected_host is not None else None
    host_usernames = list(detected_host.usernames) if detected_host is not None else []
    host_country = (
        (detected_host.iplookup.geolite2.country_code
         if detected_host.iplookup.geolite2.country_code not in {'...', 'N/A'}
         else detected_host.iplookup.ipapi.country_code)
        if detected_host is not None
        else ''
    )

    return HostDiagnosticsSnapshot(
        timestamp=now,
        success=detected_host is not None,
        outcome=result.outcome,
        rejection_reason=result.rejection_reason,
        detected_host_ip=host_ip,
        detected_host_usernames=host_usernames,
        detected_host_country_code=host_country,
        total_evaluated_players=len(session_players),
        direct_p2p_players=len(p2p_players),
        filtered_server_ips=len(session_players) - len(p2p_players),
        timing_gap_seconds=result.timing_gap,
        timing_resolution=timing_resolution,
        candidates=candidate_diagnostics,
        filtered_servers=filtered_servers,
        raw_details='\n'.join(lines),
    )


class SessionHost:
    """Track the inferred session host and pending disconnections."""

    _player: ClassVar[Player | None] = None
    search_player: ClassVar[bool] = False
    manual_redetect: ClassVar[bool] = False
    search_start_time: ClassVar[float | None] = None
    players_pending_for_disconnection: ClassVar[list[Player]] = []
    last_timing_gap_candidate: ClassVar[tuple[str, str] | None] = None
    last_rejection_reason: ClassVar[str | None] = None
    last_diagnostics: ClassVar[HostDiagnosticsSnapshot | None] = None
    last_detection_success: ClassVar[bool] = False
    last_detected_host_ip: ClassVar[str | None] = None
    _history: ClassVar[list[HostHistoryEntry]] = []

    @classmethod
    def get_player(cls) -> Player | None:
        """Return the currently detected session host player."""
        return cls._player

    @classmethod
    def set_player(cls, player: Player | None) -> None:
        """Set the currently detected session host player."""
        cls._player = player

    @classmethod
    def has_player(cls) -> bool:
        """Return True if a session host player is currently detected."""
        return cls._player is not None

    @classmethod
    def is_host(cls, player_ip: str) -> bool:
        """Return True if player_ip is the currently detected session host."""
        return cls._player is not None and cls._player.ip == player_ip

    @classmethod
    def is_relay_host_candidate(cls, player: Player) -> bool:
        """Return True if the player matches the criteria for a relay session host."""
        return (
            not player.is_third_party_server
            and not player.packets.received
            and MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST <= player.packets.sent <= MAXIMUM_PACKETS_FOR_RELAY_SESSION_HOST
        )

    @classmethod
    def clear_session_host_data(cls) -> None:
        """Clear active session host data including pending disconnections."""
        cls.players_pending_for_disconnection.clear()
        cls.search_player = False
        cls.manual_redetect = False
        cls.search_start_time = None
        cls._player = None
        cls.last_timing_gap_candidate = None

    @classmethod
    def record_host(
        cls,
        player: Player,
        diagnostics: HostDiagnosticsSnapshot | None = None,
        session_id: int | None = None,
    ) -> None:
        """Snapshot the given player as a detected session host and append to history."""
        country_code = (
            player.iplookup.geolite2.country_code
            if player.iplookup.geolite2.country_code not in {'...', 'N/A'}
            else player.iplookup.ipapi.country_code
        )
        if session_id is None:
            session_id = SessionTracker.get_current_session_id()
        cls._history.append(
            HostHistoryEntry(
                ip=player.ip,
                detected_at=datetime.now(tz=LOCAL_TZ),
                country_code=country_code,
                diagnostics=diagnostics,
                session_id=session_id,
            ),
        )

    @classmethod
    def get_history(cls, session_id: int | None = None) -> list[HostHistoryEntry]:
        """Return a snapshot list of the in-memory session host history, optionally filtered by session."""
        if session_id is not None:
            return [entry for entry in cls._history if entry.session_id == session_id]
        return list(cls._history)

    @classmethod
    def clear_history(cls) -> None:
        """Clear the in-memory session host history."""
        cls._history.clear()

    @classmethod
    def get_host_player(cls, session_connected: list[Player]) -> Player | None:
        """Infer and cache the session host from currently connected players and eligible relay candidates."""
        if not session_connected:
            cls.last_detection_success = False
            cls.last_rejection_reason = 'No other players are currently connected in your session.'
            cls.last_diagnostics = _build_host_diagnostics_snapshot(
                session_players=[],
                candidates=[],
                result=_DetectionEvaluationResult(
                    outcome='No connected players found in current session.',
                    rejection_reason=cls.last_rejection_reason,
                ),
            )
            return None

        candidates = list(session_connected)
        p2p_connected = [player for player in session_connected if not player.is_third_party_server]
        if p2p_connected:
            earliest_connected_time = min(player.datetime.last_rejoin for player in p2p_connected)
            for disconnected_player in PlayersRegistry.get_disconnected_players():
                if (
                    cls.is_relay_host_candidate(disconnected_player)
                    and abs(earliest_connected_time - disconnected_player.datetime.last_rejoin) <= _SESSION_HOST_AMBIGUITY_MAX_TD
                    and disconnected_player not in candidates
                ):
                    candidates.append(disconnected_player)

        p2p_players = [player for player in candidates if not player.is_third_party_server]
        if not p2p_players:
            cls.last_detection_success = False
            cls.last_rejection_reason = f'All {len(candidates)} connected IP{pluralize(len(candidates))} are game or relay servers, not direct peer-to-peer players.'
            cls.last_diagnostics = _build_host_diagnostics_snapshot(
                session_players=candidates,
                candidates=[],
                result=_DetectionEvaluationResult(
                    outcome='All connected IPs matched known server ranges.',
                    rejection_reason=cls.last_rejection_reason,
                ),
            )
        active_p2p_players = [
            player
            for player in p2p_players
            if (not player.left_event.is_set() or cls.is_relay_host_candidate(player))
            and player not in cls.players_pending_for_disconnection
        ]
        if not active_p2p_players:
            cls.last_detection_success = False
            cls.last_rejection_reason = f'All connected peer-to-peer player{pluralize(len(p2p_players))} are disconnecting, so the session host cannot be determined.'
            cls.last_diagnostics = _build_host_diagnostics_snapshot(
                session_players=candidates,
                candidates=[],
                result=_DetectionEvaluationResult(
                    outcome=f'All connected P2P player{pluralize(len(p2p_players))} are pending disconnection.',
                    rejection_reason=cls.last_rejection_reason,
                ),
            )
            cls.search_player = False
            cls.search_start_time = None
            return None
        connected_players: list[Player] = nsmallest(SESSION_HOST_CANDIDATE_PLAYERS_COUNT, active_p2p_players, key=attrgetter('datetime.last_rejoin'))

        potential_session_host_player: Player | None = None
        gap_seconds: float | None = None

        if len(connected_players) == 1:
            potential_session_host_player = connected_players[0]
        elif len(connected_players) == SESSION_HOST_CANDIDATE_PLAYERS_COUNT:
            time_difference = connected_players[1].datetime.last_rejoin - connected_players[0].datetime.last_rejoin
            gap_seconds = time_difference.total_seconds()
            gap_milliseconds = gap_seconds * 1000
            if time_difference > _SESSION_HOST_AMBIGUITY_MAX_TD:
                cls.last_detection_success = False
                cls.search_player = False
                cls.search_start_time = None
                cls.last_rejection_reason = (
                    f'The connection time gap between the first two players is too large ({gap_seconds:.1f}s gap).\n\n'
                    'Host detection requires players to connect together during session creation.'
                )
                cls.last_diagnostics = _build_host_diagnostics_snapshot(
                    session_players=candidates,
                    candidates=connected_players,
                    result=_DetectionEvaluationResult(
                        outcome=(
                            f'Connection time gap is too large: {gap_seconds:.1f}s gap exceeds maximum threshold '
                            f'({SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS}ms); players did not connect together.'
                        ),
                        rejection_reason=cls.last_rejection_reason,
                        timing_gap=gap_seconds,
                    ),
                )
                return None
            if time_difference >= _SESSION_HOST_AMBIGUITY_MIN_TD:
                potential_session_host_player = connected_players[0]
            else:
                cls.last_detection_success = False
                cls.last_rejection_reason = (
                    f'The first two players connected almost at the exact same moment ({gap_milliseconds:.1f}ms apart).\n\n'
                    'Their connection times are too close to determine who hosted the session.'
                )
                cls.last_diagnostics = _build_host_diagnostics_snapshot(
                    session_players=candidates,
                    candidates=connected_players,
                    result=_DetectionEvaluationResult(
                        outcome=(
                            f'Connection times are too close to determine host: first two players connected almost simultaneously '
                            f'({gap_milliseconds:.1f}ms apart; minimum separation is {SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS}ms).'
                        ),
                        rejection_reason=cls.last_rejection_reason,
                        timing_gap=gap_seconds,
                    ),
                )
                cls.search_player = False
                cls.search_start_time = None
                return None
        else:
            raise UnexpectedPlayerCountError(len(connected_players))

        # Both sole-candidate and two-candidate paths use MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST.
        # GTA5 matchmaking briefly probes other sessions' hosts (9-40 sent packet transient handshakes)
        # — a lone candidate in that range could be a probe, but it could equally be a relay host
        # that disconnected while alone in the session. Using the minimum threshold for both paths
        # ensures relay hosts with few packets are detected rather than silently missed.
        is_sole_p2p_candidate = len(connected_players) == 1

        if (
            not potential_session_host_player
            # Skip players remaining to be disconnected from the previous session.
            or potential_session_host_player in cls.players_pending_for_disconnection
            # The lower this value, the riskier it becomes, as it could potentially flag a player who ultimately isn't part of the newly discovered session.
            # In such scenarios, a better approach might involve checking around 25-100 packets.
            # However, increasing this value also increases the risk, as the host may have already disconnected.
            or potential_session_host_player.packets.sent < MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST
            # A candidate with too many packets has been connected far too long to be the host of a
            # newly joined session — host detection only applies at session join time.
            # Skip this check for manual re-detects: the user explicitly requested re-detection,
            # so packet count is irrelevant (the session is already in progress).
            or (not cls.manual_redetect and potential_session_host_player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION)
        ):
            cls.last_detection_success = False
            if not potential_session_host_player:
                cls.last_rejection_reason = 'No potential host candidate could be selected.'
                cls.last_diagnostics = _build_host_diagnostics_snapshot(
                    session_players=candidates,
                    candidates=connected_players,
                    result=_DetectionEvaluationResult(
                        outcome='No potential host candidate could be selected.',
                        rejection_reason=cls.last_rejection_reason,
                        timing_gap=gap_seconds,
                    ),
                )
            elif potential_session_host_player in cls.players_pending_for_disconnection:
                cls.last_rejection_reason = f'Candidate player {potential_session_host_player.ip} is currently disconnecting or leaving the session.'
                cls.last_diagnostics = _build_host_diagnostics_snapshot(
                    session_players=candidates,
                    candidates=connected_players,
                    result=_DetectionEvaluationResult(
                        outcome=f'Candidate player {potential_session_host_player.ip} is currently disconnecting or leaving the session.',
                        rejection_reason=cls.last_rejection_reason,
                        timing_gap=gap_seconds,
                    ),
                )
            elif potential_session_host_player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION:
                cls.search_player = False
                cls.search_start_time = None
                cls.last_rejection_reason = (
                    f'Candidate player {potential_session_host_player.ip} has already exchanged too many packets to determine if they originally hosted the session.'
                )
                cls.last_diagnostics = _build_host_diagnostics_snapshot(
                    session_players=candidates,
                    candidates=connected_players,
                    result=_DetectionEvaluationResult(
                        outcome=(
                            f'Candidate {potential_session_host_player.ip} packet count ({potential_session_host_player.packets.exchanged}) '
                            f'exceeds maximum allowed threshold ({SESSION_HOST_MAX_PACKETS_FOR_DETECTION}).'
                        ),
                        rejection_reason=cls.last_rejection_reason,
                        timing_gap=gap_seconds,
                    ),
                )
            else:
                if not is_sole_p2p_candidate:
                    cls.last_timing_gap_candidate = (connected_players[0].ip, connected_players[1].ip)
                    cls.search_player = False
                    cls.search_start_time = None
                cls.last_rejection_reason = (
                    f'Not enough network packets sent yet to candidate {potential_session_host_player.ip} '
                    f'({potential_session_host_player.packets.sent} / {MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST} sent packets).\n\n'
                    'Please wait a few moments for packets to be sent and try again.'
                )
                cls.last_diagnostics = _build_host_diagnostics_snapshot(
                    session_players=candidates,
                    candidates=connected_players,
                    result=_DetectionEvaluationResult(
                        outcome=(
                            f'Candidate {potential_session_host_player.ip} has only sent {potential_session_host_player.packets.sent} '
                            f'packets (minimum sent required: {MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST}).'
                        ),
                        rejection_reason=cls.last_rejection_reason,
                        timing_gap=gap_seconds,
                    ),
                )
            return None

        logger.debug('[SessionHost] Host found: %s', potential_session_host_player.ip)
        cls.last_detection_success = True
        cls.last_detected_host_ip = potential_session_host_player.ip
        cls.set_player(potential_session_host_player)
        cls.search_player = False
        cls.manual_redetect = False
        cls.search_start_time = None
        cls.last_rejection_reason = None
        cls.last_diagnostics = _build_host_diagnostics_snapshot(
            session_players=candidates,
            candidates=connected_players,
            result=_DetectionEvaluationResult(
                outcome=f'Session host detected: {potential_session_host_player.ip}',
                rejection_reason=None,
                detected_host=potential_session_host_player,
                timing_gap=gap_seconds,
            ),
        )
        return potential_session_host_player
