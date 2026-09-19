"""Player registry for connected and disconnected players."""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from heapq import nsmallest
from operator import attrgetter
from threading import RLock
from typing import TYPE_CHECKING, ClassVar

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.exceptions import PlayerAlreadyExistsError, PlayerNotFoundInRegistryError, UnexpectedPlayerCountError
from session_sniffer.networking.third_party_servers import is_third_party_server_ip
from session_sniffer.text_utils import format_elapsed_time

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

logger = logging.getLogger(__name__)

MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST = 10
MAXIMUM_PACKETS_FOR_RELAY_SESSION_HOST = 20
SESSION_HOST_MAX_PACKETS_FOR_DETECTION = 1000
SESSION_HOST_CANDIDATE_PLAYERS_COUNT = 2
SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS = 100
SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS = 600
SESSION_HOST_SEARCH_TIMEOUT_SECONDS = 30
SESSION_HOST_STARTUP_WINDOW_SECONDS = 1.0
_SESSION_HOST_AMBIGUITY_MIN_TD = timedelta(milliseconds=SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS)
_SESSION_HOST_AMBIGUITY_MAX_TD = timedelta(milliseconds=SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS)


@dataclass(slots=True)
class HostHistoryEntry:
    """Snapshot of a session host at the time of detection."""

    ip: str
    detected_at: datetime
    country_code: str


class PlayersRegistry:
    """Class to manage the registry of connected and disconnected players.

    This class provides methods to add, retrieve, and iterate over players in the registry.
    """

    _DEFAULT_CONNECTED_SORT_ORDER: ClassVar[str] = 'datetime.last_rejoin'
    _DEFAULT_DISCONNECTED_SORT_ORDER: ClassVar[str] = 'datetime.last_seen'

    _registry_lock: ClassVar[RLock] = RLock()
    _connected_players_registry: ClassVar[dict[str, Player]] = {}
    _disconnected_players_registry: ClassVar[dict[str, Player]] = {}

    @classmethod
    def _sort_connected_players(cls, players: list[Player]) -> list[Player]:
        return sorted(
            players,
            key=attrgetter(cls._DEFAULT_CONNECTED_SORT_ORDER),
        )

    @classmethod
    def _sort_disconnected_players(cls, players: list[Player]) -> list[Player]:
        return sorted(
            players,
            key=attrgetter(cls._DEFAULT_DISCONNECTED_SORT_ORDER),
            reverse=True,
        )

    @classmethod
    def add_connected_player(cls, player: Player) -> Player:
        """Add a connected player to the registry.

        Args:
            player: The player object to add.

        Returns:
            The player object that was added.

        Raises:
            PlayerAlreadyExistsError: If the player already exists in the registry.
        """
        with cls._registry_lock:
            if player.ip in cls._connected_players_registry:
                raise PlayerAlreadyExistsError(player.ip)

            cls._connected_players_registry[player.ip] = player
            return player

    @classmethod
    def move_player_to_connected(cls, player: Player) -> None:
        """Move a player from the disconnected registry to the connected registry.

        Args:
            player: The player object to move.

        Raises:
            PlayerNotFoundError: If the player is not found in the disconnected registry.
        """
        with cls._registry_lock:
            if player.ip not in cls._disconnected_players_registry:
                raise PlayerNotFoundInRegistryError(player.ip)

            cls._connected_players_registry[player.ip] = cls._disconnected_players_registry.pop(player.ip)

    @classmethod
    def move_player_to_disconnected(cls, player: Player) -> None:
        """Move a player from the connected registry to the disconnected registry.

        Args:
            player: The player object to move.

        Raises:
            PlayerNotFoundError: If the player is not found in the connected registry.
        """
        with cls._registry_lock:
            if player.ip not in cls._connected_players_registry:
                raise PlayerNotFoundInRegistryError(player.ip)

            cls._disconnected_players_registry[player.ip] = cls._connected_players_registry.pop(player.ip)

    @classmethod
    def get_player_by_ip(cls, ip: str, /) -> Player | None:
        """Get a player by their IP address.

        Note that `None` may also be returned if the user manually cleared the IP by
        using the clear button.

        Args:
            ip: The IP address of the player.

        Returns:
            The player object if found, otherwise `None`.
        """
        with cls._registry_lock:
            player = cls._connected_players_registry.get(ip)
            if player is None:
                player = cls._disconnected_players_registry.get(ip)
            return player

    @classmethod
    def is_player_connected(cls, player: Player) -> bool:
        """Check whether the given player instance is currently in the connected registry."""
        with cls._registry_lock:
            return cls._connected_players_registry.get(player.ip) is player

    @classmethod
    def get_connected_players(cls) -> list[Player]:
        """Return a snapshot of connected players (unsorted).

        Use this instead of `get_default_sorted_players` when sort order
        is irrelevant, to avoid an unnecessary O(n log n) sort.
        """
        with cls._registry_lock:
            return list(cls._connected_players_registry.values())

    @classmethod
    def get_all_players(cls) -> list[Player]:
        """Return an unsorted snapshot of all connected and disconnected players.

        Prefer this over `get_default_sorted_players` when sort order is irrelevant,
        to avoid the O(n log n) sort overhead.
        """
        with cls._registry_lock:
            return list(cls._connected_players_registry.values()) + list(cls._disconnected_players_registry.values())

    @classmethod
    def get_total_count(cls) -> int:
        """Return the total number of tracked players (connected + disconnected) in O(1)."""
        with cls._registry_lock:
            return len(cls._connected_players_registry) + len(cls._disconnected_players_registry)

    @classmethod
    def get_default_sorted_players(
        cls,
        *,
        include_connected: bool = True,
        include_disconnected: bool = True,
    ) -> list[Player]:
        """Return a snapshot of players sorted by default criteria.

        Connected players are sorted by last rejoin (ascending),
        disconnected players by last seen (descending).
        """
        with cls._registry_lock:
            connected_snapshot = list(cls._connected_players_registry.values()) if include_connected else []
            disconnected_snapshot = list(cls._disconnected_players_registry.values()) if include_disconnected else []
        players: list[Player] = []
        if include_connected:
            players.extend(cls._sort_connected_players(connected_snapshot))
        if include_disconnected:
            players.extend(cls._sort_disconnected_players(disconnected_snapshot))
        return players

    @classmethod
    def get_default_sorted_connected_and_disconnected_players(cls) -> tuple[list[Player], list[Player]]:
        """Return connected and disconnected players, each sorted by their default criteria."""
        with cls._registry_lock:
            connected_snapshot = list(cls._connected_players_registry.values())
            disconnected_snapshot = list(cls._disconnected_players_registry.values())
        return (
            cls._sort_connected_players(connected_snapshot),
            cls._sort_disconnected_players(disconnected_snapshot),
        )

    @classmethod
    def clear_connected_players(cls) -> None:
        """Clear all connected players from the registry."""
        with cls._registry_lock:
            players = list(cls._connected_players_registry.values())
            cls._connected_players_registry.clear()
        for player in players:
            player.left_event.set()

    @classmethod
    def clear_disconnected_players(cls) -> None:
        """Clear all disconnected players from the registry."""
        with cls._registry_lock:
            players = list(cls._disconnected_players_registry.values())
            cls._disconnected_players_registry.clear()
        for player in players:
            player.left_event.set()

    @classmethod
    def remove_connected_player(cls, ip: str) -> Player | None:
        """Remove a connected player from the registry by IP address.

        Args:
            ip: The IP address of the player to remove.

        Returns:
            The removed player object if found, otherwise `None`.
        """
        with cls._registry_lock:
            player = cls._connected_players_registry.pop(ip, None)
        if player is not None:
            player.left_event.set()
        return player

    @classmethod
    def remove_disconnected_player(cls, ip: str) -> Player | None:
        """Remove a disconnected player from the registry by IP address.

        Args:
            ip: The IP address of the player to remove.

        Returns:
            The removed player object if found, otherwise `None`.
        """
        with cls._registry_lock:
            player = cls._disconnected_players_registry.pop(ip, None)
        if player is not None:
            player.left_event.set()
        return player


def _format_host_debug_details(
    session_connected: list[Player],
    p2p_players: list[Player],
    candidates: list[Player],
    outcome: str,
    timing_gap: float | None = None,
) -> str:
    """Format structured diagnostic details for session host detection."""
    lines: list[str] = [
        '=== Session Host Detection Diagnostics ===',
        f'Outcome: {outcome}',
        '',
        '--- Session Overview ---',
        f'- Total Connected Players: {len(session_connected)}',
        f'- Direct P2P Players: {len(p2p_players)}',
        f'- Filtered Server IPs: {len(session_connected) - len(p2p_players)}',
        '',
        '--- Detection Criteria ---',
        f'- Candidate Timing Gap Window: {SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS}ms - {SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS}ms',
        f'- Minimum Packets Required: {MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST}',
        f'- Maximum Packets Limit: {SESSION_HOST_MAX_PACKETS_FOR_DETECTION}',
    ]
    if timing_gap is not None:
        gap_milliseconds = timing_gap * 1000
        time_difference_text = f'{timing_gap:.3f}s ({gap_milliseconds:.1f}ms)' if timing_gap >= 1.0 else f'{gap_milliseconds:.1f}ms'
        timing_lines = [
            '',
            '--- Timing Analysis ---',
            f'- Time Difference: {time_difference_text}',
        ]
        if SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS <= gap_milliseconds <= SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS:
            timing_lines.append(
                f'- Timing Gap Resolution: 2 candidates were evaluated, and candidate #1 joined earlier within the valid timing window '
                f'({SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS}ms - {SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS}ms).'
            )
        elif gap_milliseconds < SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS:
            timing_lines.append(
                f'- Timing Gap Resolution: Rejected — {gap_milliseconds:.1f}ms gap is below the {SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS}ms '
                'minimum threshold (players connected almost simultaneously, timing is ambiguous).'
            )
        else:
            timing_lines.append(
                f'- Timing Gap Resolution: Rejected — {time_difference_text} gap exceeds the {SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS}ms '
                'maximum threshold (candidate #1 joined too far ahead of candidate #2).'
            )
        lines.extend(timing_lines)
    elif len(candidates) == 1:
        lines.extend(
            [
                '',
                '--- Timing Analysis ---',
                '- Sole P2P Player: Only 1 non-server player was present, so timing comparison was skipped.',
            ]
        )

    if candidates:
        lines.extend(
            [
                '',
                '--- Evaluated Candidates ---',
            ]
        )
        for index, player in enumerate(candidates, start=1):
            rejoin_time = player.datetime.last_rejoin.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            rejoin_ago = format_elapsed_time(datetime.now(tz=LOCAL_TZ) - player.datetime.last_rejoin)
            if player.packets.exchanged < MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST:
                packets_status = 'Not enough'
            elif player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION:
                packets_status = 'Exceeds maximum'
            else:
                packets_status = 'Enough'
            username_suffix = f' ({", ".join(player.usernames)})' if player.usernames else ''
            candidate_lines = [
                f'Candidate #{index}:',
                f'  IP Address: {player.ip}{username_suffix}',
                f'  Last Rejoin: {rejoin_time} ({rejoin_ago} ago)',
                f'  Packets Exchanged: {player.packets.exchanged} ({packets_status})',
            ]
            if player in SessionHost.players_pending_for_disconnection:
                candidate_lines.append('  Note: Pending Disconnection')
            lines.extend(candidate_lines)

    return '\n'.join(lines)


class SessionHost:
    """Track the inferred session host and pending disconnections."""

    _player: ClassVar[Player | None] = None
    search_player: ClassVar[bool] = False
    manual_redetect: ClassVar[bool] = False
    search_start_time: ClassVar[float | None] = None
    players_pending_for_disconnection: ClassVar[list[Player]] = []
    last_timing_gap_candidate: ClassVar[tuple[str, str] | None] = None
    last_rejection_reason: ClassVar[str | None] = None
    last_debug_details: ClassVar[str | None] = None
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
    def clear_session_host_data(cls) -> None:
        """Clear all session host data including pending disconnections."""
        cls.players_pending_for_disconnection.clear()
        cls.search_player = False
        cls.manual_redetect = False
        cls.search_start_time = None
        cls._player = None
        cls.last_timing_gap_candidate = None
        cls.last_rejection_reason = None
        cls.last_debug_details = None

    @classmethod
    def record_host(cls, player: Player) -> None:
        """Snapshot the given player as a detected session host and append to history."""
        cls._history.append(
            HostHistoryEntry(
                ip=player.ip,
                detected_at=datetime.now(tz=LOCAL_TZ),
                country_code=player.iplookup.geolite2.country_code if player.iplookup.geolite2.country_code not in {'...', 'N/A'} else player.iplookup.ipapi.country_code,
            ),
        )

    @classmethod
    def get_history(cls) -> list[HostHistoryEntry]:
        """Return a snapshot list of the in-memory session host history."""
        return list(cls._history)

    @classmethod
    def clear_history(cls) -> None:
        """Clear the in-memory session host history."""
        cls._history.clear()

    @classmethod
    def get_host_player(cls, session_connected: list[Player]) -> Player | None:
        """Infer and cache the session host from currently connected players."""
        if not session_connected:
            cls.last_rejection_reason = 'No other players are currently connected in your session.'
            cls.last_debug_details = (
                '=== Session Host Detection Diagnostics ===\n'
                'Outcome: No connected players found in current session.\n\n'
                '--- Session Overview ---\n'
                '- Total Connected Players: 0\n'
                '- Direct P2P Players: 0\n'
                '- Filtered Server IPs: 0'
            )
            return None

        p2p_players = [player for player in session_connected if not is_third_party_server_ip(player.ip)]
        if len(p2p_players) < len(session_connected):
            logger.debug(
                '[SessionHost] Filtered %d server IP(s) from candidates (%d P2P players remain)',
                len(session_connected) - len(p2p_players),
                len(p2p_players),
            )
        if not p2p_players:
            logger.debug('[SessionHost] No P2P players remain after server filtering, skipping host search')
            cls.last_rejection_reason = f'All {len(session_connected)} connected IP(s) are game or relay servers, not direct peer-to-peer players.'
            server_list = '\n'.join(f'  - {player.ip} ({player.packets.exchanged} packets)' for player in session_connected)
            cls.last_debug_details = (
                '=== Session Host Detection Diagnostics ===\n'
                'Outcome: All connected IPs matched known server ranges.\n\n'
                '--- Session Overview ---\n'
                f'- Total Connected Players: {len(session_connected)}\n'
                '- Direct P2P Players: 0\n'
                f'- Filtered Server IPs: {len(session_connected)}\n\n'
                f'--- Filtered Server List ---\n{server_list}'
            )
        active_p2p_players = [player for player in p2p_players if not player.left_event.is_set() and player not in cls.players_pending_for_disconnection]
        if not active_p2p_players:
            logger.debug('[SessionHost] No active P2P players remain (%d P2P players pending disconnection)', len(p2p_players))
            cls.last_rejection_reason = 'All connected peer-to-peer player(s) are disconnecting, so the session host cannot be determined.'
            cls.last_debug_details = _format_host_debug_details(
                session_connected,
                p2p_players,
                candidates=[],
                outcome='All connected P2P player(s) are pending disconnection.',
            )
            cls.search_player = False
            cls.search_start_time = None
            return None
        connected_players: list[Player] = nsmallest(SESSION_HOST_CANDIDATE_PLAYERS_COUNT, active_p2p_players, key=attrgetter('datetime.last_rejoin'))

        for i, player in enumerate(connected_players):
            logger.debug(
                '[SessionHost]   candidate[%d]: ip=%s, last_rejoin=%s, packets_exchanged=%d',
                i,
                player.ip,
                player.datetime.last_rejoin,
                player.packets.exchanged,
            )

        potential_session_host_player: Player | None = None
        gap_seconds: float | None = None

        if len(connected_players) == 1:
            logger.debug('[SessionHost] Single candidate, selecting as potential host')
            potential_session_host_player = connected_players[0]
        elif len(connected_players) == SESSION_HOST_CANDIDATE_PLAYERS_COUNT:
            time_difference = connected_players[1].datetime.last_rejoin - connected_players[0].datetime.last_rejoin
            gap_seconds = time_difference.total_seconds()
            gap_milliseconds = gap_seconds * 1000
            logger.debug('[SessionHost] Two candidates, time_difference=%s', time_difference)
            if time_difference > _SESSION_HOST_AMBIGUITY_MAX_TD:
                logger.debug(
                    '[SessionHost] Rejected: gap %.0fms exceeds max threshold %sms, candidate[0] is temporally isolated',
                    gap_milliseconds,
                    SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS,
                )
                cls.search_player = False
                cls.search_start_time = None
                cls.last_rejection_reason = (
                    f'The connection time gap between the first two players is too large ({gap_seconds:.1f}s gap).\n\n'
                    'Host detection requires players to connect together during session creation.'
                )
                cls.last_debug_details = _format_host_debug_details(
                    session_connected,
                    p2p_players,
                    connected_players,
                    outcome=(
                        f'Connection time gap is too large: {gap_seconds:.1f}s gap exceeds maximum threshold '
                        f'({SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS}ms); players did not connect together.'
                    ),
                    timing_gap=gap_seconds,
                )
                return None
            if time_difference >= _SESSION_HOST_AMBIGUITY_MIN_TD:
                logger.debug(
                    '[SessionHost] Gap %.0fms in range [%sms, %sms], selecting candidate[0] as potential host',
                    gap_milliseconds,
                    SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS,
                    SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS,
                )
                potential_session_host_player = connected_players[0]
            else:
                logger.debug(
                    '[SessionHost] Gap %.0fms < %sms, ambiguous timing, cannot determine host',
                    gap_milliseconds,
                    SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS,
                )
                cls.last_rejection_reason = (
                    f'The first two players connected almost at the exact same moment ({gap_milliseconds:.1f}ms apart).\n\n'
                    'Their connection times are too close to determine who hosted the session.'
                )
                cls.last_debug_details = _format_host_debug_details(
                    session_connected,
                    p2p_players,
                    connected_players,
                    outcome=(
                        f'Connection times are too close to determine host: first two players connected almost simultaneously '
                        f'({gap_milliseconds:.1f}ms apart; minimum separation is {SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS}ms).'
                    ),
                    timing_gap=gap_seconds,
                )
                cls.search_player = False
                cls.search_start_time = None
                return None
        else:
            raise UnexpectedPlayerCountError(len(connected_players))

        # Both sole-candidate and two-candidate paths use MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST.
        # GTA5 matchmaking briefly probes other sessions' hosts (10-20 packet transient handshakes)
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
            or potential_session_host_player.packets.exchanged < MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST
            # A candidate with too many packets has been connected far too long to be the host of a
            # newly joined session — host detection only applies at session join time.
            # Skip this check for manual re-detects: the user explicitly requested re-detection,
            # so packet count is irrelevant (the session is already in progress).
            or (not cls.manual_redetect and potential_session_host_player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION)
        ):
            if not potential_session_host_player:
                logger.debug('[SessionHost] Rejected: no potential host candidate was selected')
                cls.last_rejection_reason = 'No potential host candidate could be selected.'
                cls.last_debug_details = _format_host_debug_details(
                    session_connected,
                    p2p_players,
                    connected_players,
                    outcome='No potential host candidate could be selected.',
                )
            elif potential_session_host_player in cls.players_pending_for_disconnection:
                logger.debug(
                    '[SessionHost] Rejected: candidate %s is in players_pending_for_disconnection (%d pending)',
                    potential_session_host_player.ip,
                    len(cls.players_pending_for_disconnection),
                )
                cls.last_rejection_reason = f'Candidate player {potential_session_host_player.ip} is currently disconnecting or leaving the session.'
                cls.last_debug_details = _format_host_debug_details(
                    session_connected,
                    p2p_players,
                    connected_players,
                    outcome=f'Candidate player {potential_session_host_player.ip} is currently disconnecting or leaving the session.',
                    timing_gap=gap_seconds,
                )
            elif potential_session_host_player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION:
                logger.debug(
                    '[SessionHost] Rejected: candidate %s has %d packets (exceeds max %d, too many for a newly joined session)',
                    potential_session_host_player.ip,
                    potential_session_host_player.packets.exchanged,
                    SESSION_HOST_MAX_PACKETS_FOR_DETECTION,
                )
                cls.search_player = False
                cls.search_start_time = None
                cls.last_rejection_reason = (
                    f'Candidate player {potential_session_host_player.ip} has already exchanged too many packets to determine if they originally hosted the session.'
                )
                cls.last_debug_details = _format_host_debug_details(
                    session_connected,
                    p2p_players,
                    connected_players,
                    outcome=(
                        f'Candidate {potential_session_host_player.ip} packet count ({potential_session_host_player.packets.exchanged}) '
                        f'exceeds maximum allowed threshold ({SESSION_HOST_MAX_PACKETS_FOR_DETECTION}).'
                    ),
                    timing_gap=gap_seconds,
                )
            elif is_sole_p2p_candidate:
                logger.debug(
                    '[SessionHost] Rejected: sole candidate %s has %d packets (need >= %d)',
                    potential_session_host_player.ip,
                    potential_session_host_player.packets.exchanged,
                    MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
                )
                cls.last_rejection_reason = (
                    f'Not enough network packets exchanged yet with candidate {potential_session_host_player.ip} '
                    f'({potential_session_host_player.packets.exchanged} / {MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST} packets).\n\n'
                    'Please wait a few moments for packets to exchange and try again.'
                )
                cls.last_debug_details = _format_host_debug_details(
                    session_connected,
                    p2p_players,
                    connected_players,
                    outcome=(
                        f'Candidate {potential_session_host_player.ip} has only exchanged {potential_session_host_player.packets.exchanged} '
                        f'packets (minimum required: {MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST}).'
                    ),
                )
            else:
                logger.debug(
                    '[SessionHost] Rejected: candidate %s has %d packets (need >= %d)',
                    potential_session_host_player.ip,
                    potential_session_host_player.packets.exchanged,
                    MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
                )
                cls.last_timing_gap_candidate = (connected_players[0].ip, connected_players[1].ip)
                cls.search_player = False
                cls.search_start_time = None
                cls.last_rejection_reason = (
                    f'Not enough network packets exchanged yet with candidate {potential_session_host_player.ip} '
                    f'({potential_session_host_player.packets.exchanged} / {MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST} packets).\n\n'
                    'Please wait a few moments for packets to exchange and try again.'
                )
                cls.last_debug_details = _format_host_debug_details(
                    session_connected,
                    p2p_players,
                    connected_players,
                    outcome=(
                        f'Candidate {potential_session_host_player.ip} has only exchanged {potential_session_host_player.packets.exchanged} '
                        f'packets (minimum required: {MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST}).'
                    ),
                    timing_gap=gap_seconds,
                )
            return None

        logger.debug('[SessionHost] Host found: %s', potential_session_host_player.ip)
        cls.set_player(potential_session_host_player)
        cls.search_player = False
        cls.manual_redetect = False
        cls.search_start_time = None
        cls.last_rejection_reason = None
        cls.last_debug_details = _format_host_debug_details(
            session_connected,
            p2p_players,
            connected_players,
            outcome=f'Session host detected: {potential_session_host_player.ip}',
            timing_gap=gap_seconds,
        )
        return potential_session_host_player
