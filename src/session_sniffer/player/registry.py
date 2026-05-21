"""Player registry for connected and disconnected players."""

from datetime import timedelta
from heapq import nsmallest
from ipaddress import IPv4Address, IPv4Network
from operator import attrgetter
from threading import RLock
from typing import TYPE_CHECKING, ClassVar

from session_sniffer.constants.third_party_servers import ThirdPartyServers
from session_sniffer.exceptions import PlayerAlreadyExistsError, PlayerNotFoundInRegistryError, UnexpectedPlayerCountError
from session_sniffer.logging_setup import get_logger

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

logger = get_logger(__name__)

MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST = 10
MAXIMUM_PACKETS_FOR_RELAY_SESSION_HOST = 20
SESSION_HOST_MAX_PACKETS_FOR_DETECTION = 1000
SESSION_HOST_CANDIDATE_PLAYERS_COUNT = 2
SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS = 200
SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS = 600
SESSION_HOST_SEARCH_TIMEOUT_SECONDS = 30
SESSION_HOST_STARTUP_WINDOW_SECONDS = 3.0

_ALL_THIRD_PARTY_NETWORKS: tuple[IPv4Network, ...] = tuple(
    IPv4Network(cidr, strict=False)
    for server in ThirdPartyServers
    for cidr in server.value
)


def is_third_party_server_ip(ip: str) -> bool:
    """Return True if `ip` matches any known third-party server CIDR range."""
    return any(IPv4Address(ip) in net for net in _ALL_THIRD_PARTY_NETWORKS)


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
            return cls._connected_players_registry.get(ip) or cls._disconnected_players_registry.get(ip)

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
            cls._connected_players_registry.clear()

    @classmethod
    def clear_disconnected_players(cls) -> None:
        """Clear all disconnected players from the registry."""
        with cls._registry_lock:
            cls._disconnected_players_registry.clear()

    @classmethod
    def remove_connected_player(cls, ip: str) -> Player | None:
        """Remove a connected player from the registry by IP address.

        Args:
            ip: The IP address of the player to remove.

        Returns:
            The removed player object if found, otherwise `None`.
        """
        with cls._registry_lock:
            return cls._connected_players_registry.pop(ip, None)

    @classmethod
    def remove_disconnected_player(cls, ip: str) -> Player | None:
        """Remove a disconnected player from the registry by IP address.

        Args:
            ip: The IP address of the player to remove.

        Returns:
            The removed player object if found, otherwise `None`.
        """
        with cls._registry_lock:
            return cls._disconnected_players_registry.pop(ip, None)


class SessionHost:
    """Track the inferred session host and pending disconnections."""

    player: ClassVar[Player | None] = None
    search_player: ClassVar[bool] = False
    search_start_time: ClassVar[float | None] = None
    players_pending_for_disconnection: ClassVar[list[Player]] = []
    last_timing_gap_candidate: ClassVar[tuple[str, str] | None] = None
    startup_players: ClassVar[set[str]] = set()

    @classmethod
    def clear_session_host_data(cls) -> None:
        """Clear all session host data including pending disconnections."""
        cls.players_pending_for_disconnection.clear()
        cls.search_player = False
        cls.search_start_time = None
        cls.player = None
        cls.last_timing_gap_candidate = None

    @staticmethod
    def get_host_player(session_connected: list[Player]) -> Player | None:
        """Infer and cache the session host from currently connected players."""
        p2p_players = [p for p in session_connected if not is_third_party_server_ip(p.ip)]
        if len(p2p_players) < len(session_connected):
            logger.debug(
                '[SessionHost] Filtered %d server IP(s) from candidates (%d P2P players remain)',
                len(session_connected) - len(p2p_players), len(p2p_players),
            )
        if not p2p_players:
            logger.debug('[SessionHost] No P2P players remain after server filtering, skipping host search')
            return None
        connected_players: list[Player] = nsmallest(SESSION_HOST_CANDIDATE_PLAYERS_COUNT, p2p_players, key=attrgetter('datetime.last_rejoin'))

        for i, p in enumerate(connected_players):
            logger.debug(
                '[SessionHost]   candidate[%d]: ip=%s, last_rejoin=%s, packets_exchanged=%d',
                i, p.ip, p.datetime.last_rejoin, p.packets.exchanged,
            )

        potential_session_host_player = None

        if len(connected_players) == 1:
            logger.debug('[SessionHost] Single candidate, selecting as potential host')
            potential_session_host_player = connected_players[0]
        elif len(connected_players) == SESSION_HOST_CANDIDATE_PLAYERS_COUNT:
            time_difference = connected_players[1].datetime.last_rejoin - connected_players[0].datetime.last_rejoin
            logger.debug('[SessionHost] Two candidates, time_difference=%s', time_difference)
            if time_difference > timedelta(milliseconds=SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS):
                logger.debug(
                    '[SessionHost] Rejected: gap %.0fms exceeds max threshold %sms, candidate[0] is temporally isolated',
                    time_difference.total_seconds() * 1000, SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS,
                )
                return None
            if time_difference >= timedelta(milliseconds=SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS):
                logger.debug(
                    '[SessionHost] Gap %.0fms in range [%sms, %sms], selecting candidate[0] as potential host',
                    time_difference.total_seconds() * 1000, SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS, SESSION_HOST_AMBIGUITY_MAX_THRESHOLD_MS,
                )
                potential_session_host_player = connected_players[0]
            else:
                logger.debug('[SessionHost] Gap < %sms, ambiguous timing, cannot determine host', SESSION_HOST_AMBIGUITY_MIN_THRESHOLD_MS)
                SessionHost.search_player = False
                SessionHost.search_start_time = None
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
            or potential_session_host_player in SessionHost.players_pending_for_disconnection
            # The lower this value, the riskier it becomes, as it could potentially flag a player who ultimately isn't part of the newly discovered session.
            # In such scenarios, a better approach might involve checking around 25-100 packets.
            # However, increasing this value also increases the risk, as the host may have already disconnected.
            or potential_session_host_player.packets.exchanged < MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST
            # A candidate with too many packets has been connected far too long to be the host of a
            # newly joined session — host detection only applies at session join time.
            or potential_session_host_player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION
        ):
            if not potential_session_host_player:
                logger.debug('[SessionHost] Rejected: no potential host candidate was selected')
            elif potential_session_host_player in SessionHost.players_pending_for_disconnection:
                logger.debug(
                    '[SessionHost] Rejected: candidate %s is in players_pending_for_disconnection (%d pending)',
                    potential_session_host_player.ip, len(SessionHost.players_pending_for_disconnection),
                )
            elif potential_session_host_player.packets.exchanged > SESSION_HOST_MAX_PACKETS_FOR_DETECTION:
                logger.debug(
                    '[SessionHost] Rejected: candidate %s has %d packets (exceeds max %d, too many for a newly joined session)',
                    potential_session_host_player.ip, potential_session_host_player.packets.exchanged, SESSION_HOST_MAX_PACKETS_FOR_DETECTION,
                )
            elif is_sole_p2p_candidate:
                logger.debug(
                    '[SessionHost] Rejected: sole candidate %s has %d packets (need >= %d)',
                    potential_session_host_player.ip, potential_session_host_player.packets.exchanged, MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
                )
            else:
                logger.debug(
                    '[SessionHost] Rejected: candidate %s has %d packets (need >= %d)',
                    potential_session_host_player.ip, potential_session_host_player.packets.exchanged, MINIMUM_PACKETS_FOR_RELAY_SESSION_HOST,
                )
                SessionHost.last_timing_gap_candidate = (connected_players[0].ip, connected_players[1].ip)
                SessionHost.search_player = False
                SessionHost.search_start_time = None
            return None

        logger.debug('[SessionHost] Host found: %s', potential_session_host_player.ip)
        SessionHost.player = potential_session_host_player
        SessionHost.search_player = False
        SessionHost.search_start_time = None
        return potential_session_host_player
