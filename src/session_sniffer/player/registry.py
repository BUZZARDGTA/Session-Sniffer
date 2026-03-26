"""Player registry for connected and disconnected players."""

from datetime import timedelta
from operator import attrgetter
from threading import RLock
from typing import TYPE_CHECKING, ClassVar

from session_sniffer.exceptions import PlayerAlreadyExistsError, PlayerNotFoundInRegistryError, UnexpectedPlayerCountError
from session_sniffer.utils import take

if TYPE_CHECKING:
    from session_sniffer.models.player import Player

MINIMUM_PACKETS_FOR_SESSION_HOST = 50
SESSION_HOST_CANDIDATE_PLAYERS_COUNT = 2


class PlayersRegistry:
    """Class to manage the registry of connected and disconnected players.

    This class provides methods to add, retrieve, and iterate over players in the registry.
    """
    _DEFAULT_CONNECTED_SORT_ORDER: ClassVar = 'datetime.last_rejoin'
    _DEFAULT_DISCONNECTED_SORT_ORDER: ClassVar = 'datetime.last_seen'

    _registry_lock: ClassVar = RLock()
    _connected_players_registry: ClassVar[dict[str, Player]] = {}
    _disconnected_players_registry: ClassVar[dict[str, Player]] = {}

    @classmethod
    def _get_sorted_connected_players(cls) -> list[Player]:
        return sorted(
            cls._connected_players_registry.values(),
            key=attrgetter(cls._DEFAULT_CONNECTED_SORT_ORDER),
        )

    @classmethod
    def _get_sorted_disconnected_players(cls) -> list[Player]:
        return sorted(
            cls._disconnected_players_registry.values(),
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

        Raies:
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
            players: list[Player] = []
            if include_connected:
                players.extend(cls._get_sorted_connected_players())
            if include_disconnected:
                players.extend(cls._get_sorted_disconnected_players())
            return players

    @classmethod
    def get_default_sorted_connected_and_disconnected_players(cls) -> tuple[list[Player], list[Player]]:
        """Return connected and disconnected players, each sorted by their default criteria."""
        with cls._registry_lock:
            return (
                cls._get_sorted_connected_players(),
                cls._get_sorted_disconnected_players(),
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
    players_pending_for_disconnection: ClassVar[list[Player]] = []

    @classmethod
    def clear_session_host_data(cls) -> None:
        """Clear all session host data including pending disconnections."""
        cls.players_pending_for_disconnection.clear()
        cls.search_player = False
        cls.player = None

    @staticmethod
    def get_host_player(session_connected: list[Player]) -> Player | None:
        """Infer and cache the session host from currently connected players."""
        connected_players: list[Player] = take(SESSION_HOST_CANDIDATE_PLAYERS_COUNT, sorted(session_connected, key=attrgetter('datetime.last_rejoin')))

        potential_session_host_player = None

        if len(connected_players) == 1:
            potential_session_host_player = connected_players[0]
        elif len(connected_players) == SESSION_HOST_CANDIDATE_PLAYERS_COUNT:
            time_difference = connected_players[1].datetime.last_rejoin - connected_players[0].datetime.last_rejoin
            if time_difference >= timedelta(milliseconds=200):
                potential_session_host_player = connected_players[0]
        else:
            raise UnexpectedPlayerCountError(len(connected_players))

        if (
            not potential_session_host_player
            # Skip players remaining to be disconnected from the previous session.
            or potential_session_host_player in SessionHost.players_pending_for_disconnection
            # The lower this value, the riskier it becomes, as it could potentially flag a player who ultimately isn't part of the newly discovered session.
            # In such scenarios, a better approach might involve checking around 25-100 packets.
            # However, increasing this value also increases the risk, as the host may have already disconnected.
            or potential_session_host_player.packets.exchanged < MINIMUM_PACKETS_FOR_SESSION_HOST
        ):
            return None

        SessionHost.player = potential_session_host_player
        SessionHost.search_player = False
        return potential_session_host_player
