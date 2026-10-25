"""Player registry and session tracking."""

import copy
import logging
from collections import OrderedDict
from datetime import datetime
from operator import attrgetter
from threading import RLock
from typing import TYPE_CHECKING, ClassVar

from session_sniffer.constants.standard import LOCAL_TZ
from session_sniffer.exceptions import PlayerAlreadyExistsError, PlayerNotFoundInRegistryError
from session_sniffer.models.player_lookup import PlayerModMenus
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Iterable

    from session_sniffer.models.player import Player

logger = logging.getLogger(__name__)


def _is_session_activity_player(player: Player) -> bool:
    """Return whether *player* is a confirmed game P2P peer for fallback session start timestamps."""
    if player.is_third_party_server:
        return False
    if not CaptureState.is_local_capture():
        return True
    if Settings.is_gta5_feature_set():
        return player.is_gta5_process
    if Settings.is_rdr2_feature_set():
        return player.is_rdr2_process
    return True


class PlayersRegistry:
    """Class to manage the registry of connected and disconnected players.

    This class provides methods to add, retrieve, and iterate over players in the registry.
    """

    _DEFAULT_CONNECTED_SORT_ORDER: ClassVar[str] = 'datetime.last_rejoin'
    _DEFAULT_DISCONNECTED_SORT_ORDER: ClassVar[str] = 'datetime.last_seen'

    _registry_lock: ClassVar[RLock] = RLock()
    _connected_players_registry: ClassVar[dict[str, Player]] = {}
    _disconnected_players_registry: ClassVar[OrderedDict[str, Player]] = OrderedDict()
    _all_players_by_ip: ClassVar[dict[str, Player]] = {}

    @classmethod
    def _evict_excess_disconnected_players(cls) -> None:
        """Evict oldest disconnected players when registry exceeds the configured limit."""
        limit = Settings.gui_disconnected_players_limit
        if limit <= 0 or len(cls._disconnected_players_registry) <= limit:
            return
        evicted_players: list[Player] = []
        while len(cls._disconnected_players_registry) > limit:
            evicted_ip, evicted_player = cls._disconnected_players_registry.popitem(last=False)
            cls._all_players_by_ip.pop(evicted_ip, None)
            evicted_players.append(evicted_player)
        for evicted_player in evicted_players:
            evicted_player.left_event.set()

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
            cls._all_players_by_ip[player.ip] = player
            player.session_id = max(player.session_id, SessionTracker.get_current_session_id())
            should_record_activity = _is_session_activity_player(player)
            session_id = player.session_id
            last_rejoin = player.datetime.last_rejoin
        if should_record_activity:
            SessionTracker.record_session_player_activity(session_id, last_rejoin)
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

            cls._disconnected_players_registry.pop(player.ip)
            cls._connected_players_registry[player.ip] = player
            cls._all_players_by_ip[player.ip] = player
            player.session_id = max(player.session_id, SessionTracker.get_current_session_id())
            should_record_activity = _is_session_activity_player(player)
            session_id = player.session_id
            last_rejoin = player.datetime.last_rejoin
        if should_record_activity:
            SessionTracker.record_session_player_activity(session_id, last_rejoin)

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

            snapshot_player = (
                player.snapshot(session_id=player.session_id)
                if player.session_id < SessionTracker.get_current_session_id()
                else None
            )
            cls._connected_players_registry.pop(player.ip)
            cls._disconnected_players_registry[player.ip] = player
            cls._all_players_by_ip[player.ip] = player

            cls._evict_excess_disconnected_players()
        if snapshot_player is not None:
            SessionTracker.update_session_player_snapshot(snapshot_player)

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
        return cls._all_players_by_ip.get(ip)

    @classmethod
    def is_player_connected(cls, player: Player) -> bool:
        """Check whether the given player instance is currently in the connected registry."""
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
    def get_disconnected_players(cls) -> list[Player]:
        """Return a snapshot of disconnected players (unsorted).

        Use this instead of `get_default_sorted_players` when sort order
        is irrelevant, to avoid an unnecessary O(n log n) sort.
        """
        with cls._registry_lock:
            cls._evict_excess_disconnected_players()
            return list(cls._disconnected_players_registry.values())

    @classmethod
    def get_connected_and_disconnected_players(cls) -> tuple[list[Player], list[Player]]:
        """Return connected and disconnected players without sorting.

        Avoids O(n log n) sorting when caller handles sorting or when order is irrelevant.
        """
        with cls._registry_lock:
            cls._evict_excess_disconnected_players()
            return (
                list(cls._connected_players_registry.values()),
                list(cls._disconnected_players_registry.values()),
            )

    @classmethod
    def get_all_players(cls) -> list[Player]:
        """Return an unsorted snapshot of all connected and disconnected players.

        Prefer this over `get_default_sorted_players` when sort order is irrelevant,
        to avoid the O(n log n) sort overhead.
        """
        with cls._registry_lock:
            return list(cls._all_players_by_ip.values())

    @classmethod
    def get_players_map(cls) -> dict[str, Player]:
        """Return an unsorted snapshot mapping of all connected and disconnected players by IP."""
        with cls._registry_lock:
            return dict(cls._all_players_by_ip)

    @classmethod
    def get_total_count(cls) -> int:
        """Return the total number of tracked players (connected + disconnected) in O(1)."""
        return len(cls._all_players_by_ip)

    @classmethod
    def get_connected_count(cls) -> int:
        """Return the number of connected players in O(1)."""
        return len(cls._connected_players_registry)

    @classmethod
    def get_disconnected_count(cls) -> int:
        """Return the number of disconnected players in O(1)."""
        return len(cls._disconnected_players_registry)

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
            if include_disconnected:
                cls._evict_excess_disconnected_players()
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
            cls._evict_excess_disconnected_players()
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
                cls._all_players_by_ip.pop(player.ip, None)
        for player in players:
            player.left_event.set()

    @classmethod
    def clear_disconnected_players(cls) -> None:
        """Clear all disconnected players from the registry."""
        with cls._registry_lock:
            players = list(cls._disconnected_players_registry.values())
            cls._disconnected_players_registry.clear()
            for player in players:
                cls._all_players_by_ip.pop(player.ip, None)
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
                cls._all_players_by_ip.pop(ip, None)
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
                cls._all_players_by_ip.pop(ip, None)
        if player is not None:
            player.left_event.set()
        return player

    @classmethod
    def remove_players_by_session_id(cls, session_id: int) -> list[Player]:
        """Remove all disconnected (and past-session pending-disconnection) players belonging to the specified session."""
        include_connected = session_id < SessionTracker.get_current_session_id()
        with cls._registry_lock:
            players_to_remove = [player for player in cls._disconnected_players_registry.values() if player.session_id == session_id]
            if include_connected:
                players_to_remove.extend(
                    player for player in cls._connected_players_registry.values() if player.session_id == session_id
                )
            for player in players_to_remove:
                cls._disconnected_players_registry.pop(player.ip, None)
                if include_connected:
                    cls._connected_players_registry.pop(player.ip, None)
                cls._all_players_by_ip.pop(player.ip, None)
        for player in players_to_remove:
            player.left_event.set()
        return players_to_remove


class SessionTracker:
    """Track the current session identifier and session transitions."""

    _lock: ClassVar[RLock] = RLock()
    _current_session_id: ClassVar[int] = 1
    _known_sessions: ClassVar[set[int]] = {1}

    _session_names: ClassVar[dict[int, str]] = {}
    _session_snapshots: ClassVar[dict[int, list[Player]]] = {}
    _session_transition_pending_ips: ClassVar[dict[int, set[str]]] = {}
    _session_start_times: ClassVar[dict[int, datetime]] = {}
    _session_end_times: ClassVar[dict[int, datetime]] = {}

    @classmethod
    def get_session_snapshots(cls, session_id: int) -> list[Player]:
        """Return the snapshot list of players for a past session."""
        with cls._lock:
            return list(cls._session_snapshots.get(session_id, []))

    @classmethod
    def get_session_snapshot_player(cls, session_id: int, ip: str) -> Player | None:
        """Return the snapshot player for `ip` in `session_id`, if present."""
        with cls._lock:
            snapshots = cls._session_snapshots.get(session_id)
            if snapshots is None:
                return None
            for player in snapshots:
                if player.ip == ip:
                    return player
        return None

    @classmethod
    def get_all_snapshot_players(cls) -> list[Player]:
        """Return a flat list of all player snapshots across all past sessions."""
        with cls._lock:
            return [player for snapshots in cls._session_snapshots.values() for player in snapshots]

    @classmethod
    def get_session_players(cls, session_id: int) -> list[Player]:
        """Return all players belonging to the specified session sequence number."""
        with cls._lock:
            if session_id == cls._current_session_id:
                players = [
                    *(player for player in PlayersRegistry.get_connected_players() if player.session_id in (0, session_id)),
                    *(player for player in PlayersRegistry.get_disconnected_players() if player.session_id == session_id),
                ]
            elif session_id in cls._session_snapshots:
                players = list(cls._session_snapshots[session_id])
            else:
                players = [
                    player for player in PlayersRegistry.get_disconnected_players() if player.session_id == session_id
                ]
        return [player for player in players if not player.is_third_party_server]

    @classmethod
    def get_session_player_count(cls, session_id: int) -> int:
        """Return the count of players belonging to the specified session sequence number."""
        return len(cls.get_session_players(session_id))

    @classmethod
    def record_session_player_activity(
        cls,
        session_id: int,
        timestamp: datetime,
        *,
        fallback_timestamp: datetime | None = None,
    ) -> None:
        """Record player activity timestamp to preserve session boundaries."""
        with cls._lock:
            prev_end = cls._session_end_times.get(session_id - 1)
            if prev_end is not None and timestamp < prev_end:
                timestamp = fallback_timestamp if fallback_timestamp is not None and fallback_timestamp >= prev_end else prev_end
            existing_start = cls._session_start_times.get(session_id)
            if existing_start is None or timestamp < existing_start:
                cls._session_start_times[session_id] = timestamp

    @classmethod
    def get_session_start_time(cls, session_id: int) -> datetime | None:
        """Return the start timestamp for the specified session sequence number."""
        with cls._lock:
            recorded_start = cls._session_start_times.get(session_id)
        if recorded_start is not None:
            return recorded_start
        players = cls.get_session_players(session_id)
        player_starts = [player.datetime.last_rejoin for player in players if _is_session_activity_player(player)]
        if player_starts:
            return min(player_starts)
        return None

    @classmethod
    def get_session_end_time(cls, session_id: int) -> datetime | None:
        """Return the end timestamp for the specified session sequence number."""
        with cls._lock:
            if session_id == cls._current_session_id:
                return None
            recorded_end = cls._session_end_times.get(session_id)
        players = cls.get_session_players(session_id)
        player_ends = [player.datetime.last_seen for player in players]
        if player_ends:
            latest_player = max(player_ends)
            if recorded_end is not None:
                return max(recorded_end, latest_player)
            return latest_player
        return recorded_end

    @classmethod
    def get_session_time_label(cls, session_id: int) -> str | None:
        """Return a formatted time string for the session sequence number."""
        start_time = cls.get_session_start_time(session_id)
        end_time = cls.get_session_end_time(session_id)
        if start_time is None and end_time is None:
            return None

        now_date = datetime.now(tz=LOCAL_TZ).date()

        def _format_dt(target_datetime: datetime) -> str:
            prefix = f'{target_datetime.strftime("%m/%d")} ' if target_datetime.date() != now_date else ''
            return f'{prefix}{target_datetime.strftime("%H:%M:%S")}'

        if start_time is not None and end_time is not None:
            start_str = _format_dt(start_time)
            end_str = _format_dt(end_time)
            if start_str == end_str:
                return start_str
            return f'{start_str} - {end_str}'

        if start_time is not None:
            return _format_dt(start_time)

        if end_time is not None:
            return _format_dt(end_time)

        return None

    @classmethod
    def get_current_session_id(cls) -> int:
        """Return the current session sequence number."""
        return cls._current_session_id

    @classmethod
    def get_all_session_ids(cls) -> list[int]:
        """Return a sorted list of all known session sequence numbers."""
        with cls._lock:
            return sorted(cls._known_sessions)

    @classmethod
    def set_session_name(cls, session_id: int, name: str) -> None:
        """Set a custom name for a session sequence number, or remove it if empty."""
        with cls._lock:
            cleaned_name = name.strip()
            if cleaned_name:
                cls._session_names[session_id] = cleaned_name
            else:
                cls._session_names.pop(session_id, None)

    @classmethod
    def get_session_name(cls, session_id: int) -> str | None:
        """Return the custom name for a session, or None if not set."""
        with cls._lock:
            return cls._session_names.get(session_id)

    @classmethod
    def get_session_display_name(cls, session_id: int) -> str:
        """Return the display name for a session (custom name if set, otherwise '#<id>')."""
        with cls._lock:
            custom_name = cls._session_names.get(session_id)
            if custom_name is not None:
                return custom_name
            return f'#{session_id}'

    @classmethod
    def advance_session(
        cls,
        *,
        players: Iterable[Player] | None = None,
        p2p_players: Iterable[Player] | None = None,
        excluded_players: Iterable[Player] = (),
    ) -> None:
        """Advance to the next session identifier and update player session IDs."""
        excluded_list = list(excluded_players)
        excluded_ips = {player.ip for player in excluded_list}
        carried_by_ip: dict[str, Player] = {
            player.ip: player
            for player in (players or ())
            if player.ip not in excluded_ips
        }
        explicit_p2p_players = list(p2p_players) if p2p_players is not None else None
        with cls._lock:
            now = datetime.now(tz=LOCAL_TZ)
            old_session_id = cls._current_session_id
            live_connected = PlayersRegistry.get_connected_players()
            for player in live_connected:
                if player.ip not in excluded_ips:
                    carried_by_ip[player.ip] = player
            if explicit_p2p_players is not None:
                p2p_by_ip = {player.ip: player for player in explicit_p2p_players if player.ip not in excluded_ips}
                for player in carried_by_ip.values():
                    if player.ip not in p2p_by_ip and _is_session_activity_player(player):
                        p2p_by_ip[player.ip] = player
                carried_p2p_players = list(p2p_by_ip.values())
            else:
                carried_p2p_players = [player for player in carried_by_ip.values() if _is_session_activity_player(player)]
            old_disconnected = [
                player
                for player in PlayersRegistry.get_disconnected_players()
                if player.session_id == old_session_id and player.ip not in carried_by_ip
            ]
            old_live_departing = [
                player
                for player in live_connected
                if player.session_id in (0, old_session_id) and player.ip not in carried_by_ip
            ]
            has_old_session_players = any(
                not player.is_third_party_server
                for player in (
                    *cls._session_snapshots.get(old_session_id, ()),
                    *old_live_departing,
                    *old_disconnected,
                )
            )
            if not has_old_session_players:
                return
            p2p_carried_starts = [player.datetime.last_rejoin for player in carried_p2p_players if not player.is_third_party_server]
            if old_session_id not in cls._session_start_times:
                old_players = [*old_live_departing, *old_disconnected]
                player_starts = [player.datetime.last_rejoin for player in old_players if _is_session_activity_player(player)]
                if player_starts:
                    cls._session_start_times[old_session_id] = min(player_starts)
            cls._current_session_id += 1
            cls._known_sessions.add(cls._current_session_id)
            old_end = now
            if p2p_carried_starts:
                old_start = cls._session_start_times.get(old_session_id)
                valid_starts = [ts for ts in p2p_carried_starts if old_start is None or ts >= old_start]
                if valid_starts:
                    earliest_new_start = min(valid_starts)
                    cls._session_start_times[cls._current_session_id] = earliest_new_start
                    old_end = min(now, earliest_new_start)
                else:
                    cls._session_start_times[cls._current_session_id] = now
            cls._session_end_times[old_session_id] = old_end
            new_session_id = cls._current_session_id
            if old_session_id not in cls._session_snapshots:
                live_connected_ips = {player.ip for player in live_connected}
                has_disconnected_excluded = any(
                    not player.is_third_party_server and (player.left_event.is_set() or player.ip not in live_connected_ips)
                    for player in excluded_list
                )
                transition_pending_ips = {
                    player.ip
                    for player in old_live_departing
                    if not player.is_third_party_server
                }
                if transition_pending_ips and not has_disconnected_excluded:
                    cls._session_transition_pending_ips[old_session_id] = transition_pending_ips
                session_players = [
                    player.snapshot(session_id=old_session_id)
                    for player in old_live_departing
                ]
                session_players.extend(
                    player.snapshot(session_id=old_session_id)
                    for player in old_disconnected
                )
                cls._session_snapshots[old_session_id] = session_players
            for player in carried_by_ip.values():
                player.session_id = new_session_id
            logger.debug('[SessionTracker] Advanced to session %d', cls._current_session_id)

    @classmethod
    def delete_session(cls, session_id: int) -> list[Player]:
        """Delete a past session and its associated snapshots and metadata."""
        with cls._lock:
            if session_id == cls._current_session_id:
                return []
            if session_id in cls._known_sessions:
                cls._known_sessions.discard(session_id)
                cls._session_names.pop(session_id, None)
                cls._session_snapshots.pop(session_id, None)
                cls._session_transition_pending_ips.pop(session_id, None)
                cls._session_start_times.pop(session_id, None)
                cls._session_end_times.pop(session_id, None)
                logger.debug('[SessionTracker] Deleted session %d', session_id)
                deleted = True
            else:
                deleted = False
        if deleted:
            return PlayersRegistry.remove_players_by_session_id(session_id)
        return []

    @classmethod
    def clear_session_players(cls, session_id: int | None = None) -> list[int]:
        """Clear the snapshot players for a past session, or across all past sessions when `session_id` is None."""
        pruned_sessions: list[int] = []
        with cls._lock:
            if session_id is None:
                connected_players = PlayersRegistry.get_connected_players()
                for sid, snapshots in list(cls._session_snapshots.items()):
                    session_connected_ips = {player.ip for player in connected_players if player.session_id == sid}
                    if session_connected_ips:
                        cls._session_snapshots[sid] = [player for player in snapshots if player.ip in session_connected_ips]
                    else:
                        snapshots.clear()
                for sid in list(cls._session_transition_pending_ips):
                    session_connected_ips = {player.ip for player in connected_players if player.session_id == sid}
                    cls._session_transition_pending_ips[sid] &= session_connected_ips
                    if not cls._session_transition_pending_ips[sid]:
                        del cls._session_transition_pending_ips[sid]
                for sid in sorted(cls._known_sessions):
                    if sid < cls._current_session_id and not cls.get_session_players(sid):
                        cls._known_sessions.discard(sid)
                        cls._session_names.pop(sid, None)
                        cls._session_snapshots.pop(sid, None)
                        cls._session_transition_pending_ips.pop(sid, None)
                        cls._session_start_times.pop(sid, None)
                        cls._session_end_times.pop(sid, None)
                        pruned_sessions.append(sid)
                logger.debug('[SessionTracker] Cleared players across all past sessions')
            elif session_id in cls._known_sessions and session_id < cls._current_session_id:
                cls._session_snapshots.pop(session_id, None)
                cls._session_transition_pending_ips.pop(session_id, None)
                cls._known_sessions.discard(session_id)
                cls._session_names.pop(session_id, None)
                cls._session_start_times.pop(session_id, None)
                cls._session_end_times.pop(session_id, None)
                pruned_sessions.append(session_id)
                logger.debug('[SessionTracker] Cleared players for session %d', session_id)
        return pruned_sessions

    @classmethod
    def update_session_player_snapshot(cls, player_snapshot: Player, *, metadata_only: bool = False) -> None:
        """Refresh a player's snapshot in past sessions once disconnection finalizes or metadata resolves."""
        with cls._lock:
            if metadata_only:
                for session_snapshots in cls._session_snapshots.values():
                    for snapshot in session_snapshots:
                        if snapshot.ip != player_snapshot.ip:
                            continue
                        if player_snapshot.iplookup.geolite2.is_initialized:
                            snapshot.iplookup.geolite2 = player_snapshot.iplookup.geolite2
                        if player_snapshot.iplookup.ipapi.is_initialized:
                            snapshot.iplookup.ipapi = player_snapshot.iplookup.ipapi
                        if player_snapshot.reverse_dns.is_initialized:
                            snapshot.reverse_dns = player_snapshot.reverse_dns
                        if player_snapshot.looky_system.is_initialized:
                            snapshot.looky_system = player_snapshot.looky_system
                        if snapshot.country_flag is None and player_snapshot.country_flag is not None:
                            snapshot.country_flag = player_snapshot.country_flag
                        if not snapshot.ping.is_initialized and player_snapshot.ping.is_initialized:
                            snapshot.ping = copy.copy(player_snapshot.ping)
                        if snapshot.ps3_username is None and player_snapshot.ps3_username is not None:
                            snapshot.ps3_username = player_snapshot.ps3_username
                        snapshot.is_third_party_server = player_snapshot.is_third_party_server
                        snapshot.mod_menus = (
                            PlayerModMenus(usernames=list(player_snapshot.mod_menus.usernames))
                            if player_snapshot.mod_menus is not None
                            else None
                        )
                        snapshot.userip = player_snapshot.userip
                        if snapshot.usernames != player_snapshot.usernames:
                            snapshot.usernames = list(player_snapshot.usernames)
                return
            if not player_snapshot.is_third_party_server:
                cls._session_transition_pending_ips.pop(player_snapshot.session_id, None)
            snapshots = cls._session_snapshots.get(player_snapshot.session_id)
            if snapshots is None:
                return
            for index, existing in enumerate(snapshots):
                if existing.ip == player_snapshot.ip:
                    snapshots[index] = player_snapshot
                    return

    @classmethod
    def remove_session_player(cls, session_id: int, ip: str, *, recovered: bool = False) -> bool:
        """Remove a player by IP from a past session snapshot."""
        with cls._lock:
            pending_ips = cls._session_transition_pending_ips.get(session_id)
            if pending_ips is not None:
                if not recovered:
                    cls._session_transition_pending_ips.pop(session_id, None)
                else:
                    pending_ips.discard(ip)
            if session_id in cls._session_snapshots:
                initial_count = len(cls._session_snapshots[session_id])
                cls._session_snapshots[session_id] = [player for player in cls._session_snapshots[session_id] if player.ip != ip]
                removed = len(cls._session_snapshots[session_id]) < initial_count
                if removed:
                    logger.debug('[SessionTracker] Removed player %s from session %d', ip, session_id)
                return removed
            return False

    @classmethod
    def prune_empty_past_session(cls, session_id: int) -> int | None:
        """Prune or collapse a past session if it is empty or all of its pending players recovered."""
        with cls._lock:
            if session_id >= cls._current_session_id or session_id not in cls._known_sessions:
                return None
            pending_ips = cls._session_transition_pending_ips.get(session_id)
            all_transition_pending_recovered = pending_ips is not None and not pending_ips
            is_empty = not cls.get_session_players(session_id)
            if (
                all_transition_pending_recovered
                and session_id == cls._current_session_id - 1
                and cls._current_session_id not in cls._session_snapshots
            ):
                collapsed_from = cls._current_session_id
                for player in PlayersRegistry.get_all_players():
                    if player.session_id == collapsed_from:
                        player.session_id = session_id
                cls._known_sessions.discard(collapsed_from)
                if collapsed_from in cls._session_names and session_id not in cls._session_names:
                    cls._session_names[session_id] = cls._session_names.pop(collapsed_from)
                else:
                    cls._session_names.pop(collapsed_from, None)
                new_start = cls._session_start_times.pop(collapsed_from, None)
                if new_start is not None:
                    old_start = cls._session_start_times.get(session_id)
                    if old_start is None or new_start < old_start:
                        cls._session_start_times[session_id] = new_start
                cls._session_end_times.pop(collapsed_from, None)
                cls._session_end_times.pop(session_id, None)
                cls._session_snapshots.pop(session_id, None)
                cls._session_transition_pending_ips.pop(collapsed_from, None)
                cls._session_transition_pending_ips.pop(session_id, None)
                cls._current_session_id = session_id
                logger.debug('[SessionTracker] Collapsed past session %d with current session %d', session_id, collapsed_from)
                return collapsed_from
            if all_transition_pending_recovered:
                cls._session_transition_pending_ips.pop(session_id, None)
            if not is_empty:
                return None
            cls._known_sessions.discard(session_id)
            cls._session_names.pop(session_id, None)
            cls._session_snapshots.pop(session_id, None)
            cls._session_transition_pending_ips.pop(session_id, None)
            cls._session_start_times.pop(session_id, None)
            cls._session_end_times.pop(session_id, None)
            logger.debug('[SessionTracker] Pruned empty past session %d', session_id)
            return session_id
