"""Shared non-UI Rockstar ID resolution helpers across Looky results and in-memory cache."""

from typing import TYPE_CHECKING

from session_sniffer.models.player import Player
from session_sniffer.networking.looky_system import get_cached_rid_for_username
from session_sniffer.player.registry import PlayersRegistry, SessionTracker
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from session_sniffer.guis.tables_player_actions._ip_lookup_dialog import StandaloneIPLookup


def resolve_player_rockstar_ids(target: Player | StandaloneIPLookup) -> list[tuple[str, int]]:
    """Return deduplicated `(name, rockstar_id)` pairs for *target* from Looky results and in-memory cache."""
    resolved: list[tuple[str, int]] = []
    seen_rids: dict[int, int] = {}

    def _add_pair(raw_name: str, rid: int) -> None:
        if rid <= 0:
            return
        cleaned = raw_name.strip()
        existing_idx = seen_rids.get(rid)
        if existing_idx is None:
            seen_rids[rid] = len(resolved)
            resolved.append((cleaned, rid))
        elif not resolved[existing_idx][0] and cleaned:
            resolved[existing_idx] = (cleaned, rid)

    def _collect_from_looky(source: Player | StandaloneIPLookup) -> None:
        with source.looky_system.lock:
            rockstar_ids = list(source.looky_system.rockstarids)
            entry_names = list(source.looky_system.entry_names)
        for idx, rid in enumerate(rockstar_ids):
            name = entry_names[idx] if idx < len(entry_names) else ''
            _add_pair(name, rid)

    _collect_from_looky(target)

    if isinstance(target, Player):
        if (live_player := PlayersRegistry.get_player_by_ip(target.ip)) is not None and live_player is not target:
            _collect_from_looky(live_player)
        if not resolved:
            for snapshot_player in reversed(SessionTracker.get_all_snapshot_players()):
                if snapshot_player is not target and snapshot_player.ip == target.ip:
                    _collect_from_looky(snapshot_player)
                    if resolved:
                        break

    candidate_names = dedup_preserve_order(
        target.userip.usernames if target.userip is not None else (),
        target.usernames,
        target.mod_menus.usernames if isinstance(target, Player) and target.mod_menus is not None else (),
    )
    for username in candidate_names:
        cleaned = username.strip()
        if not cleaned:
            continue
        cached_rid = get_cached_rid_for_username(cleaned)
        if cached_rid is not None and cached_rid > 0:
            _add_pair(cleaned, cached_rid)

    return resolved
