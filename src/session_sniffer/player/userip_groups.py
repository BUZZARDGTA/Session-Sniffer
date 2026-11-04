"""Persistent UserIP account grouping, ungrouping (false-positive exclusions), and per-IP Looky username exclusions."""

import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from session_sniffer.constants.local import APP_DIR_ROAMING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from collections.abc import Set as AbstractSet
    from pathlib import Path

logger = logging.getLogger(__name__)

USERIP_GROUPS_PATH: Path = APP_DIR_ROAMING / 'userip_groups.json'
MIN_GROUP_USERNAMES = 2


def _empty_pair_list() -> list[tuple[str, str]]:
    return []


def _empty_pair_set() -> set[tuple[str, str]]:
    return set()


def _empty_str_dict() -> dict[str, str]:
    return {}


def _empty_excluded_dict() -> dict[str, list[str]]:
    return {}


class UserIPGroupsData(BaseModel):
    """Pydantic model for persistent UserIP account links, unlinks, and per-IP Looky exclusions."""

    linked_pairs: list[tuple[str, str]] = Field(default_factory=_empty_pair_list)
    unlinked_pairs: list[tuple[str, str]] = Field(default_factory=_empty_pair_list)
    canonical_names: dict[str, str] = Field(default_factory=_empty_str_dict)
    excluded_looky_usernames: dict[str, list[str]] = Field(default_factory=_empty_excluded_dict)

    model_config = ConfigDict(extra='ignore')


@dataclass(slots=True)
class _GroupsCache:
    """In-memory cache for persistent UserIP grouping state."""

    loaded: bool = False
    linked_pairs: set[tuple[str, str]] = field(default_factory=_empty_pair_set)
    unlinked_pairs: set[tuple[str, str]] = field(default_factory=_empty_pair_set)
    canonical_names: dict[str, str] = field(default_factory=_empty_str_dict)
    excluded_looky_by_ip: dict[str, list[str]] = field(default_factory=_empty_excluded_dict)


_groups_lock = threading.Lock()
_cache = _GroupsCache()


def _normalize_pair(u1: str, u2: str) -> tuple[str, str] | None:
    """Return a sorted casefolded pair `(a, b)` when `u1` and `u2` are distinct non-empty usernames."""
    cf1 = u1.strip().casefold()
    cf2 = u2.strip().casefold()
    if not cf1 or not cf2 or cf1 == cf2:
        return None
    return (cf1, cf2) if cf1 < cf2 else (cf2, cf1)


def _ensure_loaded_locked() -> None:
    """Load `userip_groups.json` into memory if not yet loaded (caller must hold `_groups_lock`)."""
    if _cache.loaded:
        return
    _cache.loaded = True
    _cache.linked_pairs.clear()
    _cache.unlinked_pairs.clear()
    _cache.canonical_names.clear()
    _cache.excluded_looky_by_ip.clear()

    if not USERIP_GROUPS_PATH.is_file():
        return

    try:
        data = UserIPGroupsData.model_validate_json(USERIP_GROUPS_PATH.read_text(encoding='utf-8'))
    except (OSError, ValidationError) as e:
        logger.warning('Failed to load UserIP groups from %s: %s', USERIP_GROUPS_PATH, e)
        return

    for u1, u2 in data.unlinked_pairs:
        if pair := _normalize_pair(u1, u2):
            _cache.unlinked_pairs.add(pair)

    for u1, u2 in data.linked_pairs:
        if (pair := _normalize_pair(u1, u2)) and pair not in _cache.unlinked_pairs:
            _cache.linked_pairs.add(pair)

    for cf, display_name in data.canonical_names.items():
        clean_name = display_name.strip()
        if clean_name:
            _cache.canonical_names[cf.strip().casefold()] = clean_name

    for ip, names in data.excluded_looky_usernames.items():
        clean_ip = ip.strip()
        if not clean_ip:
            continue
        deduped: list[str] = []
        seen_cf: set[str] = set()
        for name in names:
            clean_name = name.strip()
            name_cf = clean_name.casefold()
            if clean_name and name_cf not in seen_cf:
                seen_cf.add(name_cf)
                deduped.append(clean_name)
        if deduped:
            _cache.excluded_looky_by_ip[clean_ip] = deduped


def _save_locked() -> None:
    """Persist in-memory grouping state to `userip_groups.json` (caller must hold `_groups_lock`)."""
    data = UserIPGroupsData(
        linked_pairs=sorted(_cache.linked_pairs),
        unlinked_pairs=sorted(_cache.unlinked_pairs),
        canonical_names=dict(sorted(_cache.canonical_names.items())),
        excluded_looky_usernames=dict(sorted(_cache.excluded_looky_by_ip.items())),
    )
    try:
        USERIP_GROUPS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERIP_GROUPS_PATH.write_text(data.model_dump_json(indent=2), encoding='utf-8')
    except OSError:
        logger.exception('Failed to save UserIP groups to %s', USERIP_GROUPS_PATH)


def get_grouping_snapshot() -> tuple[set[tuple[str, str]], set[tuple[str, str]], dict[str, str]]:
    """Return a copy of `(linked_pairs, unlinked_pairs, canonical_names)`."""
    with _groups_lock:
        _ensure_loaded_locked()
        return set(_cache.linked_pairs), set(_cache.unlinked_pairs), dict(_cache.canonical_names)


def are_usernames_unlinked(u1: str, u2: str) -> bool:
    """Return True if `u1` and `u2` were explicitly ungrouped by the user."""
    pair = _normalize_pair(u1, u2)
    if pair is None:
        return False
    with _groups_lock:
        _ensure_loaded_locked()
        return pair in _cache.unlinked_pairs


def group_usernames(
    usernames: Sequence[str],
    existing_clusters: Mapping[str, Sequence[str]] | None = None,
) -> bool:
    """Manually group all `usernames` together, clearing any unlinked overrides between their clusters.

    Returns:
        True if the persisted grouping state changed.
    """
    cleaned: list[str] = []
    seen_cf: set[str] = set()
    for name in usernames:
        clean = name.strip()
        cf = clean.casefold()
        if clean and cf not in seen_cf:
            seen_cf.add(cf)
            cleaned.append(clean)

    if len(cleaned) < MIN_GROUP_USERNAMES:
        return False

    expanded_cfs: set[str] = set(seen_cf)
    if existing_clusters is not None:
        for cf in list(seen_cf):
            for member in existing_clusters.get(cf, ()):
                if member_cf := member.strip().casefold():
                    expanded_cfs.add(member_cf)

    with _groups_lock:
        _ensure_loaded_locked()
        changed = False

        for clean in cleaned:
            cf = clean.casefold()
            if _cache.canonical_names.get(cf) != clean:
                _cache.canonical_names[cf] = clean
                changed = True

        expanded_list = sorted(expanded_cfs)
        for i, cf1 in enumerate(expanded_list):
            for cf2 in expanded_list[i + 1 :]:
                unlinked_pair = (cf1, cf2)
                if unlinked_pair in _cache.unlinked_pairs:
                    _cache.unlinked_pairs.discard(unlinked_pair)
                    changed = True

        cleaned_cfs = [c.casefold() for c in cleaned]
        for i, cf1 in enumerate(cleaned_cfs):
            for cf2 in cleaned_cfs[i + 1 :]:
                linked_pair = _normalize_pair(cf1, cf2)
                if linked_pair is not None and linked_pair not in _cache.linked_pairs:
                    _cache.linked_pairs.add(linked_pair)
                    changed = True

        if changed:
            _save_locked()
        return changed


def ungroup_usernames(
    usernames_to_detach: Sequence[str],
    cluster_usernames: Sequence[str],
) -> bool:
    """Detach `usernames_to_detach` from `cluster_usernames` and mark them as unlinked so false positives stay ungrouped.

    If `usernames_to_detach` covers every member of `cluster_usernames` (e.g., user checked all accounts in the group),
    all pairs among `cluster_usernames` are unlinked from one another.

    Returns:
        True if the persisted grouping state changed.
    """
    detach_cfs = {u.strip().casefold() for u in usernames_to_detach if u.strip()}
    cluster_cfs = {u.strip().casefold() for u in cluster_usernames if u.strip()}
    cluster_cfs |= detach_cfs
    if not detach_cfs or len(cluster_cfs) < MIN_GROUP_USERNAMES:
        return False

    remaining_cfs = cluster_cfs - detach_cfs
    unlink_all_among_detached = not remaining_cfs

    with _groups_lock:
        _ensure_loaded_locked()
        changed = False

        for d_cf in detach_cfs:
            targets = cluster_cfs if unlink_all_among_detached else remaining_cfs
            for t_cf in targets:
                pair = _normalize_pair(d_cf, t_cf)
                if pair is not None:
                    if pair in _cache.linked_pairs:
                        _cache.linked_pairs.discard(pair)
                        changed = True
                    if pair not in _cache.unlinked_pairs:
                        _cache.unlinked_pairs.add(pair)
                        changed = True

        if changed:
            _save_locked()
        return changed


def record_looky_db_correlation(
    looky_usernames: Sequence[str],
    db_usernames_cf: AbstractSet[str],
) -> bool:
    """Auto-link Looky usernames resolved on the same IP when at least 2 of them exist in the user's UserIP databases.

    Explicitly unlinked pairs (`unlinked_pairs`) are respected and never re-linked.

    Returns:
        True if any new link was recorded.
    """
    if len(looky_usernames) < MIN_GROUP_USERNAMES or not db_usernames_cf:
        return False

    matched: list[str] = []
    seen_cf: set[str] = set()
    for name in looky_usernames:
        clean = name.strip()
        cf = clean.casefold()
        if clean and cf in db_usernames_cf and cf not in seen_cf:
            seen_cf.add(cf)
            matched.append(clean)

    if len(matched) < MIN_GROUP_USERNAMES:
        return False

    with _groups_lock:
        _ensure_loaded_locked()
        changed = False

        for clean in matched:
            cf = clean.casefold()
            if cf not in _cache.canonical_names:
                _cache.canonical_names[cf] = clean
                changed = True

        matched_cfs = [m.casefold() for m in matched]
        for i, cf1 in enumerate(matched_cfs):
            for cf2 in matched_cfs[i + 1 :]:
                pair = _normalize_pair(cf1, cf2)
                if pair is not None and pair not in _cache.unlinked_pairs and pair not in _cache.linked_pairs:
                    _cache.linked_pairs.add(pair)
                    changed = True

        if changed:
            _save_locked()
        return changed


def get_excluded_looky_usernames(ip: str) -> list[str]:
    """Return the list of Looky usernames excluded/removed by the user for `ip`."""
    clean_ip = ip.strip()
    if not clean_ip:
        return []
    with _groups_lock:
        _ensure_loaded_locked()
        return list(_cache.excluded_looky_by_ip.get(clean_ip, ()))


def get_excluded_looky_usernames_cf(ip: str) -> frozenset[str]:
    """Return a frozenset of casefolded Looky usernames excluded/removed by the user for `ip`."""
    clean_ip = ip.strip()
    if not clean_ip:
        return frozenset(())
    with _groups_lock:
        _ensure_loaded_locked()
        names = _cache.excluded_looky_by_ip.get(clean_ip)
        if names is None or not names:
            return frozenset(())
        return frozenset(n.casefold() for n in names)


def exclude_looky_usernames(ip: str, usernames: Sequence[str]) -> bool:
    """Exclude/hide the specified Looky `usernames` on `ip` and persist to disk.

    Returns:
        True if the exclusion list for `ip` changed.
    """
    clean_ip = ip.strip()
    if not clean_ip or not usernames:
        return False

    with _groups_lock:
        _ensure_loaded_locked()
        current = list(_cache.excluded_looky_by_ip.get(clean_ip, ()))
        seen_cf = {n.casefold() for n in current}
        changed = False
        for name in usernames:
            clean_name = name.strip()
            name_cf = clean_name.casefold()
            if clean_name and name_cf not in seen_cf:
                seen_cf.add(name_cf)
                current.append(clean_name)
                changed = True
        if changed:
            _cache.excluded_looky_by_ip[clean_ip] = current
            _save_locked()
        return changed


def restore_looky_usernames(ip: str, usernames: Sequence[str]) -> bool:
    """Restore previously excluded Looky `usernames` on `ip` and persist to disk.

    Returns:
        True if the exclusion list for `ip` changed.
    """
    clean_ip = ip.strip()
    if not clean_ip or not usernames:
        return False

    restore_cfs = {u.strip().casefold() for u in usernames if u.strip()}
    if not restore_cfs:
        return False

    with _groups_lock:
        _ensure_loaded_locked()
        current = _cache.excluded_looky_by_ip.get(clean_ip)
        if current is None or not current:
            return False
        remaining = [n for n in current if n.casefold() not in restore_cfs]
        if len(remaining) == len(current):
            return False
        if remaining:
            _cache.excluded_looky_by_ip[clean_ip] = remaining
        else:
            _cache.excluded_looky_by_ip.pop(clean_ip, None)
        _save_locked()
        return True


def compute_row_group_ids_and_prefixes(
    row_usernames_cf: Sequence[str],
    row_ips: Sequence[str],
    row_indices: Sequence[int],
    clusters_snapshot: Mapping[str, Sequence[str]],
    *,
    descending: bool = False,
) -> tuple[list[str], list[str]]:
    """Compute connected-component group IDs and sort prefixes for table rows."""
    row_count = len(row_usernames_cf)
    if row_count <= 0:
        return [], []

    linked_pairs, unlinked_pairs, _ = get_grouping_snapshot()
    present_cfs = {cf for cf in row_usernames_cf if cf}
    rows_by_ip: dict[str, list[int]] = {}
    for row, ip_val in enumerate(row_ips):
        if ip_val:
            rows_by_ip.setdefault(ip_val, []).append(row)

    adj: dict[str, set[str]] = {}
    for u_cf, cluster in clusters_snapshot.items():
        if u_cf not in present_cfs:
            continue
        cluster_cfs = [m.casefold() for m in cluster if m.casefold() in present_cfs]
        for idx, c1 in enumerate(cluster_cfs):
            for c2 in cluster_cfs[idx + 1 :]:
                pair = (c1, c2) if c1 < c2 else (c2, c1)
                if pair not in unlinked_pairs:
                    adj.setdefault(c1, set()).add(c2)
                    adj.setdefault(c2, set()).add(c1)

    for u1, u2 in linked_pairs:
        if u1 in present_cfs and u2 in present_cfs:
            pair = (u1, u2) if u1 < u2 else (u2, u1)
            if pair not in unlinked_pairs:
                adj.setdefault(u1, set()).add(u2)
                adj.setdefault(u2, set()).add(u1)

    for ip_rows in rows_by_ip.values():
        if len(ip_rows) > 1:
            ip_cfs: list[str] = []
            for r in ip_rows:
                cf = row_usernames_cf[r]
                if cf and cf not in ip_cfs:
                    ip_cfs.append(cf)
            for idx, c1 in enumerate(ip_cfs):
                for c2 in ip_cfs[idx + 1 :]:
                    pair = (c1, c2) if c1 < c2 else (c2, c1)
                    if pair not in unlinked_pairs:
                        adj.setdefault(c1, set()).add(c2)
                        adj.setdefault(c2, set()).add(c1)

    visited: set[str] = set()
    cf_to_group_id: dict[str, str] = {}
    for root in present_cfs:
        if root in visited:
            continue
        comp: list[str] = []
        queue = [root]
        visited.add(root)
        while queue:
            curr = queue.pop()
            comp.append(curr)
            for nb in adj.get(curr, ()):
                if nb not in visited and all(((nb, m) if nb < m else (m, nb)) not in unlinked_pairs for m in comp):
                    visited.add(nb)
                    queue.append(nb)
        gid = f'u:{min(comp)}'
        for member in comp:
            cf_to_group_id[member] = gid

    row_gids: list[str] = []
    group_anchor_index: dict[str, int] = {}
    for row in range(row_count):
        u_cf = row_usernames_cf[row]
        if u_cf:
            gid = cf_to_group_id.get(u_cf, f'u:{u_cf}')
        elif row_ips[row]:
            peer_cf = next((row_usernames_cf[r] for r in rows_by_ip.get(row_ips[row], ()) if row_usernames_cf[r]), '')
            gid = cf_to_group_id.get(peer_cf, f'u:{peer_cf}') if peer_cf else f'ip:{row_ips[row]}'
        else:
            gid = f'row:{row}'
        row_gids.append(gid)
        r_idx = row_indices[row]
        prev_anchor = group_anchor_index.get(gid)
        if prev_anchor is None or (r_idx > prev_anchor if descending else r_idx < prev_anchor):
            group_anchor_index[gid] = r_idx

    prefixes = [f'{group_anchor_index[row_gids[row]]:010d}\x00{row_gids[row]}' for row in range(row_count)]
    return row_gids, prefixes
