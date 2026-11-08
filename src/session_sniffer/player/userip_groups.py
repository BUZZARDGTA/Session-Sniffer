"""Persistent UserIP account grouping, ungrouping (false-positive exclusions), and per-IP Looky username exclusions."""

import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from session_sniffer.constants.local import APP_DIR_ROAMING
from session_sniffer.utils import FileSignature, get_file_signature

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
    version: int = 0
    file_sig: FileSignature | None = None
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
    """Load `userip_groups.json` into memory if not yet loaded or if modified on disk (caller must hold `_groups_lock`)."""
    current_sig = get_file_signature(USERIP_GROUPS_PATH)
    if _cache.loaded and current_sig == _cache.file_sig:
        return
    if _cache.loaded:
        _cache.version += 1
    _cache.loaded = True
    _cache.file_sig = current_sig
    _cache.linked_pairs.clear()
    _cache.unlinked_pairs.clear()
    _cache.canonical_names.clear()
    _cache.excluded_looky_by_ip.clear()

    if current_sig is None:
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
    _cache.version += 1
    data = UserIPGroupsData(
        linked_pairs=sorted(_cache.linked_pairs),
        unlinked_pairs=sorted(_cache.unlinked_pairs),
        canonical_names=dict(sorted(_cache.canonical_names.items())),
        excluded_looky_usernames=dict(sorted(_cache.excluded_looky_by_ip.items())),
    )
    try:
        USERIP_GROUPS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERIP_GROUPS_PATH.write_text(data.model_dump_json(indent=2), encoding='utf-8')
        _cache.file_sig = get_file_signature(USERIP_GROUPS_PATH)
    except OSError:
        logger.exception('Failed to save UserIP groups to %s', USERIP_GROUPS_PATH)


def get_groups_state_token() -> tuple[int, FileSignature | None]:
    """Return a version and file-signature token representing the current `userip_groups.json` state."""
    with _groups_lock:
        _ensure_loaded_locked()
        return _cache.version, _cache.file_sig


def _expand_unlinked_across_linked(
    linked_pairs: AbstractSet[tuple[str, str]],
    unlinked_pairs: AbstractSet[tuple[str, str]],
) -> set[tuple[str, str]]:
    """Propagate `unlinked_pairs` exclusions across connected components of `linked_pairs`."""
    if not linked_pairs or not unlinked_pairs:
        return set(unlinked_pairs)
    link_adj: dict[str, list[str]] = {}
    for u1, u2 in linked_pairs:
        if (u1, u2) not in unlinked_pairs:
            link_adj.setdefault(u1, []).append(u2)
            link_adj.setdefault(u2, []).append(u1)
    if not link_adj:
        return set(unlinked_pairs)

    comp_by_cf: dict[str, list[str]] = {}
    for root in link_adj:
        if root in comp_by_cf:
            continue
        comp: list[str] = []
        queue = [root]
        comp_by_cf[root] = comp
        while queue:
            curr = queue.pop(0)
            comp.append(curr)
            for nb in link_adj.get(curr, ()):
                if nb not in comp_by_cf and all(((nb, m) if nb < m else (m, nb)) not in unlinked_pairs for m in comp):
                    comp_by_cf[nb] = comp
                    queue.append(nb)

    expanded_unlinked = set(unlinked_pairs)
    for u1, u2 in unlinked_pairs:
        c1 = comp_by_cf.get(u1, (u1,))
        c2 = comp_by_cf.get(u2, (u2,))
        if c1 is c2:
            continue
        for m1 in c1:
            for m2 in c2:
                expanded_unlinked.add((m1, m2) if m1 < m2 else (m2, m1))
    return expanded_unlinked


def get_grouping_snapshot() -> tuple[set[tuple[str, str]], set[tuple[str, str]], dict[str, str]]:
    """Return a copy of `(linked_pairs, unlinked_pairs, canonical_names)`."""
    with _groups_lock:
        _ensure_loaded_locked()
        return (
            set(_cache.linked_pairs),
            _expand_unlinked_across_linked(_cache.linked_pairs, _cache.unlinked_pairs),
            dict(_cache.canonical_names),
        )


def are_usernames_unlinked(u1: str, u2: str) -> bool:
    """Return True if `u1` and `u2` were explicitly ungrouped by the user."""
    pair = _normalize_pair(u1, u2)
    if pair is None:
        return False
    with _groups_lock:
        _ensure_loaded_locked()
        return pair in _expand_unlinked_across_linked(_cache.linked_pairs, _cache.unlinked_pairs)


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

    with _groups_lock:
        _ensure_loaded_locked()
        changed = False

        for clean in cleaned:
            cf = clean.casefold()
            if _cache.canonical_names.get(cf) != clean:
                _cache.canonical_names[cf] = clean
                changed = True

        expanded_cfs: set[str] = set(seen_cf)
        if existing_clusters is not None:
            for cf in list(seen_cf):
                for member in existing_clusters.get(cf, ()):
                    member_cf = member.strip().casefold()
                    if member_cf and not any(
                        _normalize_pair(member_cf, s_cf) in _cache.unlinked_pairs and _normalize_pair(cf, s_cf) not in _cache.unlinked_pairs
                        for s_cf in seen_cf
                    ):
                        expanded_cfs.add(member_cf)

        expanded_list = sorted(expanded_cfs)
        for i, cf1 in enumerate(expanded_list):
            for cf2 in expanded_list[i + 1 :]:
                unlinked_pair = (cf1, cf2)
                if unlinked_pair in _cache.unlinked_pairs:
                    _cache.unlinked_pairs.discard(unlinked_pair)
                    changed = True

        external_unlinked_cfs = {
            u2 if u1 in expanded_cfs else u1
            for u1, u2 in _cache.unlinked_pairs
            if (u1 in expanded_cfs) != (u2 in expanded_cfs)
        }
        for member_cf in expanded_cfs:
            for ext_cf in external_unlinked_cfs:
                if (ext_pair := _normalize_pair(member_cf, ext_cf)) is not None:
                    if ext_pair in _cache.linked_pairs:
                        _cache.linked_pairs.discard(ext_pair)
                        changed = True
                    if ext_pair not in _cache.unlinked_pairs:
                        _cache.unlinked_pairs.add(ext_pair)
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


def rename_username_in_groups(old_username: str, new_username: str) -> bool:
    """Replace `old_username` with `new_username` across persisted group links, unlinks, and canonical names."""
    old_clean, new_clean = old_username.strip(), new_username.strip()
    old_cf, new_cf = old_clean.casefold(), new_clean.casefold()
    if not old_cf or not new_cf:
        return False
    with _groups_lock:
        _ensure_loaded_locked()
        if old_cf == new_cf:
            if old_cf in _cache.canonical_names and _cache.canonical_names[old_cf] != new_clean:
                _cache.canonical_names[old_cf] = new_clean
                _save_locked()
                return True
            return False

        changed = False
        if old_cf in _cache.canonical_names:
            _cache.canonical_names.pop(old_cf, None)
            _cache.canonical_names[new_cf] = new_clean
            changed = True

        new_unlinked: set[tuple[str, str]] = set()
        for u1, u2 in _cache.unlinked_pairs:
            if old_cf in (u1, u2):
                changed = True
                if pair := _normalize_pair(new_cf if u1 == old_cf else u1, new_cf if u2 == old_cf else u2):
                    new_unlinked.add(pair)
            else:
                new_unlinked.add((u1, u2))

        new_linked: set[tuple[str, str]] = set()
        for u1, u2 in _cache.linked_pairs:
            if old_cf in (u1, u2):
                changed = True
                if (pair := _normalize_pair(new_cf if u1 == old_cf else u1, new_cf if u2 == old_cf else u2)) and pair not in new_unlinked:
                    new_linked.add(pair)
            elif (u1, u2) not in new_unlinked:
                new_linked.add((u1, u2))

        if changed:
            _cache.unlinked_pairs = new_unlinked
            _cache.linked_pairs = new_linked
            if any(new_cf in pair for pair in _cache.linked_pairs):
                _cache.canonical_names[new_cf] = new_clean
            _save_locked()
        return changed


def remove_usernames_from_groups(usernames_cf: AbstractSet[str]) -> bool:
    """Remove deleted database usernames (casefolded) from persisted `linked_pairs` and `canonical_names`."""
    if not usernames_cf:
        return False
    with _groups_lock:
        _ensure_loaded_locked()
        changed = False
        for cf in usernames_cf:
            if cf in _cache.canonical_names:
                _cache.canonical_names.pop(cf, None)
                changed = True
            neighbors = sorted({
                pair[1] if pair[0] == cf else pair[0]
                for pair in _cache.linked_pairs
                if (pair[0] == cf and pair[1] not in usernames_cf) or (pair[1] == cf and pair[0] not in usernames_cf)
            })
            for idx, n1 in enumerate(neighbors):
                for n2 in neighbors[idx + 1 :]:
                    bridge = (n1, n2) if n1 < n2 else (n2, n1)
                    if bridge not in _cache.unlinked_pairs and bridge not in _cache.linked_pairs:
                        _cache.linked_pairs.add(bridge)
                        changed = True
        kept_linked = {pair for pair in _cache.linked_pairs if pair[0] not in usernames_cf and pair[1] not in usernames_cf}
        if len(kept_linked) != len(_cache.linked_pairs):
            _cache.linked_pairs = kept_linked
            changed = True
        if changed:
            _save_locked()
        return changed


def record_looky_db_correlation(
    looky_usernames: Sequence[str],
    db_by_username_cf: Mapping[str, Path],
) -> bool:
    """Auto-link Looky usernames resolved on the same IP when at least 2 of them exist in the same UserIP database.

    Explicitly unlinked pairs (`unlinked_pairs`) are respected and never re-linked.

    Returns:
        True if any new link was recorded.
    """
    if len(looky_usernames) < MIN_GROUP_USERNAMES or not db_by_username_cf:
        return False

    matched_by_db: dict[Path, list[str]] = {}
    clean_by_cf: dict[str, str] = {}
    seen_cf: set[str] = set()
    for name in looky_usernames:
        clean = name.strip()
        cf = clean.casefold()
        if clean and cf not in seen_cf and (db_path := db_by_username_cf.get(cf)) is not None:
            seen_cf.add(cf)
            clean_by_cf[cf] = clean
            matched_by_db.setdefault(db_path, []).append(cf)

    eligible_groups = [cfs for cfs in matched_by_db.values() if len(cfs) >= MIN_GROUP_USERNAMES]
    if not eligible_groups:
        return False

    with _groups_lock:
        _ensure_loaded_locked()
        changed = False

        for matched_cfs in eligible_groups:
            for cf in matched_cfs:
                if cf not in _cache.canonical_names:
                    _cache.canonical_names[cf] = clean_by_cf[cf]
                    changed = True
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


def exclude_looky_usernames(
    ip: str,
    usernames: Sequence[str],
    *,
    peer_usernames: Sequence[str] = (),
) -> bool:
    """Exclude/hide the specified Looky `usernames` on `ip` and persist to disk.

    Also removes any Looky-correlated links in `linked_pairs` between the excluded
    `usernames` and `peer_usernames` on `ip`.

    Returns:
        True if the persisted state changed.
    """
    clean_ip = ip.strip()
    if not clean_ip or not usernames:
        return False

    excluded_batch_cfs: set[str] = set()
    peer_cfs = {p.strip().casefold() for p in peer_usernames if p.strip()}

    with _groups_lock:
        _ensure_loaded_locked()
        current = list(_cache.excluded_looky_by_ip.get(clean_ip, ()))
        seen_cf = {n.casefold() for n in current}
        changed = False
        for name in usernames:
            clean_name = name.strip()
            name_cf = clean_name.casefold()
            if clean_name:
                excluded_batch_cfs.add(name_cf)
                if name_cf not in seen_cf:
                    seen_cf.add(name_cf)
                    current.append(clean_name)
                    changed = True
        if changed:
            _cache.excluded_looky_by_ip[clean_ip] = current

        for ex_cf in excluded_batch_cfs:
            for p_cf in peer_cfs:
                if (pair := _normalize_pair(ex_cf, p_cf)) is not None and pair in _cache.linked_pairs:
                    _cache.linked_pairs.discard(pair)
                    changed = True

        if changed:
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
    rows: Sequence[tuple[str, str, int, str]],
    clusters_snapshot: Mapping[str, Sequence[str]],
    *,
    descending: bool = False,
) -> tuple[list[str], list[str]]:
    """Compute connected-component group IDs and sort prefixes for table rows `(username_cf, ip, row_index, db_key)`."""
    row_count = len(rows)
    if row_count <= 0:
        return [], []

    linked_pairs, unlinked_pairs, _ = get_grouping_snapshot()
    ordered_present_nodes = list(dict.fromkeys((db_key, cf) for cf, _, _, db_key in rows if cf))
    nodes_by_db: dict[str, set[str]] = {}
    for db_key, cf in ordered_present_nodes:
        nodes_by_db.setdefault(db_key, set()).add(cf)

    rows_by_db_ip: dict[tuple[str, str], list[int]] = {}
    for row, (_, ip_val, _, db_key) in enumerate(rows):
        if ip_val:
            rows_by_db_ip.setdefault((db_key, ip_val), []).append(row)

    adj: dict[tuple[str, str], dict[tuple[str, str], None]] = {}
    for db_key, db_present_cfs in nodes_by_db.items():
        for u_cf, cluster in clusters_snapshot.items():
            if u_cf not in db_present_cfs:
                continue
            cluster_cfs = [m.casefold() for m in cluster if m.casefold() in db_present_cfs]
            for idx, c1 in enumerate(cluster_cfs):
                for c2 in cluster_cfs[idx + 1 :]:
                    pair = (c1, c2) if c1 < c2 else (c2, c1)
                    if pair not in unlinked_pairs:
                        adj.setdefault((db_key, c1), {})[(db_key, c2)] = None
                        adj.setdefault((db_key, c2), {})[(db_key, c1)] = None

        for u1, u2 in sorted(linked_pairs):
            if u1 in db_present_cfs and u2 in db_present_cfs:
                pair = (u1, u2) if u1 < u2 else (u2, u1)
                if pair not in unlinked_pairs:
                    adj.setdefault((db_key, u1), {})[(db_key, u2)] = None
                    adj.setdefault((db_key, u2), {})[(db_key, u1)] = None

    for (db_key, _), ip_rows in rows_by_db_ip.items():
        if len(ip_rows) > 1:
            ip_cfs = list(dict.fromkeys(rows[r][0] for r in ip_rows if rows[r][0]))
            for idx, c1 in enumerate(ip_cfs):
                for c2 in ip_cfs[idx + 1 :]:
                    pair = (c1, c2) if c1 < c2 else (c2, c1)
                    if pair not in unlinked_pairs:
                        adj.setdefault((db_key, c1), {})[(db_key, c2)] = None
                        adj.setdefault((db_key, c2), {})[(db_key, c1)] = None

    visited: set[tuple[str, str]] = set()
    node_to_group_id: dict[tuple[str, str], str] = {}
    for root in ordered_present_nodes:
        if root in visited:
            continue
        comp: list[str] = []
        queue = [root]
        visited.add(root)
        while queue:
            curr_db, curr_cf = queue.pop(0)
            comp.append(curr_cf)
            for nb_db, nb_cf in adj.get((curr_db, curr_cf), ()):
                if (nb_db, nb_cf) not in visited and all(((nb_cf, m) if nb_cf < m else (m, nb_cf)) not in unlinked_pairs for m in comp):
                    visited.add((nb_db, nb_cf))
                    queue.append((nb_db, nb_cf))
        db_prefix = f'{root[0]}\x00' if root[0] else ''
        gid = f'{max(comp) if descending else min(comp)}\x00{db_prefix}u:{min(comp)}'
        for member in comp:
            node_to_group_id[(root[0], member)] = gid

    row_gids: list[str] = []
    group_anchor_index: dict[str, int] = {}
    for row, (u_cf, ip_val, r_idx, db_key) in enumerate(rows):
        db_prefix = f'{db_key}\x00' if db_key else ''
        if u_cf:
            gid = node_to_group_id.get((db_key, u_cf), f'{u_cf}\x00{db_prefix}u:{u_cf}')
        elif ip_val:
            nearest_peer = min(((abs(r - row), r, rows[r][0]) for r in rows_by_db_ip.get((db_key, ip_val), ()) if rows[r][0]), default=None)
            peer_cf = nearest_peer[2] if nearest_peer is not None else ''
            gid = node_to_group_id.get((db_key, peer_cf), f'{peer_cf}\x00{db_prefix}u:{peer_cf}') if peer_cf else f'\x00{db_prefix}ip:{ip_val}'
        else:
            gid = f'\x00{db_prefix}row:{row}'
        row_gids.append(gid)
        prev_anchor = group_anchor_index.get(gid)
        if prev_anchor is None or (r_idx > prev_anchor if descending else r_idx < prev_anchor):
            group_anchor_index[gid] = r_idx

    prefixes = [f'{group_anchor_index[row_gids[row]]:010d}\x00{row_gids[row]}' for row in range(row_count)]
    return row_gids, prefixes


def build_known_alts_clusters(
    entry_username_groups: Sequence[Sequence[str]],
    ambiguous_usernames: AbstractSet[str],
    single_db_by_cf: Mapping[str, Path],
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Build `(canonical_names, known_alts_clusters)` from entry username groups and persisted group links."""
    linked_pairs, unlinked_pairs, stored_canonical_names = get_grouping_snapshot()
    adj: dict[str, dict[str, None]] = {}
    canonical_names: dict[str, str] = {}
    ip_groups: list[list[str]] = []

    for names in entry_username_groups:
        unique_cfs: list[str] = []
        for raw_name in names:
            if name := raw_name.strip():
                cf = name.casefold()
                canonical_names.setdefault(cf, name)
                if cf not in ambiguous_usernames and cf not in unique_cfs:
                    unique_cfs.append(cf)
        if len(unique_cfs) > 1:
            ip_groups.append(unique_cfs)

    for cf, display_name in stored_canonical_names.items():
        canonical_names.setdefault(cf, display_name)

    eligible_cfs = set(canonical_names) - set(ambiguous_usernames)
    for u_cf, v_cf in sorted(linked_pairs):
        pair = (u_cf, v_cf) if u_cf < v_cf else (v_cf, u_cf)
        if pair in unlinked_pairs or u_cf not in eligible_cfs or v_cf not in eligible_cfs:
            continue
        u_db, v_db = single_db_by_cf.get(u_cf), single_db_by_cf.get(v_cf)
        if u_db is None or v_db is None or u_db == v_db:
            adj.setdefault(u_cf, {})[v_cf] = None
            adj.setdefault(v_cf, {})[u_cf] = None

    for unique_cfs in ip_groups:
        for idx, u_cf in enumerate(unique_cfs):
            for v_cf in unique_cfs[idx + 1 :]:
                pair = (u_cf, v_cf) if u_cf < v_cf else (v_cf, u_cf)
                if pair not in unlinked_pairs:
                    adj.setdefault(u_cf, {})[v_cf] = None
                    adj.setdefault(v_cf, {})[u_cf] = None

    visited: set[str] = set()
    known_alts_clusters: dict[str, list[str]] = {}
    for root in adj:
        if root in visited:
            continue
        component: list[str] = []
        comp_db: Path | None = single_db_by_cf.get(root)
        queue = [root]
        visited.add(root)
        while queue:
            curr = queue.pop(0)
            component.append(curr)
            for neighbor in adj.get(curr, ()):
                nb_db = single_db_by_cf.get(neighbor)
                same_db = comp_db is None or nb_db is None or nb_db == comp_db
                if neighbor not in visited and same_db and all(((neighbor, m) if neighbor < m else (m, neighbor)) not in unlinked_pairs for m in component):
                    comp_db = comp_db or nb_db
                    visited.add(neighbor)
                    queue.append(neighbor)
        if len(component) > 1:
            canonical_cluster = [canonical_names[cf] for cf in component]
            for cf in component:
                known_alts_clusters[cf] = canonical_cluster

    return canonical_names, known_alts_clusters
