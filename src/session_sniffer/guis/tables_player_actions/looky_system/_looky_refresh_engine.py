"""Background worker and UserIP diff/apply engine for Looky System database refreshes."""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, override

import requests
from pydantic import ValidationError
from PySide6.QtCore import Signal

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.tables_player_actions.looky_system._looky_helpers import format_looky_request_error
from session_sniffer.guis.userip_manager_helpers import (
    load_userip_database_model,
    refresh_userip_and_wake_renderer,
    save_userip_database_model,
)
from session_sniffer.models.userip_settings_model import UserIPEntryModel
from session_sniffer.networking.ip_range import entry_ip_covers_ip
from session_sniffer.networking.looky_system import lookup_ip_batches, lookup_username_ips
from session_sniffer.player.userip_loader import append_userip_entries, userip_databases_lock
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from session_sniffer.models.looky_system import LookyPlayer

logger = logging.getLogger(__name__)


def format_db_label(db_path: Path) -> str:
    """Return a clean relative display name (e.g. `Searchlist` or `Crews/DXRT`) for *db_path*."""
    try:
        return db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('').as_posix()
    except ValueError:
        return db_path.stem


def list_available_databases(extra_paths: set[Path]) -> list[tuple[str, Path]]:
    """Return sorted `(label, path)` pairs for all `.json` databases in `USERIP_DATABASES_DIR_PATH` plus *extra_paths*."""
    all_paths = {json_path for json_path in USERIP_DATABASES_DIR_PATH.rglob('*.json') if json_path.is_file()} | extra_paths
    return sorted(((format_db_label(path), path) for path in all_paths), key=lambda pair: pair[0].casefold())


def is_single_ipv4(entry: str) -> bool:
    """Return True if `entry` is a single IPv4 address (not a range, CIDR, or wildcard)."""
    try:
        IPv4Address(entry)
    except ValueError:
        return False
    return True


class LookyRefreshWorker(CrashingQThread):
    """Background thread that batch-looks up IPs and resolves usernames to IPs via the Looky System API."""

    finished_ok: Signal = Signal(object, object)  # dict[str, list[LookyPlayer]], dict[str, list[str]]
    finished_error: Signal = Signal(str)  # error message
    progress_updated: Signal = Signal(str, int, int)  # status_text, current, total

    def __init__(self, ip_addresses: list[str], usernames: list[str], api_key: str, version: str) -> None:
        """Initialize the Looky refresh worker."""
        super().__init__()
        self._ip_addresses, self._usernames, self._api_key, self._version = ip_addresses, usernames, api_key, version

    def _emit_request_error(self, exc: Exception) -> None:
        logger.warning('Looky System lookup failed: %s', exc)
        self.finished_error.emit(format_looky_request_error(exc))

    @override
    def _run(self) -> None:
        """Batch-lookup all IPs, resolve usernames to IPs, and emit the combined results."""
        started_at = time.monotonic()
        logger.info(
            '[Looky System] Starting UserIP refresh worker: %d single IPv4%s, %d unique username%s (version=%s).',
            len(self._ip_addresses),
            pluralize(len(self._ip_addresses)),
            len(self._usernames),
            pluralize(len(self._usernames)),
            self._version,
        )
        combined: dict[str, list[LookyPlayer]] = {}
        discovered_ips_by_cf: dict[str, list[str]] = {}
        try:
            if self._ip_addresses:
                combined.update(
                    lookup_ip_batches(
                        self._ip_addresses,
                        self._api_key,
                        self._version,
                        should_cancel=self.isInterruptionRequested,
                        on_progress=self.progress_updated.emit,
                    ),
                )
            if self._usernames and not self.isInterruptionRequested():
                user_players_by_ip, discovered_ips_by_cf = lookup_username_ips(
                    self._usernames,
                    self._api_key,
                    self._version,
                    should_cancel=self.isInterruptionRequested,
                    on_progress=self.progress_updated.emit,
                )
                for ip, players in user_players_by_ip.items():
                    existing = combined.setdefault(ip, [])
                    seen_cfs = {player.name.casefold() for player in existing}
                    existing.extend(player for player in players if player.name.casefold() not in seen_cfs)
        except (requests.RequestException, ValidationError) as e:
            self._emit_request_error(e)
            return

        if self.isInterruptionRequested():
            logger.info('[Looky System] UserIP refresh worker canceled after %.2fs.', time.monotonic() - started_at)
            return
        matched_ips_count = sum(1 for players in combined.values() if players)
        logger.info(
            '[Looky System] UserIP refresh worker completed in %.2fs: %d IP%s with Looky players, %d username%s resolved to IPs.',
            time.monotonic() - started_at,
            matched_ips_count,
            pluralize(matched_ips_count),
            len(discovered_ips_by_cf),
            pluralize(len(discovered_ips_by_cf)),
        )
        self.finished_ok.emit(combined, discovered_ips_by_cf)


@dataclass(slots=True)
class _DbLookupSnapshot:
    """Pre-indexed snapshot of a UserIP database file for Looky result matching."""

    ip_to_entries: dict[str, list[tuple[str, bool, int, str]]]
    all_usernames_cf: set[str]
    canonical_name_by_cf: dict[str, str]
    notes_by_cf: dict[str, str]
    unconfirmed_ips_by_cf: dict[str, list[tuple[str, str]]]


def _collect_existing_usernames(db_path: Path) -> _DbLookupSnapshot:
    """Build a `_DbLookupSnapshot` for the given database file."""
    ip_to_entries, ip_to_seen = dict[str, list[tuple[str, bool, int, str]]](), dict[str, dict[str, int]]()
    all_usernames_cf, canonical_name_by_cf, notes_by_cf = set[str](), dict[str, str](), dict[str, str]()
    unconfirmed_ips_by_cf, seen_unconfirmed_ips = defaultdict[str, list[tuple[str, str]]](list), defaultdict[str, set[str]](set)
    for entry in load_userip_database_model(db_path).entries:
        username_cf = entry.username.casefold()
        all_usernames_cf.add(username_cf)
        canonical_name_by_cf.setdefault(username_cf, entry.username)
        if entry.notes and username_cf not in notes_by_cf:
            notes_by_cf[username_cf] = entry.notes
        if not entry.is_looky and not entry.detections_count and is_single_ipv4(entry.ip) and entry.ip not in seen_unconfirmed_ips[username_cf]:
            seen_unconfirmed_ips[username_cf].add(entry.ip)
            unconfirmed_ips_by_cf[username_cf].append((entry.ip, entry.notes))
        seen_for_ip = ip_to_seen.setdefault(entry.ip, {})
        if (existing_idx := seen_for_ip.get(username_cf)) is None:
            entries_for_ip = ip_to_entries.setdefault(entry.ip, [])
            seen_for_ip[username_cf] = len(entries_for_ip)
            entries_for_ip.append((entry.username, entry.is_looky, entry.detections_count, entry.notes))
        else:
            entries_for_ip = ip_to_entries[entry.ip]
            prev_name, prev_looky, prev_det, prev_notes = entries_for_ip[existing_idx]
            entries_for_ip[existing_idx] = (prev_name, prev_looky or entry.is_looky, max(prev_det, entry.detections_count), prev_notes or entry.notes)
    return _DbLookupSnapshot(ip_to_entries, all_usernames_cf, canonical_name_by_cf, notes_by_cf, unconfirmed_ips_by_cf)


@dataclass(slots=True)
class SuspectRemoval:
    """An unconfirmed candidate row (`not is_looky and not detections_count`) in Searchlist to delete."""

    db_path: Path
    username_cf: str
    username: str
    ip: str
    looky_username: str = ''
    notes: str = ''
    reason: str = ''


@dataclass(slots=True)
class PendingEntry:
    """A single new or confirmed username=IP entry discovered by Looky, with optional Searchlist candidate removals."""

    db_path: Path
    target_db_path: Path
    ip: str
    username: str
    notes: str = ''
    is_confirmation: bool = False
    is_known_in_db: bool = False
    already_looky: bool = False
    detections_count: int = 0
    suspect_removals: tuple[SuspectRemoval, ...] = ()
    anchor_username: str = ''


def _resolve_cross_db_context(db_path: Path, *, is_searchlist: bool) -> tuple[defaultdict[str, Path], dict[str, Path], list[str]]:
    """Return `(username_targets, single_ip_owners, other_ranges)` across all other non-Searchlist databases."""
    other_dbs = [path for _label, path in list_available_databases(set()) if path != db_path and path.stem.casefold() != 'searchlist']
    fallback_db = next((path for path in other_dbs if path.stem.casefold() == 'randomlist'), db_path) if is_searchlist else db_path
    targets, ip_owners, other_ranges = defaultdict[str, Path](lambda: fallback_db), dict[str, Path](), list[str]()
    for other_db in sorted(other_dbs, key=lambda path: path.stem.casefold() == 'randomlist'):
        for entry in load_userip_database_model(other_db).entries:
            if is_searchlist and entry.username:
                targets.setdefault(entry.username.casefold(), other_db)
            if is_single_ipv4(entry.ip):
                ip_owners.setdefault(entry.ip, other_db)
            elif entry.ip:
                other_ranges.append(entry.ip)
    return targets, ip_owners, other_ranges


def build_pending_entries_for_database(
    db_path: Path,
    ip_addresses: list[str],
    results: dict[str, list[LookyPlayer]],
    *,
    anchor_by_ip: dict[str, str] | None = None,
) -> tuple[list[PendingEntry], list[SuspectRemoval], int]:
    """Build sorted `PendingEntry` and standalone `SuspectRemoval` items for *db_path*."""
    snapshot, is_searchlist = _collect_existing_usernames(db_path), db_path.stem.casefold() == 'searchlist'
    default_targets, ip_owners, other_ranges = _resolve_cross_db_context(db_path, is_searchlist=is_searchlist)
    looky_resolved_ips_by_cf: dict[str, set[str]] = defaultdict(set)
    for db_ip, db_entries in snapshot.ip_to_entries.items():
        for name, is_looky, _det, _notes in db_entries:
            if is_looky:
                looky_resolved_ips_by_cf[name.casefold()].add(db_ip)
    for ip in (addr for addr in ip_addresses if is_single_ipv4(addr)):
        for player_entry in results.get(ip, []):
            looky_resolved_ips_by_cf[player_entry.name.casefold()].add(ip)

    assigned_user_cleanup_cf, seen_ips_for_db, counted_ips_with_results = set[str](), set[str](), set[str]()
    assigned_removal_pairs, pending_entries, standalone_removals = set[tuple[str, str]](), list[PendingEntry](), list[SuspectRemoval]()

    for ip in ip_addresses:
        if not is_single_ipv4(ip) or ip in seen_ips_for_db:
            continue
        is_in_other_db = ip in ip_owners or any(entry_ip_covers_ip(r, ip) for r in other_ranges)
        if not is_searchlist and is_in_other_db and ip not in snapshot.ip_to_entries:
            continue
        seen_ips_for_db.add(ip)
        players, existing_entries_for_ip = results.get(ip, []), snapshot.ip_to_entries.get(ip, [])
        existing_by_cf = {name.casefold(): (name, is_looky, det, notes) for name, is_looky, det, notes in existing_entries_for_ip}
        matched_non_random = (default_targets[p_cf] for p in players if (p_cf := p.name.casefold()) in snapshot.all_usernames_cf)
        ip_target_db = (ip_owners.get(ip) or next((db for db in matched_non_random if db.stem.casefold() != 'randomlist'), None)) if is_searchlist else None
        seen_new_cf: set[str] = set()
        for player_entry in players:
            name_cf = player_entry.name.casefold()
            if name_cf in seen_new_cf:
                continue
            if (existing_info := existing_by_cf.get(name_cf)) is not None:
                display_name, existing_is_looky, existing_det, existing_notes = existing_info
                if is_searchlist and not existing_notes:
                    existing_notes = snapshot.notes_by_cf.get(name_cf, '')
                is_confirmation, is_known = True, True
            else:
                display_name = snapshot.canonical_name_by_cf.get(name_cf, player_entry.name)
                existing_notes = snapshot.notes_by_cf.get(name_cf, '') if is_searchlist else ''
                existing_is_looky, existing_det, is_confirmation, is_known = False, 0, False, name_cf in snapshot.all_usernames_cf

            if (is_searchlist and not (is_confirmation or is_known)) or (not is_searchlist and is_in_other_db and not is_confirmation):
                continue

            removals: list[SuspectRemoval] = []
            if is_searchlist and (is_confirmation or is_known) and name_cf not in assigned_user_cleanup_cf:
                for cand_ip, cand_notes in snapshot.unconfirmed_ips_by_cf.get(name_cf, []):
                    if cand_ip != ip and cand_ip not in looky_resolved_ips_by_cf.get(name_cf, set()) and (name_cf, cand_ip) not in assigned_removal_pairs:
                        assigned_removal_pairs.add((name_cf, cand_ip))
                        cand_looky = ', '.join(dict.fromkeys(player_item.name for player_item in results.get(cand_ip, [])))
                        reason = f'Wrong candidate IP for "{display_name}" (Looky found them on {ip})'
                        removals.append(SuspectRemoval(db_path, name_cf, display_name, cand_ip, cand_looky, cand_notes, reason))
                assigned_user_cleanup_cf.add(name_cf)

            if is_searchlist and (is_confirmation or is_known):
                for o_name, o_looky, o_det, o_notes in existing_entries_for_ip:
                    o_cf = o_name.casefold()
                    if o_cf != name_cf and not o_looky and not o_det and ip not in looky_resolved_ips_by_cf.get(o_cf, set()) and (o_cf, ip) not in assigned_removal_pairs:
                        assigned_removal_pairs.add((o_cf, ip))
                        removals.append(SuspectRemoval(db_path, o_cf, o_name, ip, display_name, o_notes, f'Belongs to "{display_name}" on Looky, not "{o_name}"'))

            target_db = ip_target_db or default_targets[name_cf]
            if existing_is_looky and target_db == db_path and not removals:
                continue
            def_anchor = anchor_by_ip.get(ip, '') if anchor_by_ip is not None else ''
            anchor_user = (existing_entries_for_ip[0][0] if existing_entries_for_ip else def_anchor) if not (is_confirmation or is_known) else (def_anchor or display_name)
            pending_entries.append(PendingEntry(
                db_path, target_db, ip, display_name, existing_notes, is_confirmation, is_known, existing_is_looky, existing_det, tuple(removals), anchor_user,
            ))
            seen_new_cf.add(name_cf)
            counted_ips_with_results.add(ip)

    if is_searchlist:
        for ip in seen_ips_for_db:
            if not (random_label := ', '.join(dict.fromkeys(p.name for p in results.get(ip, []) if p.name.casefold() not in snapshot.all_usernames_cf))):
                continue
            for other_name, other_is_looky, other_det, other_notes in snapshot.ip_to_entries.get(ip, []):
                other_cf = other_name.casefold()
                if not other_is_looky and not other_det and ip not in looky_resolved_ips_by_cf.get(other_cf, set()) and (other_cf, ip) not in assigned_removal_pairs:
                    assigned_removal_pairs.add((other_cf, ip))
                    reason = f'Belongs to random "{random_label}" on Looky, not "{other_name}"'
                    standalone_removals.append(SuspectRemoval(db_path, other_cf, other_name, ip, random_label, other_notes, reason))
                    counted_ips_with_results.add(ip)

    pending_entries.sort(
        key=lambda item: (not (item.is_confirmation or item.is_known_in_db), item.username.casefold(), not item.is_confirmation, not bool(item.suspect_removals)),
    )
    standalone_removals.sort(key=lambda item: (item.username.casefold(), item.ip))
    return pending_entries, standalone_removals, len(counted_ips_with_results)


def apply_accepted_changes(accepted_entries: list[PendingEntry], accepted_removals: list[SuspectRemoval]) -> tuple[int, int, int, int]:
    """Write accepted Looky additions/confirmations/moves and remove checked unconfirmed suspect IPs."""
    affected_dbs, by_target_db = set[Path](), defaultdict[Path, list[PendingEntry]](list)
    moved_from_db, by_db_rem = defaultdict[Path, set[tuple[str, str]]](set), defaultdict[Path, set[tuple[str, str]]](set)
    for entry in accepted_entries:
        by_target_db[entry.target_db_path].append(entry)
        if entry.target_db_path != entry.db_path:
            moved_from_db[entry.db_path].add((entry.username.casefold(), entry.ip))

    total_added, total_moved, total_removed = 0, 0, 0
    with userip_databases_lock():
        for target_db_path, db_entries in by_target_db.items():
            ordered_entries = sorted(db_entries, key=lambda item: not (item.is_confirmation or item.is_known_in_db))
            new_models = [
                UserIPEntryModel(username=e.username, ip=e.ip, is_looky=True, source='Looky', detections_count=e.detections_count, notes=e.notes) for e in ordered_entries
            ]
            anchors = {entry.ip: entry.anchor_username for entry in ordered_entries if entry.anchor_username}
            added_pairs = append_userip_entries(target_db_path, new_models, anchor_usernames_by_ip=anchors)
            added_pairs_cf = {(u.casefold(), ip) for u, ip in added_pairs}
            total_added += sum(1 for entry in ordered_entries if entry.target_db_path == entry.db_path and (entry.username.casefold(), entry.ip) in added_pairs_cf)
            total_moved += sum(1 for entry in ordered_entries if entry.target_db_path != entry.db_path)
            if added_pairs:
                affected_dbs.add(target_db_path)
        for rem in accepted_removals:
            by_db_rem[rem.db_path].add((rem.username_cf, rem.ip))
        for db_path in set(by_db_rem) | set(moved_from_db):
            removal_pairs, move_pairs = by_db_rem.get(db_path, set()), moved_from_db.get(db_path, set())
            db_model, kept_entries, removed_suspects_in_db = load_userip_database_model(db_path), list[UserIPEntryModel](), 0
            for db_entry in db_model.entries:
                cf_pair = (db_entry.username.casefold(), db_entry.ip)
                if cf_pair in move_pairs:
                    continue
                if cf_pair in removal_pairs and not db_entry.is_looky and not db_entry.detections_count:
                    removed_suspects_in_db += 1
                    continue
                kept_entries.append(db_entry)
            if len(kept_entries) != len(db_model.entries):
                db_model.entries = kept_entries
                save_userip_database_model(db_path, db_model)
                total_removed += removed_suspects_in_db
                affected_dbs.add(db_path)
        if total_added or total_moved or total_removed:
            refresh_userip_and_wake_renderer()
    return total_added, total_moved, total_removed, len(affected_dbs)


def collect_usernames_for_requested_ips(db_path: Path, ip_addresses: list[str]) -> list[str]:
    """Return unique usernames from *db_path* whose entry IP matches or covers any of *ip_addresses*."""
    req_set, single_ips = set(ip_addresses), [ip for ip in dict.fromkeys(ip_addresses) if is_single_ipv4(ip)]
    matched_usernames, seen_cfs = list[str](), set[str]()
    for entry in load_userip_database_model(db_path).entries:
        if entry.username and (u_cf := entry.username.casefold()) not in seen_cfs and (entry.ip in req_set or any(entry_ip_covers_ip(entry.ip, r) for r in single_ips)):
            seen_cfs.add(u_cf)
            matched_usernames.append(entry.username)
    return matched_usernames
