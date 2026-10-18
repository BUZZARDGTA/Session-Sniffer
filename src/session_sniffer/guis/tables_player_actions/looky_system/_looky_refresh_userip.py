"""Looky System → UserIP username refresh: batch-lookup IPs and append new usernames to database files."""

import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import partial
from http import HTTPStatus
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, override, runtime_checkable

import requests
from pydantic import ValidationError
from PySide6.QtCore import QPoint, QSignalBlocker, QSize, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QIcon
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.fonts import get_monospace_font
from session_sniffer.guis.looky_text import LOOKY_TITLE
from session_sniffer.guis.stylesheets import (
    LOOKY_ACTION_BUTTON_STYLESHEET,
    LOOKY_CRAWLER_HEADER_STYLESHEET,
    LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
    LOOKY_REVIEW_DIALOG_STYLESHEET,
    LOOKY_REVIEW_MATCHES_TOGGLE_STYLESHEET,
    LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET,
    LOOKY_REVIEW_SUMMARY_STYLESHEET,
    LOOKY_REVIEW_TABLE_STYLESHEET,
    SVG_ICON_CONTEXT_MENU_STYLESHEET,
)
from session_sniffer.guis.table_column_resizing import setup_table_header_context_menu
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.tables_player_actions.looky_system._looky_helpers import LookyRefreshLoadingDialog, check_looky_prerequisites
from session_sniffer.guis.userip_manager_helpers import append_userip_entries, load_userip_database_model, populate_userip_databases_menu, save_userip_database_model
from session_sniffer.guis.utils import (
    activate_window,
    apply_adaptive_window_size,
    apply_search_icon,
    render_svg_icon_from_resource,
    set_clipboard_text,
    set_dialog_window_flags,
)
from session_sniffer.models.userip_settings_model import UserIPEntryModel
from session_sniffer.networking.looky_system import extract_rate_limit_message, extract_rate_limit_wait_seconds, lookup_ip_batch, lookup_username_ips
from session_sniffer.player.userip_loader import update_userip_databases
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from session_sniffer.models.looky_system import LookyPlayer

logger = logging.getLogger(__name__)

_BATCH_SIZE = 32
_COLOR_CONFIRMED, _COLOR_MATCH_TAG, _COLOR_REMOVE_SUSPECT = QColor('#38bdf8'), QColor('#fbbf24'), QColor('#f87171')
_COLOR_NEW, _COLOR_NEW_TAG, _COLOR_DB_LABEL = QColor('#a855f7'), QColor('#22c55e'), QColor('#9ca3af')

_COMBO_STYLESHEET = (
    'QComboBox { background-color: #1a1325; color: #e9d5ff; border: 1px solid #3d2d6e; border-radius: 4px; padding: 2px 6px; font-size: 8.5pt; }'
    'QComboBox:hover { border: 1px solid #7c3aed; }'
    'QComboBox QAbstractItemView { background-color: #161021; color: #e9d5ff; selection-background-color: #4c1d95; border: 1px solid #4c1d95; }'
)


def _format_db_label(db_path: Path) -> str:
    """Return a clean relative display name (e.g. `Searchlist` or `Crews/DXRT`) for *db_path*."""
    try:
        return db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('').as_posix()
    except ValueError:
        return db_path.stem


def _list_available_databases(extra_paths: set[Path]) -> list[tuple[str, Path]]:
    """Return sorted `(label, path)` pairs for all `.json` databases in `USERIP_DATABASES_DIR_PATH` plus *extra_paths*."""
    all_paths = {json_path for json_path in USERIP_DATABASES_DIR_PATH.rglob('*.json') if json_path.is_file()} | extra_paths
    return sorted(((_format_db_label(path), path) for path in all_paths), key=lambda pair: pair[0].casefold())


class _LookyRefreshWorker(CrashingQThread):
    """Background thread that batch-looks up IPs and resolves usernames to IPs via the Looky System API."""

    finished_ok: Signal = Signal(object, object)  # dict[str, list[LookyPlayer]], dict[str, list[str]]
    finished_error: Signal = Signal(str)  # error message
    progress_updated: Signal = Signal(str, int, int)  # status_text, current, total

    def __init__(self, ip_addresses: list[str], usernames: list[str], api_key: str, version: str) -> None:
        super().__init__()
        self._ip_addresses, self._usernames, self._api_key, self._version = ip_addresses, usernames, api_key, version

    def _emit_request_error(self, exc: Exception) -> None:
        logger.warning('Looky System lookup failed: %s', exc)
        if isinstance(exc, requests.HTTPError):
            if exc.response is not None and exc.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                wait_seconds = extract_rate_limit_wait_seconds(exc)
                self.finished_error.emit(f'Rate limited: {extract_rate_limit_message(exc)}. Try again in {wait_seconds} second{pluralize(wait_seconds or 0)}.')
            else:
                self.finished_error.emit(f'Looky System API error: HTTP {exc.response.status_code if exc.response is not None else "?"}')
        elif isinstance(exc, requests.RequestException):
            self.finished_error.emit(f'Looky System request failed: {exc}')
        else:
            self.finished_error.emit(f'Looky System response format unexpected: {exc}')

    @override
    def _run(self) -> None:
        """Batch-lookup all IPs, resolve usernames to IPs, and emit the combined results."""
        combined: dict[str, list[LookyPlayer]] = {}
        discovered_ips_by_cf: dict[str, list[str]] = {}
        batches = [self._ip_addresses[i : i + _BATCH_SIZE] for i in range(0, len(self._ip_addresses), _BATCH_SIZE)]
        try:
            if batches:
                self.progress_updated.emit('Checking IP batches', 0, len(batches))
                with ThreadPoolExecutor(max_workers=min(8, len(batches))) as executor:
                    futures = [executor.submit(lookup_ip_batch, batch, self._api_key, self._version) for batch in batches]
                    for completed_idx, future in enumerate(as_completed(futures), start=1):
                        if self.isInterruptionRequested():
                            return
                        combined.update(future.result())
                        self.progress_updated.emit('Checking IP batches', completed_idx, len(batches))
            if self._usernames and not self.isInterruptionRequested():
                user_players_by_ip, discovered_ips_by_cf = lookup_username_ips(
                    self._usernames, self._api_key, self._version, should_cancel=self.isInterruptionRequested, on_progress=self.progress_updated.emit,
                )
                for ip, players in user_players_by_ip.items():
                    existing = combined.setdefault(ip, [])
                    seen_cfs = {player.name.casefold() for player in existing}
                    existing.extend(player for player in players if player.name.casefold() not in seen_cfs)
        except (requests.RequestException, ValidationError) as e:
            self._emit_request_error(e)
            return

        if not self.isInterruptionRequested():
            self.finished_ok.emit(combined, discovered_ips_by_cf)


def _is_single_ipv4(entry: str) -> bool:
    """Return True if `entry` is a single IPv4 address (not a range, CIDR, or wildcard)."""
    try:
        IPv4Address(entry)
    except ValueError:
        return False
    return True


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
        if not entry.is_looky and not entry.detections_count and _is_single_ipv4(entry.ip) and entry.ip not in seen_unconfirmed_ips[username_cf]:
            seen_unconfirmed_ips[username_cf].add(entry.ip)
            unconfirmed_ips_by_cf[username_cf].append((entry.ip, entry.notes))
        seen_for_ip = ip_to_seen.setdefault(entry.ip, {})
        existing_idx = seen_for_ip.get(username_cf)
        if existing_idx is None:
            entries_for_ip = ip_to_entries.setdefault(entry.ip, [])
            seen_for_ip[username_cf] = len(entries_for_ip)
            entries_for_ip.append((entry.username, entry.is_looky, entry.detections_count, entry.notes))
        else:
            entries_for_ip = ip_to_entries[entry.ip]
            prev_name, prev_looky, prev_det, prev_notes = entries_for_ip[existing_idx]
            entries_for_ip[existing_idx] = (prev_name, prev_looky or entry.is_looky, max(prev_det, entry.detections_count), prev_notes or entry.notes)

    return _DbLookupSnapshot(ip_to_entries, all_usernames_cf, canonical_name_by_cf, notes_by_cf, unconfirmed_ips_by_cf)


@dataclass(slots=True)
class _SuspectRemoval:
    """An unconfirmed candidate row (`not is_looky and not detections_count`) in Searchlist to delete."""

    db_path: Path
    username_cf: str
    username: str
    ip: str
    looky_username: str = ''
    notes: str = ''
    reason: str = ''


@dataclass(slots=True)
class _PendingEntry:
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
    suspect_removals: tuple[_SuspectRemoval, ...] = ()


_TREE_HEADERS = ['Username', 'IP', 'Looky Username', 'Action', 'Notes', 'Detections', 'Why / Details', 'Target Database']
_COL_IP, _COL_LOOKY_USER, _COL_ACTION, _COL_NOTES, _COL_DETECTIONS, _COL_DETAILS, _COL_TARGET_DB = range(1, 8)


class _ReviewTreeItem(QTreeWidgetItem):
    """Tree widget item with case-insensitive text sorting, numeric IPv4/detections sorting, and Target DB sorting."""

    @override
    def __lt__(self, other: QTreeWidgetItem) -> bool:
        col = self.treeWidget().sortColumn()
        if col == _COL_IP:
            return IPv4Address(self.text(_COL_IP)) < IPv4Address(other.text(_COL_IP))
        if col == _COL_DETECTIONS:
            return int(self.text(_COL_DETECTIONS) or 0) < int(other.text(_COL_DETECTIONS) or 0)
        if col == _COL_TARGET_DB:
            self_db, other_db = self.data(_COL_TARGET_DB, Qt.ItemDataRole.UserRole), other.data(_COL_TARGET_DB, Qt.ItemDataRole.UserRole)
            return (_format_db_label(self_db) if isinstance(self_db, Path) else '').casefold() < (_format_db_label(other_db) if isinstance(other_db, Path) else '').casefold()
        return self.text(col).casefold() < other.text(col).casefold()


@runtime_checkable
class _UserIPManagerProtocol(Protocol):
    """Structural protocol for navigating or searching in `UserIPDatabasesManager`."""

    def search_global(self, text: str) -> None:
        """Run a global search across all UserIP databases."""

    def navigate_to_database(self, db_path: Path, *, username: str = '', ip_or_range: str = '') -> None:
        """Load *db_path* and highlight the matching entry."""


def _set_row_tooltip(item: QTreeWidgetItem, db_path: Path, text: str) -> None:
    """Store *db_path* on *item* and assign *text* as the tooltip across all columns."""
    item.setData(_COL_TARGET_DB, Qt.ItemDataRole.UserRole, db_path)
    for col in range(len(_TREE_HEADERS)):
        item.setToolTip(col, f'{text}\n\nTip: Right-click this row to copy, change its Target Database, or jump to it in UserIP Databases Manager.')


class LookyRefreshReviewDialog(PlayerInfoDialogMixin):
    """Non-modal dialog displaying a Username-grouped review of Looky results, Target Database selection, and Searchlist cleanup."""

    def __init__(self, parent: QWidget, pending_entries: list[_PendingEntry], standalone_removals: list[_SuspectRemoval], *, ips_with_results_count: int) -> None:
        super().__init__(None)
        set_dialog_window_flags(self)
        self._owner_window, self._updating_checks, self._updating_combos = parent, False, False
        parent.destroyed.connect(self.close)
        self.setWindowTitle(f'{LOOKY_TITLE} \u2014 UserIP Refresh Review')
        self.setStyleSheet(f'{LOOKY_REVIEW_DIALOG_STYLESHEET}{_COMBO_STYLESHEET}')
        apply_adaptive_window_size(self, min_size=(980, 560), size_1080p=(1280, 720), size_720p=(1040, 620))

        self._confirmed_icon = render_svg_icon_from_resource('user-round-check.svg', 16, 16, '#38bdf8')
        self._move_icon = render_svg_icon_from_resource('box.svg', 16, 16, '#38bdf8')
        self._match_icon = render_svg_icon_from_resource('user-round-search.svg', 16, 16, '#fbbf24')
        self._new_icon = render_svg_icon_from_resource('user-plus.svg', 16, 16, '#22c55e')
        self._remove_icon = render_svg_icon_from_resource('remove.svg', 16, 16, '#f87171')

        unique_dbs = {entry.db_path for entry in pending_entries} | {rem.db_path for rem in standalone_removals}
        self._available_dbs = _list_available_databases(unique_dbs | {entry.target_db_path for entry in pending_entries})

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(12, 12, 12, 12)
        outer_layout.setSpacing(10)
        self._add_header_label(outer_layout, '\U0001f441  Looky \u2014 UserIP Refresh Review', '#1c0a38', '#2e1065').setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)

        total_new = sum(1 for entry in pending_entries if not entry.is_confirmation and not entry.is_known_in_db)
        total_matches = sum(1 for entry in pending_entries if entry.is_confirmation or entry.is_known_in_db)
        total_suspects = sum(len(entry.suspect_removals) for entry in pending_entries) + len(standalone_removals)

        summary_frame = QFrame()
        summary_frame.setStyleSheet(LOOKY_REVIEW_SUMMARY_STYLESHEET)
        summary_layout = QHBoxLayout(summary_frame)
        summary_layout.setContentsMargins(10, 8, 10, 8)
        summary_layout.setSpacing(20)
        new_tip = 'Additional usernames returned by Looky on these IPs that do not exist in your database yet.'
        summary_stats = [
            (f'IP{pluralize(ips_with_results_count)} w/ Results', str(ips_with_results_count), 'Number of queried database IPs for which Looky returned results.'),
            ('Matches in DB', str(total_matches), 'Usernames returned by Looky that match a username already in your database.'),
            *([('Wrong Candidate Rows', str(total_suspects), 'Unconfirmed candidate rows in Searchlist (0 detections) that will be deleted.')] if total_suspects > 0 else []),
            *([(f'New Username{pluralize(total_new)}', str(total_new), new_tip)] if total_new > 0 else []),
            (f'Database{pluralize(len(unique_dbs))}', str(len(unique_dbs)), 'Number of source UserIP database files included in this Looky review.'),
        ]
        for label_text, value_text, stat_tooltip in summary_stats:
            stat_layout = QVBoxLayout()
            stat_layout.setSpacing(2)
            for text_val, style_val in (
                (value_text, 'color: #d8b4fe; font-size: 14pt; font-weight: 700; background: transparent;'),
                (label_text, 'color: #9ca3af; font-size: 8pt; font-weight: 600; letter-spacing: 1px; background: transparent;'),
            ):
                stat_lbl = QLabel(text_val)
                stat_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
                stat_lbl.setStyleSheet(style_val)
                stat_lbl.setToolTip(stat_tooltip)
                stat_layout.addWidget(stat_lbl)
            summary_layout.addLayout(stat_layout)
        outer_layout.addWidget(summary_frame)

        info_bar = QHBoxLayout()
        info_bar.setSpacing(8)
        match_legends = ('<span style="color: #38bdf8;">\u25cf Confirm / Move</span>', '<span style="color: #fbbf24;">\u25cf Add Real IP (Match in DB)</span>')
        legend_parts = [
            *(match_legends if total_matches > 0 or not total_suspects else ()),
            *(('<span style="color: #f87171;">\u25cf Delete Wrong IP</span>',) if total_suspects > 0 else ()),
            *(('<span style="color: #22c55e;">\u25cf Add New Username</span>',) if total_new > 0 else ()),
        ]
        legend_label = QLabel('&nbsp;&nbsp;&nbsp;'.join(legend_parts))
        legend_label.setStyleSheet('font-size: 8pt; background: transparent;')
        legend_label.setToolTip(
            'Row Legend:\n\u2022 Confirm Looky / Move: Confirms the username on this IP (or moves it to your chosen Target Database).\n'
            '\u2022 Add Real IP (Match in DB): Username was tracked in your DB on other candidate IPs, and Looky found their real IP here.\n'
            '\u2022 Delete Wrong IP (Searchlist only): Unconfirmed candidate row (0 detections) in Searchlist ruled out by Looky.\n'
            '\u2022 Add New Username: Username returned by Looky on this IP that is not in your database yet.',
        )
        info_bar.addWidget(legend_label)
        info_bar.addStretch(1)
        self._counter_label = QLabel()
        self._counter_label.setStyleSheet('color: #9ca3af; font-size: 8pt; background: transparent;')
        self._counter_label.setToolTip('Summary of currently checked Looky additions/moves and Searchlist candidate deletions.')
        info_bar.addWidget(self._counter_label)
        outer_layout.addLayout(info_bar)

        controls_bar = QHBoxLayout()
        controls_bar.setSpacing(8)
        self._total_matches = total_matches
        self._matches_only_btn: QPushButton | None = None
        if total_matches > 0 and total_new > 0:
            self._matches_only_btn = QPushButton('', self)
            self._matches_only_btn.setCheckable(True)
            self._matches_only_btn.setChecked(False)
            self._matches_only_btn.setStyleSheet(LOOKY_REVIEW_MATCHES_TOGGLE_STYLESHEET)
            self._matches_only_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._matches_only_btn.setToolTip(
                'Filter the review list:\n\u2022 ON: Shows and selects ONLY usernames that match a username in your database, hiding new usernames.\n'
                '\u2022 OFF: Shows all Looky results, including new usernames found on the queried IPs.',
            )
            self._sync_matches_only_button()
            self._matches_only_btn.clicked.connect(self._on_matches_only_toggled)
            controls_bar.addWidget(self._matches_only_btn)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText('Search username, IP, or notes...')
        self._search_input.setToolTip('Filter the table by username, IP address, notes, action, or target database.')
        self._search_input.setStyleSheet(
            'QLineEdit { background-color: #1a1325; color: #d4c8f0; border: 1px solid #3d2d6e; border-radius: 6px; padding: 4px 8px; font-size: 9pt; }'
            ' QLineEdit:focus { border: 1px solid #7c3aed; }',
        )
        self._search_input.setMinimumWidth(200)
        apply_search_icon(self._search_input)
        self._search_input.textChanged.connect(self._apply_tree_visibility)
        controls_bar.addWidget(self._search_input, stretch=1)

        self._bulk_db_combo = QComboBox()
        if pending_entries:
            move_label = QLabel('Target DB for Checked:')
            move_label.setStyleSheet('color: #d8b4fe; font-size: 8.5pt; font-weight: 600; background: transparent;')
            controls_bar.addWidget(move_label)
            self._bulk_db_combo.setMinimumWidth(145)
            self._bulk_db_combo.setToolTip(
                'Change the Target Database for all currently checked & visible usernames.\n'
                'When you move a Searchlist player to another database, their confirmed IP is saved there and their candidate rows are removed from Searchlist.',
            )
            self._bulk_db_combo.addItem('Keep Current DB', None)
            for db_label, db_path in self._available_dbs:
                self._bulk_db_combo.addItem(db_label, db_path)
            self._bulk_db_combo.currentIndexChanged.connect(self._on_bulk_db_changed)
            controls_bar.addWidget(self._bulk_db_combo)

        for btn_text, icon_name, tip_text, is_checked in (
            ('Select All', 'check.svg', 'Check all currently visible Looky entries and wrong candidate IP removals.', True),
            ('Unselect All', 'x.svg', 'Uncheck all rows in the table.', False),
        ):
            sel_btn = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / icon_name)), btn_text)
            sel_btn.setStyleSheet(LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET)
            sel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            sel_btn.setToolTip(tip_text)
            sel_btn.clicked.connect(partial(self._set_all_checked, checked=is_checked))
            controls_bar.addWidget(sel_btn)
        outer_layout.addLayout(controls_bar)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(len(_TREE_HEADERS))
        self._tree.setHeaderLabels(_TREE_HEADERS)
        header_tooltips = (
            'The username in your database (or new Looky username). Click to sort.',
            'The IP address (real IP for Looky matches, or wrong candidate IP for deletions). Click to sort.',
            'The usernames that the Looky System resolved on this IP address. Click to sort.',
            'What will happen to this row when you click "Accept Selected". Click to sort.',
            'Notes attached to this username in your database (preserved when confirming or moving). Click to sort.',
            'Number of times Session Sniffer has detected this entry in your database. Click to sort.',
            'Plain-English explanation of why this row is shown. Click to sort.',
            'Database where this username will be saved/moved or deleted from. Click to sort.',
        )
        for col, tip in enumerate(header_tooltips):
            self._tree.headerItem().setToolTip(col, tip)
        self._tree.setAlternatingRowColors(False)
        self._tree.setStyleSheet(LOOKY_REVIEW_TABLE_STYLESHEET)
        self._tree.setRootIsDecorated(any(bool(entry.suspect_removals) for entry in pending_entries))
        self._tree.setIndentation(20)
        self._tree.setIconSize(QSize(18, 18))
        self._tree.setItemDelegate(SearchHighlightDelegate(self._tree, self._search_input.text))
        self._tree.setWordWrap(False)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)
        setup_table_header_context_menu(self._tree, on_reset=self._reset_column_sizes)

        self._new_items, self._removal_items = list[tuple[QTreeWidgetItem, _PendingEntry]](), list[tuple[QTreeWidgetItem, _SuspectRemoval]]()
        self._entry_to_removal_children, self._item_to_db_combo = dict[int, list[QTreeWidgetItem]](), dict[int, tuple[QComboBox, Path]]()
        self._populate_tree_items(pending_entries, standalone_removals)
        self._reset_column_sizes()
        self._tree.itemChanged.connect(self._on_item_changed)
        outer_layout.addWidget(self._tree, stretch=1)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        button_layout.addStretch(1)
        self._accept_btn, cancel_btn = QPushButton('\u2713 Accept Selected'), QPushButton('Cancel')
        accept_tip = 'Apply only the checked rows: add/confirm/move checked Looky entries and delete checked wrong candidate IPs.'
        for btn, style, tip, slot in (
            (self._accept_btn, LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET, accept_tip, self.accept),
            (cancel_btn, LOOKY_ACTION_BUTTON_STYLESHEET, 'Close this dialog without modifying any UserIP database files.', self.reject),
        ):
            btn.setStyleSheet(style)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(tip)
            btn.clicked.connect(slot)
            button_layout.addWidget(btn)
        outer_layout.addLayout(button_layout)

        self._apply_tree_visibility()
        self._update_counter()

    def _refresh_entry_action_display(self, item: QTreeWidgetItem, entry: _PendingEntry) -> None:
        """Update the Action column and tooltip on *item* to reflect `entry.target_db_path`."""
        source_label, target_label = _format_db_label(entry.db_path), _format_db_label(entry.target_db_path)
        suspect_count = len(entry.suspect_removals)
        cleanup_suffix = f' \u00b7 {suspect_count} wrong candidate row{pluralize(suspect_count)} to delete' if suspect_count > 0 else ''
        if entry.target_db_path != entry.db_path:
            icon, action_text, user_color, action_color = self._move_icon, f'Move to {target_label}', _COLOR_CONFIRMED, _COLOR_CONFIRMED
            details = f'Move from {source_label} to {target_label} (Source = Looky){cleanup_suffix}'
            tip = (
                f'Looky resolved "{entry.username}" on IP {entry.ip}.\n\n\u2022 Checked: Saves "{entry.username} = {entry.ip}" (Source = Looky) '
                f'into "{target_label}" and removes it from "{source_label}".\n\u2022 Unchecked: Leaves this entry untouched.'
            )
        elif entry.is_confirmation:
            icon, action_text, user_color, action_color = self._confirmed_icon, 'Confirm Looky', _COLOR_CONFIRMED, _COLOR_CONFIRMED
            details = f'Already on {entry.ip} in {source_label} \u2192 Looky confirmed it is correct{cleanup_suffix}'
            tip = (
                f'Looky confirmed that IP {entry.ip} belongs to "{entry.username}" in "{source_label}".\n\n\u2022 Checked: Marks "{entry.username} = {entry.ip}" '
                f'as Source = Looky in "{source_label}".\n\u2022 Tip: Change "Target Database" on the right to move this player into another database.'
            )
        elif entry.is_known_in_db:
            icon, action_text, user_color, action_color = self._match_icon, 'Add Real IP', _COLOR_NEW, _COLOR_MATCH_TAG
            details = f'Tracked in {source_label} \u2192 Looky found real IP {entry.ip}{cleanup_suffix}'
            tip = (
                f'"{entry.username}" is tracked in "{source_label}", and Looky resolved their real IP as {entry.ip}!\n\n\u2022 Checked: Saves "{entry.username} = {entry.ip}" '
                f'(Source = Looky) in "{target_label}".\n\u2022 Tip: Change "Target Database" on the right to move this player directly to another database.'
            )
        else:
            icon, action_text, user_color, action_color = self._new_icon, 'Add New Username', _COLOR_NEW, _COLOR_NEW_TAG
            details = f'New username returned by Looky on {entry.ip} (not in {source_label} yet)'
            tip = (
                f'Looky returned "{entry.username}" on IP {entry.ip}. This username is not in "{source_label}" yet.\n\n'
                f'\u2022 Checked: Adds "{entry.username} = {entry.ip}" (Source = Looky) to "{target_label}".\n\u2022 Unchecked: Ignores this username.'
            )
        for col, text, color in ((0, entry.username, user_color), (_COL_ACTION, action_text, action_color), (_COL_DETAILS, details, _COLOR_DB_LABEL)):
            item.setText(col, text)
            item.setForeground(col, QBrush(color))
        item.setIcon(_COL_ACTION, icon)
        _set_row_tooltip(item, entry.target_db_path, tip)

    def _create_removal_item(self, rem: _SuspectRemoval, mono_font: QFont, bold_font: QFont) -> QTreeWidgetItem:
        """Create and style a `Delete Wrong IP` tree item for *rem*."""
        rem_db_label = _format_db_label(rem.db_path)
        rem_item = _ReviewTreeItem([rem.username, rem.ip, rem.looky_username or '\u2014', 'Delete Wrong IP', rem.notes or '\u2014', '0', rem.reason, rem_db_label])
        for col in (0, _COL_IP, _COL_LOOKY_USER):
            rem_item.setFont(col, mono_font)
        rem_item.setIcon(_COL_ACTION, self._remove_icon)
        rem_item.setFont(_COL_ACTION, bold_font)
        for col in range(len(_TREE_HEADERS)):
            color = _COLOR_REMOVE_SUSPECT if col in (0, _COL_IP, _COL_ACTION) else (_COLOR_NEW if col == _COL_LOOKY_USER and rem.looky_username else _COLOR_DB_LABEL)
            rem_item.setForeground(col, QBrush(color))
        rem_tip = (
            f'Why is this row here?\n\u2022 {rem.reason}.\n\u2022 Looky resolved on {rem.ip}: {rem.looky_username or "none"}.\n'
            f'\u2022 In {rem_db_label}, "{rem.username} = {rem.ip}" is an unconfirmed manual candidate (Source = Manual, Detections = 0).\n\n'
            f'What does checking this box do?\n\u2022 Checked: Deletes "{rem.username} = {rem.ip}" from {rem_db_label}.\n\u2022 Unchecked: Keeps it in {rem_db_label}.'
        )
        _set_row_tooltip(rem_item, rem.db_path, rem_tip)
        rem_item.setFlags(rem_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        rem_item.setCheckState(0, Qt.CheckState.Checked)
        return rem_item

    def _populate_tree_items(self, pending_entries: list[_PendingEntry], standalone_removals: list[_SuspectRemoval]) -> None:
        """Populate top-level Username rows, child Searchlist candidate removal rows, and standalone random-IP removal rows."""
        mono_font, bold_font = get_monospace_font(), QFont()
        bold_font.setBold(True)
        for entry in pending_entries:
            top_item = _ReviewTreeItem([entry.username, entry.ip, entry.username, '', entry.notes or '\u2014', str(entry.detections_count), '', ''])
            for col in (0, _COL_IP, _COL_LOOKY_USER):
                top_item.setFont(col, mono_font)
            top_item.setFont(_COL_ACTION, bold_font)
            top_item.setForeground(_COL_LOOKY_USER, QBrush(_COLOR_NEW))
            for col in (_COL_IP, _COL_NOTES, _COL_DETECTIONS, _COL_DETAILS, _COL_TARGET_DB):
                top_item.setForeground(col, QBrush(_COLOR_DB_LABEL))
            self._refresh_entry_action_display(top_item, entry)
            top_item.setFlags(top_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            top_item.setCheckState(0, Qt.CheckState.Checked)
            self._tree.addTopLevelItem(top_item)

            combo = QComboBox()
            combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            for db_label, db_path in self._available_dbs:
                combo.addItem(db_label, db_path)
            combo.setCurrentIndex(next((i for i, (_lbl, db_path) in enumerate(self._available_dbs) if db_path == entry.target_db_path), 0))
            combo.currentIndexChanged.connect(partial(self._on_row_combo_changed, top_item, entry, combo))
            self._tree.setItemWidget(top_item, _COL_TARGET_DB, combo)
            self._item_to_db_combo[id(top_item)] = (combo, entry.target_db_path)
            self._new_items.append((top_item, entry))

            if entry.suspect_removals:
                removal_children = [self._create_removal_item(rem, mono_font, bold_font) for rem in entry.suspect_removals]
                top_item.addChildren(removal_children)
                self._removal_items.extend(zip(removal_children, entry.suspect_removals, strict=True))
                self._entry_to_removal_children[id(top_item)] = removal_children
                top_item.setExpanded(True)

        for rem in standalone_removals:
            rem_item = self._create_removal_item(rem, mono_font, bold_font)
            self._tree.addTopLevelItem(rem_item)
            self._removal_items.append((rem_item, rem))
        self._tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self._tree.setSortingEnabled(True)

    def _on_row_combo_changed(self, item: QTreeWidgetItem, entry: _PendingEntry, combo: QComboBox, _index: int = 0) -> None:
        """Update *entry*'s target database when its per-row combo box selection changes."""
        if not self._updating_combos and isinstance(chosen_path := combo.currentData(), Path):
            self._apply_target_db([(item, entry)], chosen_path)

    def _apply_target_db(self, targets: list[tuple[QTreeWidgetItem, _PendingEntry]], chosen_data: object) -> None:
        """Set the target database for *targets*, sync their combo boxes, and refresh their action display."""
        if not targets:
            return
        self._updating_combos = self._updating_checks = True
        try:
            with QSignalBlocker(self._tree.model()):
                for item, entry in targets:
                    combo_and_default = self._item_to_db_combo.get(id(item))
                    target_path = chosen_data if isinstance(chosen_data, Path) else (combo_and_default[1] if combo_and_default is not None else entry.db_path)
                    entry.target_db_path = target_path
                    if combo_and_default is not None:
                        combo_and_default[0].setCurrentIndex(next((i for i, (_lbl, db_path) in enumerate(self._available_dbs) if db_path == target_path), 0))
                    self._refresh_entry_action_display(item, entry)
        finally:
            self._updating_combos = self._updating_checks = False
        self._tree.viewport().update()
        self._update_counter()

    def _on_bulk_db_changed(self, _index: int) -> None:
        """Apply the selected bulk target database to all currently checked and visible top-level rows."""
        targets = [(item, entry) for item, entry in self._new_items if not item.isHidden() and item.checkState(0) == Qt.CheckState.Checked]
        self._apply_target_db(targets, self._bulk_db_combo.currentData())

    def _sync_matches_only_button(self) -> None:
        """Update the Matches Only toggle button text, icon, and width to reflect its checked state."""
        if self._matches_only_btn is None:
            return
        self._matches_only_btn.setMinimumWidth(0)
        is_on = self._matches_only_btn.isChecked()
        self._matches_only_btn.setText(f'Matches Only: ON ({self._total_matches})' if is_on else 'Matches Only: OFF (Show All)')
        self._matches_only_btn.setIcon(render_svg_icon_from_resource('user-round-check.svg' if is_on else 'eye.svg', 16, 16, '#ffffff' if is_on else '#9ca3af'))
        self._matches_only_btn.ensurePolished()
        self._matches_only_btn.setMinimumWidth(self._matches_only_btn.sizeHint().width() + 10)

    def _on_matches_only_toggled(self) -> None:
        """When Matches Only is toggled on, select only matched entries and their suspect removals; when off, select and show all."""
        self._sync_matches_only_button()
        if self._matches_only_btn is not None:
            matches_only = self._matches_only_btn.isChecked()
            self._updating_checks = True
            try:
                with QSignalBlocker(self._tree.model()):
                    for item, entry in self._new_items:
                        state = Qt.CheckState.Checked if (entry.is_confirmation or entry.is_known_in_db or not matches_only) else Qt.CheckState.Unchecked
                        item.setCheckState(0, state)
                        for rem_child in self._entry_to_removal_children.get(id(item), []):
                            rem_child.setCheckState(0, state)
            finally:
                self._updating_checks = False
        self._apply_tree_visibility()
        self._update_counter()

    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        """Sync child suspect-removal checkboxes when a parent username checkbox is toggled."""
        if column or self._updating_checks:
            return
        if (removal_children := self._entry_to_removal_children.get(id(item))) is not None:
            self._updating_checks = True
            try:
                with QSignalBlocker(self._tree.model()):
                    for rem_child in removal_children:
                        rem_child.setCheckState(0, item.checkState(0))
            finally:
                self._updating_checks = False
            self._tree.viewport().update()
        self._update_counter()

    def _set_all_checked(self, *, checked: bool) -> None:
        """Check all visible rows (when *checked* is True) or uncheck all rows (when *checked* is False)."""
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._updating_checks = True
        try:
            with QSignalBlocker(self._tree.model()):
                for item, _entry in self._new_items:
                    if checked and item.isHidden():
                        continue
                    item.setCheckState(0, state)
                    for rem_child in self._entry_to_removal_children.get(id(item), []):
                        if not checked or not rem_child.isHidden():
                            rem_child.setCheckState(0, state)
                for rem_item, _rem in self._removal_items:
                    if not checked or (rem_item.parent() is None and not rem_item.isHidden()):
                        rem_item.setCheckState(0, state)
        finally:
            self._updating_checks = False
        self._tree.viewport().update()
        self._update_counter()

    def _update_counter(self) -> None:
        """Refresh the counter label and accept button state based on checked additions/moves and removals."""
        checked_actionable, checked_removals = len(self.get_accepted_entries()), len(self.get_accepted_removals())
        checked_visual = sum(1 for item, _entry in self._new_items if item.checkState(0) == Qt.CheckState.Checked)
        total_visual, total_rem = len(self._new_items), len(self._removal_items)
        if self._new_items and self._removal_items:
            self._counter_label.setText(f'{checked_visual}/{total_visual} Looky to add/confirm/move \u00b7 {checked_removals}/{total_rem} wrong candidate rows to delete')
        elif self._removal_items:
            self._counter_label.setText(f'{checked_removals} / {total_rem} wrong candidate row{pluralize(total_rem)} to delete')
        else:
            self._counter_label.setText(f'{checked_visual} / {total_visual} selected')
        self._accept_btn.setEnabled((checked_actionable + checked_removals) > 0)

    def _apply_tree_visibility(self) -> None:
        """Filter top-level Username rows and removal rows according to Matches Only and search query."""
        query, matches_only = self._search_input.text().strip().lower(), self._matches_only_btn is not None and self._matches_only_btn.isChecked()
        for item, entry in self._new_items:
            if matches_only and not (entry.is_confirmation or entry.is_known_in_db):
                item.setHidden(True)
                continue
            parent_matches = not query or any(query in item.text(col).lower() for col in range(_COL_TARGET_DB)) or query in _format_db_label(entry.target_db_path).lower()
            any_child = any((child := item.child(j)) and any(query in child.text(col).lower() for col in range(len(_TREE_HEADERS))) for j in range(item.childCount()))
            item.setHidden(not (visible := parent_matches or any_child))
            if query and visible and item.childCount() > 0:
                item.setExpanded(True)
        for rem_item, _rem in self._removal_items:
            if rem_item.parent() is None:
                rem_item.setHidden(not (not query or any(query in rem_item.text(col).lower() for col in range(len(_TREE_HEADERS)))))
        self._tree.viewport().update()

    def get_accepted_entries(self) -> list[_PendingEntry]:
        """Return the list of new/confirmed/moved entries the user checked."""
        return [entry for item, entry in self._new_items if (not entry.already_looky or entry.target_db_path != entry.db_path) and item.checkState(0) == Qt.CheckState.Checked]

    def get_accepted_removals(self) -> list[_SuspectRemoval]:
        """Return the list of unconfirmed suspect IP entries the user checked for removal."""
        return [rem for item, rem in self._removal_items if item.checkState(0) == Qt.CheckState.Checked]

    def _reset_column_sizes(self) -> None:
        """Reset column widths back to their initial default layout."""
        if not (header := self._tree.header()):
            return
        col_bounds = (
            (0, 140, 260), (_COL_IP, 115, 160), (_COL_LOOKY_USER, 130, 220), (_COL_ACTION, 185, 240),
            (_COL_NOTES, 75, 145), (_COL_DETECTIONS, 85, 110), (_COL_TARGET_DB, 155, 155),
        )
        for col, min_w, max_w in col_bounds:
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            self._tree.setColumnWidth(col, min(max(self._tree.sizeHintForColumn(col) + 16, min_w), max_w))
        header.setSectionResizeMode(_COL_DETAILS, QHeaderView.ResizeMode.Stretch)
        header.setMinimumSectionSize(30)

    def _show_context_menu(self, pos: QPoint) -> None:
        """Show a right-click context menu to copy IP/username, set Target Database, or jump to UserIP Databases Manager."""
        if (item := self._tree.itemAt(pos)) is None:
            return
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        copy_icon, search_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg'))
        goto_icon, box_icon = QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'arrow-right.svg')), QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'box.svg'))
        username_str, ip_or_range, looky_user_str = item.text(0).strip(), item.text(_COL_IP).strip(), item.text(_COL_LOOKY_USER).strip()
        db_path = item.data(_COL_TARGET_DB, Qt.ItemDataRole.UserRole)
        looky_copy = '' if looky_user_str in {'\u2014', username_str} else looky_user_str
        for label_text, copy_val in (('Copy Username', username_str), ('Copy Looky Username', looky_copy), ('Copy IP Address', ip_or_range)):
            if copy_val:
                menu.addAction(copy_icon, label_text, partial(set_clipboard_text, copy_val))

        matched_pair = next(((tree_item, entry) for tree_item, entry in self._new_items if tree_item is item), None)
        if matched_pair is not None:
            tree_item, pending_entry = matched_pair
            menu.addSeparator()
            target_menu = menu.addMenu(box_icon, 'Set Target Database')
            target_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            populate_userip_databases_menu(
                target_menu, [path for _label, path in self._available_dbs], tooltip='Save or move this username entry to this UserIP database when accepted.',
                handler_factory=lambda target_path: lambda: self._apply_target_db([(tree_item, pending_entry)], target_path),
            )

        owner = self._owner_window
        if isValid(owner) and isinstance(owner, _UserIPManagerProtocol):
            menu.addSeparator()
            for act_label, query_val in ((f'Find "{username_str}" in All Databases', username_str), (f'Find IP {ip_or_range} in All Databases', ip_or_range)):
                if query_val:
                    act = menu.addAction(search_icon, act_label)
                    act.triggered.connect(partial(owner.search_global, query_val))
                    act.triggered.connect(lambda: activate_window(owner))
            if (source_db := matched_pair[1].db_path if matched_pair is not None else (db_path if isinstance(db_path, Path) else None)) is not None:
                act_db = menu.addAction(goto_icon, f'Go to Database ("{source_db.stem}")')
                act_db.triggered.connect(lambda: owner.navigate_to_database(source_db, username=username_str, ip_or_range=ip_or_range))
                act_db.triggered.connect(lambda: activate_window(owner))

        if viewport := self._tree.viewport():
            menu.popup(viewport.mapToGlobal(pos))


def _resolve_default_targets(db_path: Path, *, is_searchlist: bool) -> defaultdict[str, Path]:
    """Return a `username_cf -> target_db_path` mapping (other DB if matched, else `Randomlist` for Searchlist)."""
    other_dbs = [path for _label, path in _list_available_databases(set()) if path.stem.casefold() != 'searchlist'] if is_searchlist else []
    fallback_db = next((path for path in other_dbs if path.stem.casefold() == 'randomlist'), db_path)
    targets = defaultdict[str, Path](lambda: fallback_db)
    for other_db in sorted(other_dbs, key=lambda path: path.stem.casefold() == 'randomlist'):
        for entry in load_userip_database_model(other_db).entries:
            if entry.username:
                targets.setdefault(entry.username.casefold(), other_db)
    return targets


def _build_pending_entries_for_database(
    db_path: Path, ip_addresses: list[str], results: dict[str, list[LookyPlayer]],
) -> tuple[list[_PendingEntry], list[_SuspectRemoval], int]:
    """Build sorted `_PendingEntry` and standalone `_SuspectRemoval` items for *db_path*."""
    snapshot, is_searchlist = _collect_existing_usernames(db_path), db_path.stem.casefold() == 'searchlist'
    default_targets = _resolve_default_targets(db_path, is_searchlist=is_searchlist)
    looky_resolved_ips_by_cf: dict[str, set[str]] = defaultdict(set)
    for db_ip, db_entries in snapshot.ip_to_entries.items():
        for name, is_looky, _det, _notes in db_entries:
            if is_looky:
                looky_resolved_ips_by_cf[name.casefold()].add(db_ip)
    for ip in ip_addresses:
        if _is_single_ipv4(ip):
            for player_entry in results.get(ip, []):
                looky_resolved_ips_by_cf[player_entry.name.casefold()].add(ip)

    assigned_user_cleanup_cf, seen_ips_for_db, counted_ips_with_results = set[str](), set[str](), set[str]()
    assigned_removal_pairs, pending_entries, standalone_removals = set[tuple[str, str]](), list[_PendingEntry](), list[_SuspectRemoval]()

    for ip in ip_addresses:
        if not _is_single_ipv4(ip) or ip in seen_ips_for_db:
            continue
        seen_ips_for_db.add(ip)
        players, existing_entries_for_ip = results.get(ip, []), snapshot.ip_to_entries.get(ip, [])
        existing_by_cf = {name.casefold(): (name, is_looky, det, notes) for name, is_looky, det, notes in existing_entries_for_ip}
        seen_new_cf: set[str] = set()
        for player_entry in players:
            name_cf = player_entry.name.casefold()
            if name_cf in seen_new_cf:
                continue
            if (existing_info := existing_by_cf.get(name_cf)) is not None:
                display_name, existing_is_looky, existing_det, existing_notes = existing_info
                is_confirmation, is_known = True, True
            else:
                display_name, existing_notes = snapshot.canonical_name_by_cf.get(name_cf, player_entry.name), snapshot.notes_by_cf.get(name_cf, '')
                existing_is_looky, existing_det, is_confirmation, is_known = False, 0, False, name_cf in snapshot.all_usernames_cf

            if is_searchlist and not (is_confirmation or is_known):
                continue

            removals: list[_SuspectRemoval] = []
            if is_searchlist and (is_confirmation or is_known) and name_cf not in assigned_user_cleanup_cf:
                for cand_ip, cand_notes in snapshot.unconfirmed_ips_by_cf.get(name_cf, []):
                    if cand_ip != ip and cand_ip not in looky_resolved_ips_by_cf.get(name_cf, set()) and (name_cf, cand_ip) not in assigned_removal_pairs:
                        assigned_removal_pairs.add((name_cf, cand_ip))
                        cand_looky = ', '.join(dict.fromkeys(player_item.name for player_item in results.get(cand_ip, [])))
                        reason = f'Wrong candidate IP for "{display_name}" (Looky found them on {ip})'
                        removals.append(_SuspectRemoval(db_path, name_cf, display_name, cand_ip, cand_looky, cand_notes, reason))
                assigned_user_cleanup_cf.add(name_cf)

            if is_searchlist and (is_confirmation or is_known):
                for other_name, other_is_looky, other_det, other_notes in existing_entries_for_ip:
                    other_cf = other_name.casefold()
                    if (
                        other_cf != name_cf and not other_is_looky and not other_det
                        and ip not in looky_resolved_ips_by_cf.get(other_cf, set()) and (other_cf, ip) not in assigned_removal_pairs
                    ):
                        assigned_removal_pairs.add((other_cf, ip))
                        reason = f'Belongs to "{display_name}" on Looky, not "{other_name}"'
                        removals.append(_SuspectRemoval(db_path, other_cf, other_name, ip, display_name, other_notes, reason))

            if existing_is_looky and default_targets[name_cf] == db_path and not removals:
                continue
            pending_entries.append(
                _PendingEntry(db_path, default_targets[name_cf], ip, display_name, existing_notes, is_confirmation, is_known, existing_is_looky, existing_det, tuple(removals)),
            )
            seen_new_cf.add(name_cf)
            counted_ips_with_results.add(ip)

    if is_searchlist:
        for ip in seen_ips_for_db:
            random_label = ', '.join(dict.fromkeys(player_entry.name for player_entry in results.get(ip, []) if player_entry.name.casefold() not in snapshot.all_usernames_cf))
            if not random_label:
                continue
            for other_name, other_is_looky, other_det, other_notes in snapshot.ip_to_entries.get(ip, []):
                other_cf = other_name.casefold()
                if not other_is_looky and not other_det and ip not in looky_resolved_ips_by_cf.get(other_cf, set()) and (other_cf, ip) not in assigned_removal_pairs:
                    assigned_removal_pairs.add((other_cf, ip))
                    reason = f'Belongs to random "{random_label}" on Looky, not "{other_name}"'
                    standalone_removals.append(_SuspectRemoval(db_path, other_cf, other_name, ip, random_label, other_notes, reason))
                    counted_ips_with_results.add(ip)

    pending_entries.sort(
        key=lambda item: (not (item.is_confirmation or item.is_known_in_db), not bool(item.suspect_removals), not item.is_confirmation, item.username.casefold()),
    )
    standalone_removals.sort(key=lambda item: (item.username.casefold(), item.ip))
    return pending_entries, standalone_removals, len(counted_ips_with_results)


def _apply_accepted_changes(accepted_entries: list[_PendingEntry], accepted_removals: list[_SuspectRemoval]) -> tuple[int, int, int, int]:
    """Write accepted Looky additions/confirmations/moves and remove checked unconfirmed suspect IPs."""
    affected_dbs, by_target_db = set[Path](), defaultdict[Path, list[_PendingEntry]](list)
    moved_from_db, by_db_rem = defaultdict[Path, set[tuple[str, str]]](set), defaultdict[Path, set[tuple[str, str]]](set)
    for entry in accepted_entries:
        by_target_db[entry.target_db_path].append(entry)
        if entry.target_db_path != entry.db_path:
            moved_from_db[entry.db_path].add((entry.username.casefold(), entry.ip))

    total_added, total_moved, total_removed = 0, 0, 0
    for target_db_path, db_entries in by_target_db.items():
        new_models = [UserIPEntryModel(username=entry.username, ip=entry.ip, is_looky=True, source='Looky', notes=entry.notes) for entry in db_entries]
        added_pairs, moved_in_batch = append_userip_entries(target_db_path, new_models), sum(1 for entry in db_entries if entry.target_db_path != entry.db_path)
        if added_pairs or moved_in_batch:
            total_added += max(0, len(added_pairs) - moved_in_batch)
            total_moved += moved_in_batch
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

    return total_added, total_moved, total_removed, len(affected_dbs)


_active_review_dialogs: set[LookyRefreshReviewDialog] = set()


def looky_refresh_userip_entries(parent: QWidget, entries: list[tuple[Path, list[str]]]) -> None:
    """Look up IPs and resolve usernames from UserIP databases via the Looky System and open the review dialog."""
    if (api_key := check_looky_prerequisites(parent)) is None:
        return
    all_ips = list(dict.fromkeys(ip for _db_path, ip_addresses in entries for ip in ip_addresses if _is_single_ipv4(ip)))
    db_usernames_by_path = {db_path: list(dict.fromkeys(entry.username for entry in load_userip_database_model(db_path).entries if entry.username)) for db_path, _ in entries}
    all_usernames = list(dict.fromkeys(username for usernames in db_usernames_by_path.values() for username in usernames))
    if not all_ips and not all_usernames:
        QMessageBox.information(parent, LOOKY_TITLE, 'No single IP addresses or usernames found to look up.')
        return

    worker, loading_dialog = _LookyRefreshWorker(all_ips, all_usernames, api_key, Settings.looky_game_version.lower()), LookyRefreshLoadingDialog(parent)

    def _on_finished_ok(results: dict[str, list[LookyPlayer]], discovered_ips_by_cf: dict[str, list[str]]) -> None:
        loading_dialog.accept()
        pending_entries, standalone_removals, total_ips_with_results = list[_PendingEntry](), list[_SuspectRemoval](), 0
        for db_path, ip_addresses in entries:
            discovered_for_db = [ip for username in db_usernames_by_path.get(db_path, []) for ip in discovered_ips_by_cf.get(username.casefold(), [])]
            db_pending, db_removals, db_ips_count = _build_pending_entries_for_database(db_path, [*ip_addresses, *discovered_for_db], results)
            pending_entries.extend(db_pending)
            standalone_removals.extend(db_removals)
            total_ips_with_results += db_ips_count
        if not pending_entries and not standalone_removals:
            QMessageBox.information(
                parent, TITLE, f'No new usernames or unconfirmed candidate IPs found.\n\nAll resolved usernames already exist in the database{pluralize(len(entries))}.',
            )
            return

        dialog = LookyRefreshReviewDialog(parent, pending_entries, standalone_removals, ips_with_results_count=total_ips_with_results)

        def _on_review_accepted() -> None:
            accepted_entries, accepted_removals = dialog.get_accepted_entries(), dialog.get_accepted_removals()
            if not (accepted_entries or accepted_removals):
                return
            total_added, total_moved, total_removed, db_count = _apply_accepted_changes(accepted_entries, accepted_removals)
            if not (total_added or total_moved or total_removed):
                return
            update_userip_databases()
            wake_rendering_core()
            summary_parts = [
                part for count, part in (
                    (total_added, f'added or confirmed {total_added} username{pluralize(total_added)}'),
                    (total_moved, f'moved {total_moved} username{pluralize(total_moved)}'),
                    (total_removed, f'deleted {total_removed} wrong candidate row{pluralize(total_removed)}'),
                ) if count
            ]
            QMessageBox.information(parent if isValid(parent) else None, TITLE, f'{", ".join(summary_parts).capitalize()} across {db_count} database{pluralize(db_count)}.')

        dialog.accepted.connect(_on_review_accepted)
        dialog.finished.connect(lambda: _active_review_dialogs.discard(dialog))
        _active_review_dialogs.add(dialog)
        activate_window(dialog)

    for sig, slot in ((worker.finished_ok, _on_finished_ok), (worker.finished_error, loading_dialog.show_error), (worker.progress_updated, loading_dialog.update_progress)):
        sig.connect(slot)

    def _on_rejected() -> None:
        for sig, slot in ((worker.finished_ok, _on_finished_ok), (worker.finished_error, loading_dialog.show_error), (worker.progress_updated, loading_dialog.update_progress)):
            try:
                sig.disconnect(slot)
            except TypeError as e:
                logger.debug('Failed to disconnect worker signal: %s', e)
        worker.cancel()

    loading_dialog.rejected.connect(_on_rejected)
    worker.start()
    try:
        loading_dialog.exec()
    finally:
        if worker.isRunning():
            worker.cancel()
