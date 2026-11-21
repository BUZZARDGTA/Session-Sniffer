"""Looky System → UserIP username refresh: batch-lookup IPs and append new usernames to database files."""

import contextlib
import logging
from functools import partial
from ipaddress import IPv4Address
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, override, runtime_checkable

from PySide6.QtCore import QEvent, QObject, QPoint, QSignalBlocker, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QKeyEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
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

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._userip_tree_batch_ops import populate_userip_databases_menu
from session_sniffer.guis.delegates import SearchHighlightDelegate
from session_sniffer.guis.fonts import get_monospace_font
from session_sniffer.guis.live_language import register_language_refresh, set_i18n_colon_label, set_tree_headers
from session_sniffer.guis.loading_overlay import run_blocking_with_loading
from session_sniffer.guis.looky_text import get_looky_title
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
from session_sniffer.guis.tables_player_actions.looky_system._looky_refresh_engine import (
    LookyRefreshWorker,
    PendingEntry,
    SuspectRemoval,
    apply_accepted_changes,
    build_pending_entries_for_database,
    collect_usernames_for_requested_ips,
    format_db_label,
    is_single_ipv4,
    list_available_databases,
)
from session_sniffer.guis.theming import get_themed_icon
from session_sniffer.guis.userip_manager_helpers import refresh_userip_and_wake_renderer
from session_sniffer.guis.utils import (
    activate_window,
    apply_adaptive_window_size,
    apply_search_icon,
    render_svg_icon_from_resource,
    scale_by_ui,
    set_clipboard_text,
    set_dialog_window_flags,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import get_excluded_looky_usernames_cf, record_looky_db_correlation
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.looky_system import LookyPlayer

logger = logging.getLogger(__name__)

_COLOR_CONFIRMED = QColor('#38bdf8')
_COLOR_MATCH_TAG = QColor('#fbbf24')
_COLOR_REMOVE_SUSPECT = QColor('#f87171')
_COLOR_NEW = QColor('#a855f7')
_COLOR_NEW_TAG = QColor('#22c55e')
_COLOR_DB_LABEL = QColor('#9ca3af')

_COMBO_STYLESHEET = (
    'QComboBox { background-color: #1a1325; color: #e9d5ff; border: 1px solid #3d2d6e; border-radius: 4px; padding: 2px 6px; font-size: 8.5pt; }'
    'QComboBox:hover { border: 1px solid #7c3aed; }'
    'QComboBox QAbstractItemView { background-color: #161021; color: #e9d5ff; selection-background-color: #4c1d95; border: 1px solid #4c1d95; }'
)

_TREE_HEADERS = ['Username', 'IP', 'Looky Username', 'Action', 'Notes', 'Detections', 'Why / Details', 'Target Database']
_TREE_HEADER_TOOLTIPS: dict[str, str] = {
    'Username': 'The username in your database (or new Looky username). Click to sort.',
    'IP': 'The IP address (real IP for Looky matches, or wrong candidate IP for deletions). Click to sort.',
    'Looky Username': 'The usernames that the Looky System resolved on this IP address. Click to sort.',
    'Action': 'What will happen to this row when you click "Accept Selected". Click to sort.',
    'Notes': 'Notes attached to this username in your database (preserved when confirming or moving). Click to sort.',
    'Detections': 'Number of times Session Sniffer has detected this entry in your database. Click to sort.',
    'Why / Details': 'Plain-English explanation of why this row is shown. Click to sort.',
    'Target Database': 'Database where this username will be saved/moved or deleted from. Click to sort.',
}
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
            return (format_db_label(self_db) if isinstance(self_db, Path) else '').casefold() < (format_db_label(other_db) if isinstance(other_db, Path) else '').casefold()
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
    tip_hint = tr('Tip: Right-click row(s) to check/uncheck, copy, change Target Database, or jump to UserIP Databases Manager.')
    full_tip = f'{text}\n\n{tip_hint}'
    for col in range(len(_TREE_HEADERS)):
        item.setToolTip(col, full_tip)


class LookyRefreshReviewDialog(PlayerInfoDialogMixin):
    """Non-modal dialog displaying a Username-grouped review of Looky results, Target Database selection, and Searchlist cleanup."""

    def __init__(
        self,
        parent: QWidget,
        pending_entries: list[PendingEntry],
        standalone_removals: list[SuspectRemoval],
        *,
        ips_with_results_count: int,
        on_commit: Callable[[LookyRefreshReviewDialog], tuple[int, int, int, int]] | None = None,
    ) -> None:
        super().__init__(None)
        set_dialog_window_flags(self)
        self._owner_window, self._updating_checks, self._updating_combos = parent, False, False
        self._on_commit = on_commit
        self.commit_summary: tuple[int, int, int, int] = (0, 0, 0, 0)
        parent.destroyed.connect(self.close)
        self.setWindowTitle(f'{get_looky_title()} \u2014 {tr("UserIP Refresh Review")}')
        self.setStyleSheet(f'{LOOKY_REVIEW_DIALOG_STYLESHEET}{_COMBO_STYLESHEET}')
        apply_adaptive_window_size(self, min_size=(980, 560), size_1080p=(1280, 720), size_720p=(1040, 620))

        unique_dbs = {entry.db_path for entry in pending_entries} | {rem.db_path for rem in standalone_removals}
        self._available_dbs = list_available_databases(unique_dbs | {entry.target_db_path for entry in pending_entries})
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(12, 12, 12, 12)
        self._header_label = self._add_header_label(
            outer_layout,
            f'\U0001f441  {tr("Looky \u2014 UserIP Refresh Review")}',
            stylesheet=LOOKY_CRAWLER_HEADER_STYLESHEET,
        )
        total_new = sum(1 for entry in pending_entries if not entry.is_confirmation and not entry.is_known_in_db)
        total_matches = sum(1 for entry in pending_entries if entry.is_confirmation or entry.is_known_in_db)
        total_suspects = sum(len(entry.suspect_removals) for entry in pending_entries) + len(standalone_removals)
        self._total_new = total_new
        self._total_matches = total_matches
        self._total_suspects = total_suspects
        self._ips_with_results_count = ips_with_results_count
        self._unique_dbs_count = len(unique_dbs)

        summary_frame = QFrame()
        summary_frame.setStyleSheet(LOOKY_REVIEW_SUMMARY_STYLESHEET)
        summary_layout = QHBoxLayout(summary_frame)
        summary_layout.setContentsMargins(10, 8, 10, 8)
        summary_layout.setSpacing(20)
        self._stat_cards: list[tuple[QLabel, QLabel, Callable[[], str], Callable[[], str]]] = []
        summary_specs: list[tuple[Callable[[], str], str, Callable[[], str]]] = [
            (
                lambda: tr_plural('IP w/ Results', 'IPs w/ Results', self._ips_with_results_count),
                str(ips_with_results_count),
                lambda: tr('Number of queried database IPs for which Looky returned results.'),
            ),
            (
                lambda: tr('Matches in DB'),
                str(total_matches),
                lambda: tr('Usernames returned by Looky that match a username already in your database.'),
            ),
            *(
                [(
                    lambda: tr('Wrong Candidate Rows'),
                    str(total_suspects),
                    lambda: tr('Unconfirmed candidate rows in Searchlist (0 detections) that will be deleted.'),
                )]
                if total_suspects > 0
                else []
            ),
            *(
                [(
                    lambda: tr_plural('New Username', 'New Usernames', self._total_new),
                    str(total_new),
                    lambda: tr('Additional usernames returned by Looky on these IPs that do not exist in your database yet.'),
                )]
                if total_new > 0
                else []
            ),
            (
                lambda: tr_plural('Database', 'Databases', self._unique_dbs_count),
                str(self._unique_dbs_count),
                lambda: tr('Number of source UserIP database files included in this Looky review.'),
            ),
        ]
        for label_fn, value_text, tip_fn in summary_specs:
            stat_layout = QVBoxLayout()
            stat_layout.setSpacing(2)
            tip_text = tip_fn()
            val_lbl = QLabel(value_text, alignment=Qt.AlignmentFlag.AlignCenter)
            val_lbl.setStyleSheet('color: #d8b4fe; font-size: 14pt; font-weight: 700; background: transparent;')
            val_lbl.setToolTip(tip_text)
            stat_layout.addWidget(val_lbl)
            desc_lbl = QLabel(label_fn(), alignment=Qt.AlignmentFlag.AlignCenter)
            desc_lbl.setStyleSheet('color: #9ca3af; font-size: 8pt; font-weight: 600; letter-spacing: 1px; background: transparent;')
            desc_lbl.setToolTip(tip_text)
            stat_layout.addWidget(desc_lbl)
            self._stat_cards.append((val_lbl, desc_lbl, label_fn, tip_fn))
            summary_layout.addLayout(stat_layout)
        outer_layout.addWidget(summary_frame)

        info_bar = QHBoxLayout()
        info_bar.setSpacing(8)
        self._legend_label = QLabel()
        self._legend_label.setStyleSheet('font-size: 8pt; background: transparent;')
        self._update_legend_label()
        info_bar.addWidget(self._legend_label)
        info_bar.addStretch(1)
        self._counter_label = QLabel()
        self._counter_label.setStyleSheet('color: #9ca3af; font-size: 8pt; background: transparent;')
        self._counter_label.setToolTip(tr('Summary of currently checked Looky additions/moves and Searchlist candidate deletions.'))
        info_bar.addWidget(self._counter_label)
        outer_layout.addLayout(info_bar)

        controls_bar = QHBoxLayout()
        controls_bar.setSpacing(8)
        self._matches_only_btn: QPushButton | None = None
        if total_matches > 0 and total_new > 0:
            self._matches_only_btn = QPushButton('', self)
            self._matches_only_btn.setCheckable(True)
            self._matches_only_btn.setChecked(False)
            self._matches_only_btn.setStyleSheet(LOOKY_REVIEW_MATCHES_TOGGLE_STYLESHEET)
            self._matches_only_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self._sync_matches_only_button()
            self._matches_only_btn.clicked.connect(self._on_matches_only_toggled)
            controls_bar.addWidget(self._matches_only_btn)

        self._search_input = QLineEdit(placeholderText=tr('Search username, IP, or notes...'))
        self._search_input.setMinimumWidth(scale_by_ui(200))
        self._search_input.setToolTip(tr('Filter the table by username, IP address, notes, action, or target database.'))
        search_qss = 'QLineEdit { background-color: #1a1325; color: #d4c8f0; border: 1px solid #3d2d6e; border-radius: 6px; padding: 4px 8px; font-size: 9pt; }'
        self._search_input.setStyleSheet(f'{search_qss} QLineEdit:focus {{ border: 1px solid #7c3aed; }}')
        apply_search_icon(self._search_input)
        self._search_input.textChanged.connect(self._apply_tree_visibility)
        controls_bar.addWidget(self._search_input, stretch=1)

        self._has_pending_entries = bool(pending_entries)
        self._bulk_db_combo = QComboBox()
        self._bulk_db_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        if pending_entries:
            move_label = QLabel()
            set_i18n_colon_label(move_label, 'Target DB for Checked')
            move_label.setStyleSheet('color: #d8b4fe; font-size: 8.5pt; font-weight: 600; background: transparent;')
            controls_bar.addWidget(move_label)
            self._bulk_db_combo.setMinimumWidth(scale_by_ui(145))
            self._bulk_db_combo.setToolTip(self._get_bulk_combo_tooltip())
            self._bulk_db_combo.addItem(tr('Auto (Default)'), None)
            for db_label, db_path in self._available_dbs:
                self._bulk_db_combo.addItem(db_label, db_path)
            self._bulk_db_combo.currentIndexChanged.connect(self._on_bulk_db_changed)
            controls_bar.addWidget(self._bulk_db_combo)

        self._selection_buttons: list[tuple[QPushButton, str, str]] = []
        for btn_text, icon_name, tip_text, is_checked in (
            ('Check All', 'square-check.svg', 'Check all currently visible Looky entries and wrong candidate IP removals.', True),
            ('Uncheck All', 'square.svg', 'Uncheck all rows in the table.', False),
        ):
            sel_btn = QPushButton(get_themed_icon(icon_name), tr(btn_text))
            sel_btn.setStyleSheet(LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET)
            sel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            sel_btn.setToolTip(tr(tip_text))
            sel_btn.clicked.connect(partial(self._set_all_checked, checked=is_checked))
            controls_bar.addWidget(sel_btn)
            self._selection_buttons.append((sel_btn, btn_text, tip_text))
        outer_layout.addLayout(controls_bar)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(len(_TREE_HEADERS))
        set_tree_headers(self._tree, _TREE_HEADERS, _TREE_HEADER_TOOLTIPS)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._tree.setAlternatingRowColors(False)
        self._tree.setStyleSheet(LOOKY_REVIEW_TABLE_STYLESHEET)
        self._tree.setRootIsDecorated(any(bool(entry.suspect_removals) for entry in pending_entries))
        self._tree.setIndentation(20)
        self._tree.setIconSize(QSize(18, 18))
        self._tree.setItemDelegate(SearchHighlightDelegate(self._tree, self._search_input.text))
        self._tree.setWordWrap(False)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)
        self._tree.installEventFilter(self)
        setup_table_header_context_menu(self._tree, on_reset=self._reset_column_sizes)
        self._new_items, self._removal_items = list[tuple[QTreeWidgetItem, PendingEntry]](), list[tuple[QTreeWidgetItem, SuspectRemoval]]()
        self._entry_to_removal_children, self._item_to_db_combo = dict[int, list[QTreeWidgetItem]](), dict[int, tuple[QComboBox, Path]]()
        self._populate_tree_items(pending_entries, standalone_removals)
        self._reset_column_sizes()
        self._tree.itemChanged.connect(self._on_item_changed)
        outer_layout.addWidget(self._tree, stretch=1)
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        button_layout.addStretch(1)
        self._accept_btn = QPushButton(f'\u2713 {tr("Accept Selected")}')
        self._cancel_btn = QPushButton(tr('Cancel'))
        for btn, style, tip, slot in (
            (
                self._accept_btn,
                LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
                tr('Apply only the checked rows: add/confirm/move checked Looky entries and delete checked wrong candidate IPs.'),
                self.accept,
            ),
            (
                self._cancel_btn,
                LOOKY_ACTION_BUTTON_STYLESHEET,
                tr('Close this dialog without modifying any UserIP database files.'),
                self.reject,
            ),
        ):
            btn.setStyleSheet(style)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(tip)
            btn.clicked.connect(slot)
            button_layout.addWidget(btn)
        outer_layout.addLayout(button_layout)
        self._apply_tree_visibility()
        self._update_counter()
        register_language_refresh(self, self._refresh_language_texts)

    def _get_bulk_combo_tooltip(self) -> str:
        return tr(
            'Change the Target Database for all currently checked & visible usernames:\n'
            '\u2022 Auto (Default): Restores each row\u2019s smart default Target Database (matched DB or Randomlist for Searchlist, or source DB).\n'
            '\u2022 Specific DB: Moves all checked & visible usernames into the chosen database.',
        )

    def _update_legend_label(self) -> None:
        match_legends = (
            f'<span style="color: #38bdf8;">\u25cf {tr("Confirm / Move")}</span>',
            f'<span style="color: #fbbf24;">\u25cf {tr("Add Real IP (Match in DB)")}</span>',
        )
        suspect_legend = (f'<span style="color: #f87171;">\u25cf {tr("Delete Wrong IP")}</span>',) if self._total_suspects > 0 else ()
        new_legend = (f'<span style="color: #22c55e;">\u25cf {tr("Add New Username")}</span>',) if self._total_new > 0 else ()
        legend_parts = [*(match_legends if self._total_matches > 0 or not self._total_suspects else ()), *suspect_legend, *new_legend]
        self._legend_label.setText('&nbsp;&nbsp;&nbsp;'.join(legend_parts))
        tip_lines = (
            tr('Row Legend:'),
            tr('\u2022 Confirm Looky / Move: Confirms the username on this IP (or moves it to your chosen Target Database).'),
            tr('\u2022 Add Real IP (Match in DB): Username was tracked in your DB on other candidate IPs, and Looky found their real IP here.'),
            tr('\u2022 Delete Wrong IP (Searchlist only): Unconfirmed candidate row (0 detections) in Searchlist ruled out by Looky.'),
            tr('\u2022 Add New Username: Username returned by Looky on this IP that is not in your database yet.'),
        )
        self._legend_label.setToolTip('\n'.join(tip_lines))

    def _refresh_language_texts(self) -> None:
        self.setWindowTitle(f'{get_looky_title()} \u2014 {tr("UserIP Refresh Review")}')
        self._header_label.setText(f'\U0001f441  {tr("Looky \u2014 UserIP Refresh Review")}')
        for val_lbl, desc_lbl, label_fn, tip_fn in self._stat_cards:
            tip_text = tip_fn()
            val_lbl.setToolTip(tip_text)
            desc_lbl.setText(label_fn())
            desc_lbl.setToolTip(tip_text)
        self._update_legend_label()
        self._counter_label.setToolTip(tr('Summary of currently checked Looky additions/moves and Searchlist candidate deletions.'))
        self._sync_matches_only_button()
        self._search_input.setPlaceholderText(tr('Search username, IP, or notes...'))
        self._search_input.setToolTip(tr('Filter the table by username, IP address, notes, action, or target database.'))
        if self._has_pending_entries:
            self._bulk_db_combo.setToolTip(self._get_bulk_combo_tooltip())
            self._bulk_db_combo.setItemText(0, tr('Auto (Default)'))
        for sel_btn, btn_text, tip_text in self._selection_buttons:
            sel_btn.setText(tr(btn_text))
            sel_btn.setToolTip(tr(tip_text))
        self._accept_btn.setText(f'\u2713 {tr("Accept Selected")}')
        self._accept_btn.setToolTip(tr('Apply only the checked rows: add/confirm/move checked Looky entries and delete checked wrong candidate IPs.'))
        self._cancel_btn.setText(tr('Cancel'))
        self._cancel_btn.setToolTip(tr('Close this dialog without modifying any UserIP database files.'))
        with QSignalBlocker(self._tree.model()):
            for item, entry in self._new_items:
                self._refresh_entry_action_display(item, entry)
            for rem_item, rem in self._removal_items:
                self._refresh_removal_item_display(rem_item, rem)
        self._update_counter()

    @override
    def accept(self) -> None:
        """Apply checked Looky updates behind an animated loading overlay before closing the review dialog."""
        if self._on_commit is not None:
            on_commit = self._on_commit
            self.commit_summary = run_blocking_with_loading(
                self,
                tr('Applying Looky Changes\u2026'),
                tr('Updating UserIP databases\u2026'),
                lambda: on_commit(self),
            )
        super().accept()

    @override
    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        """Toggle check state across all selected visible rows when pressing Space on the tree."""
        if (
            watched is self._tree
            and event.type() == QEvent.Type.KeyPress
            and isinstance(event, QKeyEvent)
            and event.key() == Qt.Key.Key_Space
            and event.modifiers() == Qt.KeyboardModifier.NoModifier
        ):
            selected = [it for it in self._tree.selectedItems() if not it.isHidden()]
            if selected:
                should_check = any(it.checkState(0) != Qt.CheckState.Checked for it in selected)
                self._set_items_checked(selected, checked=should_check)
                return True
        return super().eventFilter(watched, event)

    def _set_items_checked(self, items: list[QTreeWidgetItem], *, checked: bool) -> None:
        """Set check state on *items* (and their suspect-removal children) and refresh the counter."""
        if not items:
            return
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        selected_ids = {id(it) for it in items}
        self._updating_checks = True
        try:
            with QSignalBlocker(self._tree.model()):
                for item in items:
                    item.setCheckState(0, state)
                    for rem_child in self._entry_to_removal_children.get(id(item), []):
                        if id(rem_child) not in selected_ids and not rem_child.isHidden():
                            rem_child.setCheckState(0, state)
        finally:
            self._updating_checks = False
        self._tree.viewport().update()
        self._update_counter()

    def _refresh_entry_action_display(self, item: QTreeWidgetItem, entry: PendingEntry) -> None:
        """Update the Action column and tooltip on *item* to reflect `entry.target_db_path`."""
        source_label, target_label = format_db_label(entry.db_path), format_db_label(entry.target_db_path)
        suspect_count = len(entry.suspect_removals)
        cleanup_suffix = (
            f' \u00b7 {tr_plural("{count} wrong candidate row to delete", "{count} wrong candidate rows to delete", suspect_count)}'
            if suspect_count > 0
            else ''
        )
        is_new_username = not entry.is_confirmation and not entry.is_known_in_db
        icon_px = scale_by_ui(16)
        user_text = (entry.anchor_username or '\u2014') if is_new_username else entry.username
        if entry.target_db_path != entry.db_path:
            icon = render_svg_icon_from_resource('box.svg', icon_px, icon_px, _COLOR_CONFIRMED.name())
            action_text = tr('Move to {target}', target=target_label)
            user_color = _COLOR_DB_LABEL if is_new_username else _COLOR_CONFIRMED
            action_color = _COLOR_CONFIRMED
            details = tr(
                'Move from {source} to {target} (Source = Looky){cleanup}',
                source=source_label,
                target=target_label,
                cleanup=cleanup_suffix,
            )
            tip = tr(
                'Looky resolved "{username}" on IP {ip}.\n\n\u2022 Checked: Saves "{username} = {ip}" (Source = Looky) '
                'into "{target}" and removes it from "{source}".\n\u2022 Unchecked: Leaves this entry untouched.',
                username=entry.username,
                ip=entry.ip,
                target=target_label,
                source=source_label,
            )
        elif entry.is_confirmation:
            icon = render_svg_icon_from_resource('user-round-check.svg', icon_px, icon_px, _COLOR_CONFIRMED.name())
            action_text, user_color, action_color = tr('Confirm Looky'), _COLOR_CONFIRMED, _COLOR_CONFIRMED
            details = tr(
                'Already on {ip} in {source} \u2192 Looky confirmed it is correct{cleanup}',
                ip=entry.ip,
                source=source_label,
                cleanup=cleanup_suffix,
            )
            tip = tr(
                'Looky confirmed that IP {ip} belongs to "{username}" in "{source}".\n\n\u2022 Checked: Marks "{username} = {ip}" '
                'as Source = Looky in "{source}".\n\u2022 Tip: Change "Target Database" on the right to move this player into another database.',
                ip=entry.ip,
                username=entry.username,
                source=source_label,
            )
        elif entry.is_known_in_db:
            icon = render_svg_icon_from_resource('user-round-search.svg', icon_px, icon_px, _COLOR_MATCH_TAG.name())
            action_text, user_color, action_color = tr('Add Real IP'), _COLOR_NEW, _COLOR_MATCH_TAG
            details = tr(
                'Tracked in {source} \u2192 Looky found real IP {ip}{cleanup}',
                source=source_label,
                ip=entry.ip,
                cleanup=cleanup_suffix,
            )
            tip = tr(
                '"{username}" is tracked in "{source}", and Looky resolved their real IP as {ip}!\n\n\u2022 Checked: Saves "{username} = {ip}" '
                '(Source = Looky) in "{target}".\n\u2022 Tip: Change "Target Database" on the right to move this player directly to another database.',
                username=entry.username,
                source=source_label,
                ip=entry.ip,
                target=target_label,
            )
        else:
            icon = render_svg_icon_from_resource('user-plus.svg', icon_px, icon_px, _COLOR_NEW_TAG.name())
            action_text, user_color, action_color = tr('Add New Username'), _COLOR_DB_LABEL, _COLOR_NEW_TAG
            details = tr(
                'New username returned by Looky on {ip} (not in {source} yet)',
                ip=entry.ip,
                source=source_label,
            )
            tip = tr(
                'Looky returned "{username}" on IP {ip}. This username is not in "{source}" yet.\n\n'
                '\u2022 Checked: Adds "{username} = {ip}" (Source = Looky) to "{target}".\n\u2022 Unchecked: Ignores this username.',
                username=entry.username,
                ip=entry.ip,
                source=source_label,
                target=target_label,
            )
        for col, text, color in ((0, user_text, user_color), (_COL_ACTION, action_text, action_color), (_COL_DETAILS, details, _COLOR_DB_LABEL)):
            item.setText(col, text)
            item.setForeground(col, QBrush(color))
        item.setIcon(_COL_ACTION, icon)
        _set_row_tooltip(item, entry.target_db_path, tip)

    def _refresh_removal_item_display(self, rem_item: QTreeWidgetItem, rem: SuspectRemoval) -> None:
        """Update the localized action text and tooltip on a suspect-removal tree item."""
        rem_db_label = format_db_label(rem.db_path)
        rem_item.setText(_COL_ACTION, tr('Delete Wrong IP'))
        rem_tip = tr(
            'Why is this row here?\n\u2022 {reason}.\n\u2022 Looky resolved on {ip}: {looky_user}.\n'
            '\u2022 In {db}, "{username} = {ip}" is an unconfirmed manual candidate (Source = Manual, Detections = 0).\n\n'
            'What does checking this box do?\n\u2022 Checked: Deletes "{username} = {ip}" from {db}.\n\u2022 Unchecked: Keeps it in {db}.',
            reason=rem.reason,
            ip=rem.ip,
            looky_user=rem.looky_username or tr('none'),
            db=rem_db_label,
            username=rem.username,
        )
        _set_row_tooltip(rem_item, rem.db_path, rem_tip)

    def _create_removal_item(self, rem: SuspectRemoval, mono_font: QFont, bold_font: QFont) -> QTreeWidgetItem:
        """Create and style a `Delete Wrong IP` tree item for *rem*."""
        rem_db_label = format_db_label(rem.db_path)
        rem_item = _ReviewTreeItem([rem.username, rem.ip, rem.looky_username or '\u2014', '', rem.notes or '\u2014', '0', rem.reason, rem_db_label])
        for col in (0, _COL_IP, _COL_LOOKY_USER):
            rem_item.setFont(col, mono_font)
        rem_item.setIcon(_COL_ACTION, render_svg_icon_from_resource('remove.svg', scale_by_ui(16), scale_by_ui(16), _COLOR_REMOVE_SUSPECT.name()))
        rem_item.setFont(_COL_ACTION, bold_font)
        for col in range(len(_TREE_HEADERS)):
            color = _COLOR_REMOVE_SUSPECT if col in (0, _COL_IP, _COL_ACTION) else (_COLOR_NEW if col == _COL_LOOKY_USER and rem.looky_username else _COLOR_DB_LABEL)
            rem_item.setForeground(col, QBrush(color))
        self._refresh_removal_item_display(rem_item, rem)
        rem_item.setFlags(rem_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        rem_item.setCheckState(0, Qt.CheckState.Checked)
        return rem_item

    def _populate_tree_items(self, pending_entries: list[PendingEntry], standalone_removals: list[SuspectRemoval]) -> None:
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

    def _on_row_combo_changed(self, item: QTreeWidgetItem, entry: PendingEntry, combo: QComboBox, _index: int = 0) -> None:
        """Update *entry*'s target database when its per-row combo box selection changes."""
        if not self._updating_combos and isinstance(chosen_path := combo.currentData(), Path):
            self._apply_target_db([(item, entry)], chosen_path)

    def _apply_target_db(self, targets: list[tuple[QTreeWidgetItem, PendingEntry]], chosen_data: object) -> None:
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
        matches_tip = tr(
            'Filter the review list:\n\u2022 ON: Shows and selects ONLY usernames that match a username in your database, hiding new usernames.\n'
            '\u2022 OFF: Shows all Looky results, including new usernames found on the queried IPs.',
        )
        self._matches_only_btn.setToolTip(matches_tip)
        self._matches_only_btn.setText(tr('Matches Only: ON ({count})', count=self._total_matches) if is_on else tr('Matches Only: OFF (Show All)'))
        toggle_tint = '#ffffff' if is_on else '#9ca3af'
        icon_px = scale_by_ui(16)
        self._matches_only_btn.setIcon(render_svg_icon_from_resource('toggle-right.svg' if is_on else 'toggle-left.svg', icon_px, icon_px, toggle_tint))
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
        if not column and not self._updating_checks and (removal_children := self._entry_to_removal_children.get(id(item))) is not None:
            self._updating_checks = True
            try:
                with QSignalBlocker(self._tree.model()):
                    for rem_child in removal_children:
                        rem_child.setCheckState(0, item.checkState(0))
            finally:
                self._updating_checks = False
            self._tree.viewport().update()
        if not column and not self._updating_checks:
            self._update_counter()

    def _set_all_checked(self, *, checked: bool) -> None:
        """Check all visible rows (when *checked* is True) or uncheck all rows (when *checked* is False)."""
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._updating_checks = True
        try:
            with QSignalBlocker(self._tree.model()):
                for item, _entry in self._new_items:
                    if not (checked and item.isHidden()):
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
        checked_visual = sum(1 for item, _ in self._new_items if item.checkState(0) == Qt.CheckState.Checked)
        total_visual, total_rem = len(self._new_items), len(self._removal_items)
        rem_text = tr_plural(
            '{checked} / {count} wrong candidate row to delete',
            '{checked} / {count} wrong candidate rows to delete',
            total_rem,
            checked=checked_removals,
        )
        looky_part = tr(
            '{checked}/{total} Looky to add/confirm/move',
            checked=checked_visual,
            total=total_visual,
        )
        rem_part = tr_plural(
            '{checked}/{count} wrong candidate row to delete',
            '{checked}/{count} wrong candidate rows to delete',
            total_rem,
            checked=checked_removals,
        )
        both_text = f'{looky_part} \u00b7 {rem_part}'
        single_text = rem_text if self._removal_items else tr('{checked} / {total} selected', checked=checked_visual, total=total_visual)
        self._counter_label.setText(both_text if self._new_items and self._removal_items else single_text)
        self._accept_btn.setEnabled((checked_actionable + checked_removals) > 0)

    def _apply_tree_visibility(self) -> None:
        """Filter top-level Username rows and removal rows according to Matches Only and search query."""
        query, matches_only = self._search_input.text().strip().lower(), self._matches_only_btn is not None and self._matches_only_btn.isChecked()
        self._tree.setUpdatesEnabled(False)
        try:
            for item, entry in self._new_items:
                if matches_only and not (entry.is_confirmation or entry.is_known_in_db):
                    item.setHidden(True)
                    continue
                parent_matches = not query or any(query in item.text(col).lower() for col in range(_COL_TARGET_DB)) or query in format_db_label(entry.target_db_path).lower()
                any_child = any((child := item.child(j)) and any(query in child.text(col).lower() for col in range(len(_TREE_HEADERS))) for j in range(item.childCount()))
                item.setHidden(not (visible := parent_matches or any_child))
                if query and visible and item.childCount() > 0:
                    item.setExpanded(True)
            for rem_item, _rem in self._removal_items:
                if rem_item.parent() is None:
                    rem_item.setHidden(not (not query or any(query in rem_item.text(col).lower() for col in range(len(_TREE_HEADERS)))))
        finally:
            self._tree.setUpdatesEnabled(True)
            self._tree.viewport().update()

    def get_accepted_entries(self) -> list[PendingEntry]:
        """Return the list of new/confirmed/moved entries the user checked."""
        return [entry for item, entry in self._new_items if (not entry.already_looky or entry.target_db_path != entry.db_path) and item.checkState(0) == Qt.CheckState.Checked]

    def get_accepted_removals(self) -> list[SuspectRemoval]:
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
        """Show a right-click context menu to batch check/uncheck, copy, set Target Database, or jump to UserIP Databases Manager."""
        if (item := self._tree.itemAt(pos)) is None:
            return
        selected_items = [it for it in self._tree.selectedItems() if not it.isHidden()] or [item]
        sel_count = len(selected_items)
        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
        copy_icon, search_icon = get_themed_icon('copy.svg'), get_themed_icon('search.svg')
        goto_icon, box_icon = get_themed_icon('arrow-right.svg'), get_themed_icon('box.svg')
        check_icon, uncheck_icon = get_themed_icon('square-check.svg'), get_themed_icon('square.svg')

        check_label = tr('Check Selected ({count})', count=sel_count) if sel_count > 1 else tr('Check Selected')
        uncheck_label = tr('Uncheck Selected ({count})', count=sel_count) if sel_count > 1 else tr('Uncheck Selected')
        menu.addAction(check_icon, check_label, partial(self._set_items_checked, selected_items, checked=True))
        menu.addAction(uncheck_icon, uncheck_label, partial(self._set_items_checked, selected_items, checked=False))
        menu.addSeparator()

        username_str, ip_or_range, looky_user_str = item.text(0).strip(), item.text(_COL_IP).strip(), item.text(_COL_LOOKY_USER).strip()
        db_path = item.data(_COL_TARGET_DB, Qt.ItemDataRole.UserRole)
        user_copy = '' if username_str == '\u2014' else username_str
        looky_copy = '' if looky_user_str in {'\u2014', user_copy} else looky_user_str
        if sel_count == 1:
            for label_text, copy_val in (
                (tr('Copy Username'), user_copy),
                (tr('Copy Looky Username'), looky_copy),
                (tr('Copy IP Address'), ip_or_range),
            ):
                if copy_val:
                    menu.addAction(copy_icon, label_text, partial(set_clipboard_text, copy_val))
        else:
            unique_users = list(dict.fromkeys(u for it in selected_items if (u := it.text(_COL_LOOKY_USER).strip() or it.text(0).strip()) and u != '\u2014'))
            unique_ips = list(dict.fromkeys(ip for it in selected_items if (ip := it.text(_COL_IP).strip())))
            if unique_users:
                menu.addAction(copy_icon, tr('Copy Usernames ({count})', count=len(unique_users)), partial(set_clipboard_text, '\n'.join(unique_users)))
            if unique_ips:
                menu.addAction(copy_icon, tr('Copy IP Addresses ({count})', count=len(unique_ips)), partial(set_clipboard_text, '\n'.join(unique_ips)))

        new_by_id = {id(tree_item): (tree_item, entry) for tree_item, entry in self._new_items}
        selected_entry_pairs = [pair for it in selected_items if (pair := new_by_id.get(id(it))) is not None]
        if selected_entry_pairs:
            menu.addSeparator()
            target_label = (
                tr('Set Target Database ({count})', count=len(selected_entry_pairs))
                if len(selected_entry_pairs) > 1
                else tr('Set Target Database')
            )
            target_menu = menu.addMenu(box_icon, target_label)
            target_menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            target_menu.addAction(tr('Auto (Default)'), lambda: self._apply_target_db(selected_entry_pairs, None))
            target_menu.addSeparator()
            populate_userip_databases_menu(
                target_menu,
                [path for _label, path in self._available_dbs],
                tooltip=tr('Save or move the selected username entry(s) to this UserIP database when accepted.'),
                handler_factory=lambda target_path: lambda: self._apply_target_db(selected_entry_pairs, target_path),
            )

        matched_pair = new_by_id.get(id(item))
        owner = self._owner_window
        if sel_count == 1 and isValid(owner) and isinstance(owner, _UserIPManagerProtocol):
            menu.addSeparator()
            q_user = user_copy or looky_copy
            for act_label, query_val in (
                (tr('Find "{query}" in All Databases', query=q_user), q_user),
                (tr('Find IP {ip} in All Databases', ip=ip_or_range), ip_or_range),
            ):
                if query_val:
                    act = menu.addAction(search_icon, act_label)
                    act.triggered.connect(partial(owner.search_global, query_val))
                    act.triggered.connect(lambda: activate_window(owner))
            if (source_db := matched_pair[1].db_path if matched_pair is not None else (db_path if isinstance(db_path, Path) else None)) is not None:
                act_db = menu.addAction(goto_icon, tr('Go to Database ("{name}")', name=source_db.stem))
                act_db.triggered.connect(lambda: owner.navigate_to_database(source_db, username=user_copy, ip_or_range=ip_or_range))
                act_db.triggered.connect(lambda: activate_window(owner))

        menu.addSeparator()
        sel_all_act = menu.addAction(check_icon, tr('Select All Rows'), self._tree.selectAll)
        sel_all_act.setShortcut('Ctrl+A')

        if viewport := self._tree.viewport():
            menu.popup(viewport.mapToGlobal(pos))


_active_review_dialogs: set[LookyRefreshReviewDialog] = set()


def looky_refresh_userip_entries(parent: QWidget, entries: list[tuple[Path, list[str]]], *, restriction: str | None = None) -> None:
    """Look up IPs and resolve usernames from UserIP databases via the Looky System and open the review dialog."""
    if (api_key := check_looky_prerequisites(parent, restriction=restriction)) is None:
        return
    all_ips = list(dict.fromkeys(ip for _db_path, ip_addresses in entries for ip in ip_addresses if is_single_ipv4(ip)))
    db_usernames_by_path = {db_path: collect_usernames_for_requested_ips(db_path, ip_addresses) for db_path, ip_addresses in entries}
    all_usernames = list(dict.fromkeys(username for usernames in db_usernames_by_path.values() for username in usernames))
    if not all_ips and not all_usernames:
        QMessageBox.information(parent, get_looky_title(), tr('No single IP addresses or usernames found to look up.'))
        return

    worker, loading_dialog = LookyRefreshWorker(all_ips, all_usernames, api_key, Settings.looky_game_version.lower()), LookyRefreshLoadingDialog(parent)

    def _on_finished_ok(results: dict[str, list[LookyPlayer]], discovered_ips_by_cf: dict[str, list[str]]) -> None:
        loading_dialog.accept()
        results = {ip: [lp for lp in lps if not lp.name or lp.name.strip().casefold() not in get_excluded_looky_usernames_cf(ip)] for ip, lps in results.items()}
        discovered_ips_by_cf = {u_cf: [ip for ip in ips if u_cf not in get_excluded_looky_usernames_cf(ip)] for u_cf, ips in discovered_ips_by_cf.items()}
        pending_entries, standalone_removals, total_ips_with_results = list[PendingEntry](), list[SuspectRemoval](), 0
        claimed_ips = {ip for _db_path, ip_addresses in entries for ip in ip_addresses if is_single_ipv4(ip)}
        for db_path, ip_addresses in entries:
            db_users = db_usernames_by_path.get(db_path, [])
            anchor_by_ip = {ip: username for username in reversed(db_users) for ip in discovered_ips_by_cf.get(username.casefold(), [])}
            discovered_for_db = [ip for username in db_users for ip in discovered_ips_by_cf.get(username.casefold(), []) if ip not in claimed_ips]
            claimed_ips.update(discovered_for_db)
            db_pending, db_removals, db_ips_count = build_pending_entries_for_database(db_path, [*ip_addresses, *discovered_for_db], results, anchor_by_ip=anchor_by_ip)
            pending_entries.extend(db_pending)
            standalone_removals.extend(db_removals)
            total_ips_with_results += db_ips_count
        logger.info(
            '[Looky System] UserIP review prepared across %d database%s: %d pending entry change%s, %d standalone suspect removal%s, %d IP%s with Looky results.',
            len(entries), pluralize(len(entries)), len(pending_entries), pluralize(len(pending_entries)), len(standalone_removals), pluralize(len(standalone_removals)),
            total_ips_with_results, pluralize(total_ips_with_results),
        )
        if not pending_entries and not standalone_removals:
            if sum(record_looky_db_correlation([lp.name.strip() for lp in lps if lp.name], UserIPDatabases.get_known_username_dbs_cf()) for lps in results.values()):
                refresh_userip_and_wake_renderer()
            info_message = tr_plural(
                'No new usernames or unconfirmed candidate IPs found.\n\nAll resolved usernames already exist in the database.',
                'No new usernames or unconfirmed candidate IPs found.\n\nAll resolved usernames already exist in the databases.',
                len(entries),
            )
            QMessageBox.information(parent, TITLE, info_message)
            return

        def _commit_review(review_dlg: LookyRefreshReviewDialog) -> tuple[int, int, int, int]:
            accepted = review_dlg.get_accepted_entries()
            total_added, total_moved, total_removed, db_count = apply_accepted_changes(accepted, review_dlg.get_accepted_removals())
            if not (total_added or total_moved or total_removed):
                return 0, 0, 0, 0
            rejected = {(e.ip, e.username.casefold()) for e in pending_entries} - {(e.ip, e.username.casefold()) for e in accepted}
            dbs_cf = UserIPDatabases.get_known_username_dbs_cf()
            if sum(record_looky_db_correlation([n for lp in lps if (n := lp.name.strip()) and (ip, n.casefold()) not in rejected], dbs_cf) for ip, lps in results.items()):
                refresh_userip_and_wake_renderer()
            return total_added, total_moved, total_removed, db_count

        dialog = LookyRefreshReviewDialog(parent, pending_entries, standalone_removals, ips_with_results_count=total_ips_with_results, on_commit=_commit_review)

        def _on_review_accepted() -> None:
            total_added, total_moved, total_removed, db_count = dialog.commit_summary
            if not (total_added or total_moved or total_removed):
                return
            summary_parts: list[str] = []
            if total_added:
                summary_parts.append(tr_plural('Added or confirmed {count} username', 'Added or confirmed {count} usernames', total_added))
            if total_moved:
                summary_parts.append(tr_plural('Moved {count} username', 'Moved {count} usernames', total_moved))
            if total_removed:
                summary_parts.append(tr_plural('Deleted {count} wrong candidate row', 'Deleted {count} wrong candidate rows', total_removed))
            summary_message = tr_plural(
                '{summary} across {count} database.',
                '{summary} across {count} databases.',
                db_count,
                summary='; '.join(summary_parts),
            )
            QMessageBox.information(parent if isValid(parent) else None, TITLE, summary_message)

        dialog.accepted.connect(_on_review_accepted)
        dialog.finished.connect(lambda: _active_review_dialogs.discard(dialog))
        _active_review_dialogs.add(dialog)
        activate_window(dialog)

    worker_links = ((worker.finished_ok, _on_finished_ok), (worker.finished_error, loading_dialog.show_error), (worker.progress_updated, loading_dialog.update_progress))
    for sig, slot in worker_links:
        sig.connect(slot)

    def _on_rejected() -> None:
        for sig, slot in worker_links:
            with contextlib.suppress(TypeError):
                sig.disconnect(slot)
        worker.cancel()

    loading_dialog.rejected.connect(_on_rejected)
    worker.start()
    try:
        loading_dialog.exec()
    finally:
        if worker.isRunning():
            worker.cancel()
