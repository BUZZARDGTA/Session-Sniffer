"""Looky System → UserIP username refresh: batch-lookup IPs and append new usernames to database files."""

from dataclasses import dataclass
from http import HTTPStatus
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, override

import requests
from pydantic import ValidationError
from PyQt6.QtCore import QPoint, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
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

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._crashing_qthread import CrashingQThread
from session_sniffer.guis.looky_text import LOOKY_TITLE
from session_sniffer.guis.stylesheets import (
    LOOKY_ACTION_BUTTON_STYLESHEET,
    LOOKY_CRAWLER_HEADER_STYLESHEET,
    LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET,
    LOOKY_REVIEW_DIALOG_STYLESHEET,
    LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET,
    LOOKY_REVIEW_SUMMARY_STYLESHEET,
    LOOKY_REVIEW_TABLE_STYLESHEET,
)
from session_sniffer.guis.tables_player_actions._looky_helpers import build_looky_progress_widgets, check_looky_prerequisites
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.userip_manager_helpers import iter_userip_entries
from session_sniffer.guis.utils import apply_search_icon, set_dialog_window_flags
from session_sniffer.networking.looky_system import (
    extract_rate_limit_message,
    extract_rate_limit_wait_seconds,
    lookup_ip_batch,
)
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import write_lines_to_file

if TYPE_CHECKING:
    from pathlib import Path

    from session_sniffer.models.looky_system import LookyPlayer

_BATCH_SIZE = 32

# Visual constants for tree item styling
_COLOR_EXISTING = QColor('#6b6980')       # muted grey-purple for existing usernames
_COLOR_EXISTING_TAG = QColor('#4a4660')   # dimmer tag color
_COLOR_NEW = QColor('#a855f7')            # bright purple for new Looky entries
_COLOR_NEW_TAG = QColor('#22c55e')        # green accent for "NEW" tag
_COLOR_IP_HEADER = QColor('#d8b4fe')      # light purple for IP header text
_COLOR_DB_LABEL = QColor('#9ca3af')       # muted for database name


class _LookyRefreshWorker(CrashingQThread):
    """Background thread that batch-looks up IPs via the Looky System API.

    Emits ``finished_ok`` with a dict mapping each queried IP to its list of
    `LookyPlayer` results, or ``finished_error`` with an error message string.
    """

    finished_ok: pyqtSignal = pyqtSignal(object)  # dict[str, list[LookyPlayer]]
    finished_error: pyqtSignal = pyqtSignal(str)  # error message

    def __init__(self, ip_addresses: list[str], api_key: str, version: str) -> None:
        super().__init__()
        self._ip_addresses = ip_addresses
        self._api_key = api_key
        self._version = version

    @override
    def _run(self) -> None:
        """Batch-lookup all IPs and emit the combined results."""
        combined: dict[str, list[LookyPlayer]] = {}

        for batch_start in range(0, len(self._ip_addresses), _BATCH_SIZE):
            batch = self._ip_addresses[batch_start : batch_start + _BATCH_SIZE]
            try:
                results = lookup_ip_batch(batch, self._api_key, self._version)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    message = extract_rate_limit_message(e)
                    wait_seconds = extract_rate_limit_wait_seconds(e)
                    self.finished_error.emit(f'Rate limited: {message}. Try again in {wait_seconds} second{pluralize(wait_seconds)}.')
                else:
                    status_code = e.response.status_code if e.response is not None else '?'
                    self.finished_error.emit(f'Looky System API error: HTTP {status_code}')
                return
            except requests.RequestException as e:
                self.finished_error.emit(f'Looky System request failed: {e}')
                return
            except ValidationError as e:
                self.finished_error.emit(f'Looky System response format unexpected: {e}')
                return

            combined.update(results)

        self.finished_ok.emit(combined)


def _collect_existing_usernames(db_path: Path) -> dict[str, list[str]]:
    """Return a mapping of IP → list of existing usernames in file order from the given database file."""
    ip_to_usernames: dict[str, list[str]] = {}
    ip_to_seen: dict[str, set[str]] = {}
    try:
        content = db_path.read_text(encoding='utf-8')
    except OSError:
        return ip_to_usernames
    for username, ip in iter_userip_entries(content):
        seen = ip_to_seen.setdefault(ip, set())
        if username not in seen:
            ip_to_usernames.setdefault(ip, []).append(username)
            seen.add(username)
    return ip_to_usernames


def _is_single_ipv4(entry: str) -> bool:
    """Return True if `entry` is a single IPv4 address (not a range, CIDR, or wildcard)."""
    try:
        IPv4Address(entry)
    except ValueError:
        return False

    return True


# ---------------------------------------------------------------------------
# Loading dialog
# ---------------------------------------------------------------------------

class _LookyRefreshLoadingDialog(QDialog):
    """Modal dialog shown while batch-lookup is running in the background."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        set_dialog_window_flags(self)
        self.setWindowTitle(LOOKY_TITLE)
        self.setMinimumSize(320, 150)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        header = QLabel('\U0001f441  Looky \u2014 Fetching...')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)
        layout.addWidget(header)

        self._widgets = build_looky_progress_widgets(layout, self)

    def show_error(self, message: str) -> None:
        """Hide the progress bar and show the error message."""
        self._widgets.progress_bar.hide()
        self._widgets.status_label.setText(f'<span style="color: #f87171; font-weight: 600;">\u2717 Failed: {message}</span>')
        self._widgets.status_label.show()


# ---------------------------------------------------------------------------
# Data classes for the review dialog
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class _PendingEntry:
    """A single new username=IP entry that the Looky System discovered and may be written to a database."""

    db_path: Path
    ip: str
    username: str


@dataclass(slots=True)
class _IpGroup:
    """All data for one IP address: its database, existing usernames, and new Looky-discovered entries."""

    db_path: Path
    ip: str
    existing_usernames: list[str]
    new_entries: list[_PendingEntry]


# ---------------------------------------------------------------------------
# Review dialog
# ---------------------------------------------------------------------------

class LookyRefreshReviewDialog(PlayerInfoDialogMixin):
    """Modal dialog that displays a hierarchical view of existing and new usernames per IP.

    The tree structure groups by IP address. Under each IP, existing database
    usernames are shown as dimmed read-only context, followed by new Looky-resolved
    usernames with checkboxes for selective acceptance.
    """

    def __init__(self, parent: QWidget, ip_groups: list[_IpGroup]) -> None:
        super().__init__(parent)
        set_dialog_window_flags(self)

        self.setWindowTitle(f'{LOOKY_TITLE} \u2014 UserIP Refresh Review')
        self.setStyleSheet(LOOKY_REVIEW_DIALOG_STYLESHEET)
        self._apply_standard_dialog_size()
        self.resize(max(self.width(), 760), max(self.height(), 580))

        self._ip_groups = ip_groups

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(12, 12, 12, 12)
        outer_layout.setSpacing(10)

        # --- Header ---
        self._add_header_label(
            outer_layout,
            '\U0001f441  Looky \u2014 UserIP Refresh Review',
            '#1c0a38',
            '#2e1065',
        ).setStyleSheet(LOOKY_CRAWLER_HEADER_STYLESHEET)

        # --- Summary card ---
        total_new = sum(len(g.new_entries) for g in ip_groups)
        total_existing = sum(len(g.existing_usernames) for g in ip_groups)
        unique_dbs = {g.db_path for g in ip_groups}

        summary_frame = QFrame()
        summary_frame.setStyleSheet(LOOKY_REVIEW_SUMMARY_STYLESHEET)
        summary_layout = QHBoxLayout(summary_frame)
        summary_layout.setContentsMargins(10, 8, 10, 8)
        summary_layout.setSpacing(20)

        for label_text, value_text in [
            (f'IP{pluralize(len(ip_groups))} Queried', str(len(ip_groups))),
            ('Existing', str(total_existing)),
            ('New Found', str(total_new)),
            (f'Database{pluralize(len(unique_dbs))}', str(len(unique_dbs))),
        ]:
            stat_layout = QVBoxLayout()
            stat_layout.setSpacing(2)
            value_label = QLabel(value_text)
            value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            value_label.setStyleSheet('color: #d8b4fe; font-size: 18px; font-weight: 700; background: transparent;')
            stat_layout.addWidget(value_label)
            desc_label = QLabel(label_text)
            desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            desc_label.setStyleSheet('color: #9ca3af; font-size: 10px; font-weight: 600; letter-spacing: 1px; background: transparent;')
            stat_layout.addWidget(desc_label)
            summary_layout.addLayout(stat_layout)

        outer_layout.addWidget(summary_frame)

        # --- Legend + Search + Select All / Deselect All ---
        controls_bar = QHBoxLayout()
        controls_bar.setSpacing(8)

        # Legend
        legend_label = QLabel(
            '<span style="color: #6b6980;">\u25CF Existing</span>'
            '&nbsp;&nbsp;&nbsp;'
            '<span style="color: #22c55e;">\u25CF New (Looky)</span>',
        )
        legend_label.setStyleSheet('font-size: 11px; background: transparent;')
        controls_bar.addWidget(legend_label)

        controls_bar.addStretch(1)

        # Search Bar
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText('Search IP or username...')
        self._search_input.setStyleSheet(
            'QLineEdit {'
            '    background-color: #1a1325;'
            '    color: #d4c8f0;'
            '    border: 1px solid #3d2d6e;'
            '    border-radius: 6px;'
            '    padding: 4px 8px;'
            '    font-size: 12px;'
            '}'
            'QLineEdit:focus {'
            '    border: 1px solid #7c3aed;'
            '}'
        )
        self._search_input.setMinimumWidth(200)
        apply_search_icon(self._search_input)
        self._search_input.textChanged.connect(self._filter_tree)
        controls_bar.addWidget(self._search_input)

        controls_bar.addSpacing(10)

        select_all_btn = QPushButton('\u2611 Select All')
        select_all_btn.setStyleSheet(LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET)
        select_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        select_all_btn.clicked.connect(self._select_all)
        deselect_all_btn = QPushButton('\u2610 Deselect All')
        deselect_all_btn.setStyleSheet(LOOKY_REVIEW_SELECT_BUTTON_STYLESHEET)
        deselect_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        deselect_all_btn.clicked.connect(self._deselect_all)
        controls_bar.addWidget(select_all_btn)
        controls_bar.addWidget(deselect_all_btn)

        # Counter label
        self._counter_label = QLabel()
        self._counter_label.setStyleSheet('color: #9ca3af; font-size: 11px; background: transparent;')
        controls_bar.addWidget(self._counter_label)
        outer_layout.addLayout(controls_bar)

        # --- Tree widget ---
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(['Username / IP', 'Status', 'Database'])
        self._tree.setColumnCount(3)
        self._tree.setAlternatingRowColors(False)
        self._tree.setStyleSheet(LOOKY_REVIEW_TABLE_STYLESHEET)
        self._tree.setRootIsDecorated(True)
        self._tree.setSortingEnabled(False)
        self._tree.setIndentation(22)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)

        from PyQt6.QtWidgets import QHeaderView  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

        header = self._tree.header()
        if header is not None:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setMinimumSectionSize(30)

        # Build the tree: one top-level item per IP, children for existing + new
        self._new_items: list[tuple[QTreeWidgetItem, _PendingEntry]] = []
        mono_font = QFont('Consolas')
        bold_font = QFont()
        bold_font.setBold(True)

        for group in ip_groups:
            # --- IP parent node ---
            ip_item = QTreeWidgetItem()
            existing_count = len(group.existing_usernames)
            new_count = len(group.new_entries)
            ip_item.setText(0, f'\U0001f310  {group.ip}')
            ip_item.setText(1, f'{existing_count} existing \u00b7 {new_count} new')
            ip_item.setText(2, group.db_path.stem)
            ip_item.setToolTip(2, str(group.db_path))
            ip_item.setForeground(0, QBrush(_COLOR_IP_HEADER))
            ip_item.setForeground(1, QBrush(_COLOR_DB_LABEL))
            ip_item.setForeground(2, QBrush(_COLOR_DB_LABEL))
            ip_item.setFont(0, bold_font)
            ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self._tree.addTopLevelItem(ip_item)

            # --- Existing username children (read-only, dimmed) ---
            for existing_name in sorted(group.existing_usernames):
                child = QTreeWidgetItem(ip_item)
                child.setText(0, f'     {existing_name}')
                child.setText(1, 'existing')
                child.setFont(0, mono_font)
                child.setForeground(0, QBrush(_COLOR_EXISTING))
                child.setForeground(1, QBrush(_COLOR_EXISTING_TAG))
                child.setFlags(child.flags() & ~Qt.ItemFlag.ItemIsUserCheckable & ~Qt.ItemFlag.ItemIsSelectable)

            # --- New Looky username children (checkable) ---
            for entry in group.new_entries:
                child = QTreeWidgetItem(ip_item)
                child.setText(0, f'     {entry.username}')
                child.setText(1, '\u2728 NEW')
                child.setFont(0, mono_font)
                child.setForeground(0, QBrush(_COLOR_NEW))
                child.setForeground(1, QBrush(_COLOR_NEW_TAG))
                child.setFont(1, bold_font)
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                child.setCheckState(0, Qt.CheckState.Checked)
                self._new_items.append((child, entry))

            ip_item.setExpanded(True)

        self._tree.itemChanged.connect(self._update_counter)
        outer_layout.addWidget(self._tree, stretch=1)

        # --- Buttons ---
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        cancel_btn = QPushButton('Cancel')
        cancel_btn.setStyleSheet(LOOKY_ACTION_BUTTON_STYLESHEET)
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)

        self._accept_btn = QPushButton('\u2713 Accept Selected')
        self._accept_btn.setStyleSheet(LOOKY_PRIMARY_ACTION_BUTTON_STYLESHEET)
        self._accept_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._accept_btn.clicked.connect(self.accept)

        button_layout.addStretch(1)
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(self._accept_btn)
        outer_layout.addLayout(button_layout)

        self._update_counter()

    # --- Selection helpers ---

    def _select_all(self) -> None:
        """Check all new-entry items."""
        for item, _entry in self._new_items:
            item.setCheckState(0, Qt.CheckState.Checked)

    def _deselect_all(self) -> None:
        """Uncheck all new-entry items."""
        for item, _entry in self._new_items:
            item.setCheckState(0, Qt.CheckState.Unchecked)

    def _update_counter(self) -> None:
        """Refresh the counter label and accept button state based on how many new entries are checked."""
        checked = sum(1 for item, _entry in self._new_items if item.checkState(0) == Qt.CheckState.Checked)
        total = len(self._new_items)
        self._counter_label.setText(f'{checked} / {total} selected')
        self._accept_btn.setEnabled(checked > 0)

    def _filter_tree(self, text: str) -> None:
        """Filter the tree. If any item matches the search text, the entire IP group is shown."""
        query = text.strip().lower()

        for i in range(self._tree.topLevelItemCount()):
            parent_item = self._tree.topLevelItem(i)
            if parent_item is None:
                continue

            parent_text_ip = parent_item.text(0).lower()
            parent_text_db = parent_item.text(2).lower()

            # Check if parent matches
            matches = query in parent_text_ip or query in parent_text_db

            # If parent doesn't match, check if any child matches
            if not matches:
                for j in range(parent_item.childCount()):
                    child = parent_item.child(j)
                    if child is not None and query in child.text(0).lower():
                        matches = True
                        break

            # Show or hide the entire group based on whether it matched anything
            parent_item.setHidden(not matches)

            # Ensure all children remain visible so the full context is shown
            for j in range(parent_item.childCount()):
                child = parent_item.child(j)
                if child is not None:
                    child.setHidden(False)

            if query and matches:
                parent_item.setExpanded(True)

    def get_accepted_entries(self) -> list[_PendingEntry]:
        """Return the list of new entries the user checked."""
        return [entry for item, entry in self._new_items if item.checkState(0) == Qt.CheckState.Checked]

    def _show_context_menu(self, pos: QPoint) -> None:
        """Show a right-click context menu to copy IP and username."""
        item = self._tree.itemAt(pos)
        if item is None:
            return

        menu = QMenu(self)

        parent = item.parent()
        if parent is None:
            # IP node
            ip_str = item.text(0).replace('\U0001f310  ', '').strip()
            menu.addAction('Copy IP Address', lambda: self._copy_to_clipboard(ip_str))
        else:
            # Username node
            username_str = item.text(0).strip()
            ip_str = parent.text(0).replace('\U0001f310  ', '').strip()
            menu.addAction('Copy Username', lambda: self._copy_to_clipboard(username_str))
            menu.addAction('Copy IP Address', lambda: self._copy_to_clipboard(ip_str))

        viewport = self._tree.viewport()
        if viewport is not None:
            menu.exec(viewport.mapToGlobal(pos))

    @staticmethod
    def _copy_to_clipboard(text: str) -> None:
        """Copy the given text to the system clipboard."""
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(text)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def looky_refresh_userip_entries(
    parent: QWidget,
    entries: list[tuple[Path, list[str]]],
) -> None:
    """Look up IPs from UserIP databases via the Looky System and append any new usernames.

    Args:
        parent: Parent widget for dialogs and message boxes.
        entries: List of ``(db_path, ip_addresses)`` tuples. Each ``ip_addresses`` list
                 contains the single-IP entries from that database to look up.
                 Range entries should be pre-filtered out by the caller.
    """
    api_key = check_looky_prerequisites(parent)
    if api_key is None:
        return

    # Collect all unique single IPs to look up
    all_ips: list[str] = []
    seen_ips: set[str] = set()
    for _db_path, ip_addresses in entries:
        for ip in ip_addresses:
            if _is_single_ipv4(ip) and ip not in seen_ips:
                all_ips.append(ip)
                seen_ips.add(ip)

    if not all_ips:
        QMessageBox.information(parent, LOOKY_TITLE, 'No single IP addresses found to look up.')
        return

    from session_sniffer.settings.settings import Settings  # noqa: PLC0415  # pylint: disable=import-outside-toplevel  # deferred to avoid circular imports

    worker = _LookyRefreshWorker(all_ips, api_key, Settings.looky_game_version.lower())

    loading_dialog = _LookyRefreshLoadingDialog(parent)

    def _on_finished_ok(results: dict[str, list[LookyPlayer]]) -> None:
        loading_dialog.accept()

        # Build IP groups with both existing and new data
        ip_groups: list[_IpGroup] = []
        total_new = 0

        for db_path, ip_addresses in entries:
            existing_map = _collect_existing_usernames(db_path)
            seen_ips_for_db: set[str] = set()

            for ip in ip_addresses:
                if not _is_single_ipv4(ip) or ip in seen_ips_for_db:
                    continue
                seen_ips_for_db.add(ip)

                players = results.get(ip, [])
                existing_names_list = existing_map.get(ip, [])
                existing_names_set = set(existing_names_list)

                # Collect new entries (not in existing)
                new_entries: list[_PendingEntry] = []
                seen_new: set[str] = set()
                for player_entry in players:
                    if player_entry.name not in existing_names_set and player_entry.name not in seen_new:
                        new_entries.append(_PendingEntry(db_path, player_entry.name, ip))
                        seen_new.add(player_entry.name)

                # Only create a group if there are new entries to show
                if new_entries:
                    ip_groups.append(_IpGroup(
                        db_path=db_path,
                        ip=ip,
                        existing_usernames=existing_names_list,
                        new_entries=new_entries,
                    ))
                    total_new += len(new_entries)

        if not total_new:
            QMessageBox.information(parent, TITLE, 'No new usernames found to add.\n\nAll resolved usernames already exist in the database(s).')
            return

        # Show the review dialog for user consent
        dialog = LookyRefreshReviewDialog(parent, ip_groups)
        if dialog.exec() != LookyRefreshReviewDialog.DialogCode.Accepted:
            return

        accepted = dialog.get_accepted_entries()
        if not accepted:
            return

        # Group accepted entries by database path and write
        from collections import defaultdict  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

        by_db: dict[Path, list[_PendingEntry]] = defaultdict(list)
        for entry in accepted:
            by_db[entry.db_path].append(entry)

        total_added = 0
        for db_path, db_entries in by_db.items():
            new_lines = [f'{e.username}={e.ip}\n' for e in db_entries]
            write_lines_to_file(db_path, 'a', new_lines)
            total_added += len(new_lines)

        db_count = len(by_db)
        db_word = 'database' if db_count == 1 else 'databases'
        QMessageBox.information(
            parent,
            TITLE,
            f'Added {total_added} new username{pluralize(total_added)} across {db_count} {db_word}.',
        )

    def _on_finished_error(message: str) -> None:
        loading_dialog.show_error(message)

    worker.finished_ok.connect(_on_finished_ok)
    worker.finished_error.connect(_on_finished_error)

    # If the user closes the loading dialog, disconnect so we don't pop the review dialog later
    def _on_rejected() -> None:
        try:
            worker.finished_ok.disconnect(_on_finished_ok)
            worker.finished_error.disconnect(_on_finished_error)
        except TypeError:
            pass

    loading_dialog.rejected.connect(_on_rejected)

    worker.setParent(parent)
    worker.start()
    loading_dialog.exec()
