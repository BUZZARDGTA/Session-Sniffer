"""Shared helpers, constants, and dialogs for the UserIP Databases Manager."""

import contextlib
import functools
import ipaddress
import json
import logging
from datetime import datetime
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QAbstractItemModel, QModelIndex, QObject, QPersistentModelIndex, QRegularExpression, QSignalBlocker, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor, QIcon, QRegularExpressionValidator, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QButtonGroup, QDialog, QDialogButtonBox, QGridLayout, QGroupBox, QLabel, QLineEdit, QMenu, QRadioButton, QSlider, QVBoxLayout, QWidget

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import (
    IP_RANGE_PREVIEW_EMPTY_STYLESHEET,
    IP_RANGE_PREVIEW_ERROR_STYLESHEET,
    IP_RANGE_PREVIEW_VALID_STYLESHEET,
    SUBNET_DESC_LABEL_STYLESHEET,
)
from session_sniffer.guis.utils import scale_by_ui
from session_sniffer.models.userip_settings_model import (
    DEFAULT_USERIP_FILES_SETTINGS,
    USERIP_SOURCE_TOOLTIPS,
    UserIPDatabaseFile,
    UserIPEntryModel,
    UserIPSettingsModel,
    format_iso_timestamp_display,
    get_current_iso_timestamp,
)
from session_sniffer.networking.ip_range import entry_ip_covers_ip
from session_sniffer.player.userip import UserIPDatabases
from session_sniffer.player.userip_groups import compute_row_group_ids_and_prefixes
from session_sniffer.player.userip_loader import (
    enrich_userip_entry_from_logs,
    find_userip_insert_index,
    get_cached_userip_database_entries,
    get_cached_userip_databases,
    update_userip_databases,
    userip_database_write,
)
from session_sniffer.rendering_core.events import wake_rendering_core
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
    from pathlib import Path
    from typing import Any

logger = logging.getLogger(__name__)

INDEX_COLUMN = 0
USERNAME_COLUMN = 1
IP_COLUMN = 2
RANGE_COLUMN = 3
DATABASE_COLUMN = 4
NOTES_COLUMN = 5
SOURCE_COLUMN = 6
DETECTIONS_COLUMN = 7
ADDED_AT_COLUMN = 8
UPDATED_AT_COLUMN = 9
FIRST_SEEN_AT_COLUMN = 10
LAST_SEEN_AT_COLUMN = 11

TIMESTAMP_COLUMNS = (ADDED_AT_COLUMN, UPDATED_AT_COLUMN, FIRST_SEEN_AT_COLUMN, LAST_SEEN_AT_COLUMN)
FILTERABLE_COLUMNS = (USERNAME_COLUMN, IP_COLUMN, RANGE_COLUMN, DATABASE_COLUMN, NOTES_COLUMN, SOURCE_COLUMN, *TIMESTAMP_COLUMNS)
ENTRY_TABLE_HEADERS = ['#', 'Username', 'IP', 'Range', 'Database', 'Notes', 'Source', 'Detections', 'Added', 'Updated', 'First Seen', 'Last Seen']

USERIP_METADATA_HEADER_TOOLTIPS: dict[str, str] = {
    'Source': 'How this entry was added to the database:\n' + '\n'.join(f'• {src}: {desc}' for src, desc in USERIP_SOURCE_TOOLTIPS.items()),
    'Detections': 'The number of times this entry has been matched across sessions.',
    'Added': 'The date and time when this entry was first added to the database.',
    'Updated': 'The date and time when this entry was last modified.',
    'First Seen': 'The very first time a player matching this entry was observed in a session.',
    'Last Seen': 'The most recent time a player matching this entry was active in a session.',
}

IS_PERSISTED_ROLE = Qt.ItemDataRole.UserRole + 1
SEARCH_TEXT_ROLE = Qt.ItemDataRole.UserRole + 2
SORT_KEY_ROLE = Qt.ItemDataRole.UserRole + 3

DUPLICATE_HIGHLIGHT_BRUSH = QBrush(QColor(255, 165, 0, 60))
_GROUP_BG_BRUSH_EVEN = QBrush(QColor('#1e1e1e'))
_GROUP_BG_BRUSH_ODD = QBrush(QColor('#252526'))
_LOOKY_FOREGROUND_BRUSH = QBrush(QColor('#a855f7'))
_READONLY_ITEM_FLAGS = Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsDragEnabled | Qt.ItemFlag.ItemIsDropEnabled

_IPV4_BROADCAST_FREE_PREFIX = 31
_IPV4_VERSION = 4
_EPOCH_SORT_OFFSET_MS = 10_000_000_000_000

NEW_DATABASE_SETTINGS = UserIPSettingsModel(
    ENABLED=True,
    COLOR='',
    LOG=True,
    NOTIFICATIONS=True,
    VOICE_NOTIFICATIONS=False,
    PROTECTION=False,
    PROTECTION_SUSPEND_PROCESS_MODE='Auto',
)


@functools.lru_cache(maxsize=16384)
def _ip_sort_str(value: str) -> str:
    """Return a fixed-order sortable string for an IP/range value so C++ string sort matches numeric IP order."""
    if not value:
        return ''
    lead = value.split('/', 1)[0].split('-', 1)[0].strip()
    try:
        return '0' + ipaddress.ip_address(lead).packed.hex()
    except ValueError:
        return '1' + value


@functools.lru_cache(maxsize=16384)
def _timestamp_sort_str(value: object) -> str:
    """Return a fixed-width sortable string for an ISO-8601 timestamp, sorting empty values first."""
    if isinstance(value, str) and value:
        with contextlib.suppress(ValueError):
            epoch_ms = int(datetime.fromisoformat(value).timestamp() * 1000) + _EPOCH_SORT_OFFSET_MS
            return f'1{max(0, epoch_ms):016d}'
    return ''


def _compute_cell_sort_key(model: QStandardItemModel, row: int, col: int, row_ip_key: str) -> str:
    """Compute the composite C++ sort key string for `(row, col)`."""
    item = model.item(row, col)
    if not item:
        return f'\x00{row_ip_key}'
    if col in (INDEX_COLUMN, DETECTIONS_COLUMN):
        raw_val = item.data(Qt.ItemDataRole.UserRole)
        num_val = raw_val if isinstance(raw_val, int) else 0
        return f'{max(0, num_val):010d}\x00{row_ip_key}'
    if col in (IP_COLUMN, RANGE_COLUMN):
        return f'{_ip_sort_str(item.text())}\x00{row_ip_key}'
    if col in TIMESTAMP_COLUMNS:
        return f'{_timestamp_sort_str(item.data(Qt.ItemDataRole.UserRole))}\x00{row_ip_key}'
    return f'{item.text()}\x00{row_ip_key}'


def _compute_row_search_blob(model: QStandardItemModel, row: int) -> None:
    """Compute and cache the lowercased searchable text blob for *row* in *model*."""
    blob = '\x1f'.join(text.lower() for col in FILTERABLE_COLUMNS if (item := model.item(row, col)) and (text := item.text()))
    if idx_item := model.item(row, INDEX_COLUMN):
        with QSignalBlocker(model):
            idx_item.setData(blob, SEARCH_TEXT_ROLE)


class EntriesSortProxy(QSortFilterProxyModel):
    """Proxy that delegates filtering, group sorting, and group background shading via `SEARCH_TEXT_ROLE` and `SORT_KEY_ROLE`."""

    def __init__(self, parent: QObject | None = None) -> None:
        """Initialize the proxy with C++ filter and sort roles."""
        super().__init__(parent)
        self._populated_sort_cols: set[int] = set()
        self._group_sort_enabled: bool = True
        self._last_group_descending: bool = False
        self._row_group_id: list[str] = []
        self._row_group_sort_prefix: list[str] = []
        self._proxy_row_alt_shade: list[bool] = []
        self.setFilterRole(SEARCH_TEXT_ROLE)
        self.setFilterKeyColumn(INDEX_COLUMN)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setSortRole(SORT_KEY_ROLE)
        self.layoutChanged.connect(self._rebuild_proxy_group_shades)
        self.modelReset.connect(self._rebuild_proxy_group_shades)
        self.rowsInserted.connect(self._rebuild_proxy_group_shades)
        self.rowsRemoved.connect(self._rebuild_proxy_group_shades)

    @property
    def group_sort_enabled(self) -> bool:
        """Return whether sorting groups linked accounts into consecutive blocks."""
        return self._group_sort_enabled

    def set_group_sort_enabled(self, *, enabled: bool, invalidate: bool = True) -> None:
        """Enable or disable contiguous account-group sorting and recompute sort keys."""
        if self._group_sort_enabled == enabled:
            return
        self._group_sort_enabled = enabled
        self._populated_sort_cols.clear()
        self._row_group_id.clear()
        self._row_group_sort_prefix.clear()
        if invalidate:
            self.prepare_sort_and_invalidate()

    @override
    def setFilterKeyColumn(self, column: int) -> None:
        super().setFilterKeyColumn(INDEX_COLUMN if column < 0 else column)

    @override
    def setSourceModel(self, source_model: QAbstractItemModel) -> None:
        old_model = self.sourceModel()
        if old_model:
            with contextlib.suppress(RuntimeError, TypeError):
                old_model.dataChanged.disconnect(self._on_source_data_changed)
                old_model.rowsInserted.disconnect(self._on_source_rows_changed)
                old_model.rowsRemoved.disconnect(self._on_source_rows_changed)
                old_model.modelReset.disconnect(self._on_source_model_reset)
        super().setSourceModel(source_model)
        self._populated_sort_cols.clear()
        self._row_group_id.clear()
        self._row_group_sort_prefix.clear()
        self._proxy_row_alt_shade.clear()
        if source_model:
            source_model.dataChanged.connect(self._on_source_data_changed)
            source_model.rowsInserted.connect(self._on_source_rows_changed)
            source_model.rowsRemoved.connect(self._on_source_rows_changed)
            source_model.modelReset.connect(self._on_source_model_reset)

    def _on_source_rows_changed(self, _parent: QModelIndex, _first: int, _last: int) -> None:
        self._populated_sort_cols.clear()
        self._row_group_id.clear()
        self._row_group_sort_prefix.clear()

    def _on_source_model_reset(self) -> None:
        self._populated_sort_cols.clear()
        self._row_group_id.clear()
        self._row_group_sort_prefix.clear()

    def _compute_row_groups(self, model: QStandardItemModel) -> None:
        """Build connected-component group IDs and sort prefixes for every source row in *model*."""
        row_count = model.rowCount()
        if row_count <= 0:
            self._row_group_id = []
            self._row_group_sort_prefix = []
            return
        row_usernames_cf: list[str] = []
        row_ips: list[str] = []
        row_indices: list[int] = []
        for row in range(row_count):
            u_item, ip_item, range_item, idx_item = model.item(row, USERNAME_COLUMN), model.item(row, IP_COLUMN), model.item(row, RANGE_COLUMN), model.item(row, INDEX_COLUMN)
            row_usernames_cf.append(u_item.text().strip().casefold() if u_item else '')
            row_ips.append((ip_item.text().strip() if ip_item else '') or (range_item.text().strip() if range_item else ''))
            raw_idx = idx_item.data(Qt.ItemDataRole.UserRole) if idx_item else None
            row_indices.append(raw_idx if isinstance(raw_idx, int) and raw_idx > 0 else (row + 1))
        self._row_group_id, self._row_group_sort_prefix = compute_row_group_ids_and_prefixes(
            row_usernames_cf, row_ips, row_indices, UserIPDatabases.get_known_alts_clusters_snapshot(), descending=self._last_group_descending,
        )

    def _rebuild_proxy_group_shades(self, *_args: object) -> None:
        """Recompute the alternating background shade boolean for every visible proxy row."""
        model = self.sourceModel()
        if not isinstance(model, QStandardItemModel) or (proxy_rows := self.rowCount()) <= 0:
            self._proxy_row_alt_shade = []
            return
        if len(self._row_group_id) != model.rowCount():
            self._compute_row_groups(model)
        shades: list[bool] = []
        curr_shade = False
        prev_gid: str | None = None
        row_gids, total_source = self._row_group_id, len(self._row_group_id)
        for p_row in range(proxy_rows):
            s_row = self.mapToSource(self.index(p_row, 0)).row()
            gid = row_gids[s_row] if 0 <= s_row < total_source else f'p:{p_row}'
            if prev_gid is not None and gid != prev_gid:
                curr_shade = not curr_shade
            shades.append(curr_shade)
            prev_gid = gid
        self._proxy_row_alt_shade = shades

    @override
    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.BackgroundRole and index.isValid():
            base_bg: object = super().data(index, role)
            if base_bg is not None:
                return base_bg
            p_row = index.row()
            if p_row < 0 or p_row >= len(self._proxy_row_alt_shade):
                self._rebuild_proxy_group_shades()
            if 0 <= p_row < len(self._proxy_row_alt_shade):
                return _GROUP_BG_BRUSH_ODD if self._proxy_row_alt_shade[p_row] else _GROUP_BG_BRUSH_EVEN
            return _GROUP_BG_BRUSH_EVEN
        return super().data(index, role)

    def _format_cell_sort_key(self, model: QStandardItemModel, row: int, column: int, row_ip_key: str) -> str:
        base_key = _compute_cell_sort_key(model, row, column, row_ip_key)
        if self._group_sort_enabled and column in (INDEX_COLUMN, USERNAME_COLUMN) and 0 <= row < len(self._row_group_sort_prefix):
            prefix = self._row_group_sort_prefix[row] if column == INDEX_COLUMN else self._row_group_id[row]
            return f'{prefix}\x00{base_key}'
        return base_key

    def _ensure_column_sort_keys(self, column: int) -> None:
        if column < 0 or column in self._populated_sort_cols:
            return
        model = self.sourceModel()
        if not isinstance(model, QStandardItemModel):
            return
        row_count = model.rowCount()
        if row_count > 0:
            if len(self._row_group_id) != row_count:
                self._compute_row_groups(model)
            with QSignalBlocker(model):
                for row in range(row_count):
                    ip_item = model.item(row, IP_COLUMN)
                    range_item = model.item(row, RANGE_COLUMN)
                    row_ip = (ip_item.text() if ip_item else '') or (range_item.text() if range_item else '')
                    row_ip_key = _ip_sort_str(row_ip)
                    if target_item := model.item(row, column):
                        target_item.setData(self._format_cell_sort_key(model, row, column, row_ip_key), SORT_KEY_ROLE)
        self._populated_sort_cols.add(column)

    def refresh_rows(self, rows: Iterable[int]) -> None:
        """Recompute cached search blobs, group memberships, and sort keys after model edits."""
        model = self.sourceModel()
        if not isinstance(model, QStandardItemModel) or not (row_list := list(rows)):
            return
        self._compute_row_groups(model)
        cols_to_update: set[int] = set(self._populated_sort_cols)
        if (sort_col := self.sortColumn()) >= 0:
            cols_to_update.add(sort_col)
        row_count = model.rowCount()
        target_rows = range(row_count) if self._group_sort_enabled else row_list
        with QSignalBlocker(model):
            for row in row_list:
                _compute_row_search_blob(model, row)
            for row in target_rows:
                ip_item, range_item = model.item(row, IP_COLUMN), model.item(row, RANGE_COLUMN)
                row_ip_key = _ip_sort_str((ip_item.text() if ip_item else '') or (range_item.text() if range_item else ''))
                for col in cols_to_update:
                    if target_item := model.item(row, col):
                        target_item.setData(self._format_cell_sort_key(model, row, col, row_ip_key), SORT_KEY_ROLE)
        self._rebuild_proxy_group_shades()
        min_r = 0 if self._group_sort_enabled else min(row_list)
        max_r = max(0, row_count - 1) if self._group_sort_enabled else max(row_list)
        model.dataChanged.emit(model.index(min_r, 0), model.index(max_r, max(0, model.columnCount() - 1)), [SEARCH_TEXT_ROLE, SORT_KEY_ROLE])

    def refresh_groups(self) -> None:
        """Force a full recomputation of row groups, sort keys, and alternating group background shades."""
        self._populated_sort_cols.clear()
        self._row_group_id.clear()
        self._row_group_sort_prefix.clear()
        self.prepare_sort_and_invalidate()
        self._rebuild_proxy_group_shades()

    def _on_source_data_changed(self, top_left: QModelIndex, bottom_right: QModelIndex, roles: list[int]) -> None:
        if roles and Qt.ItemDataRole.DisplayRole not in roles and Qt.ItemDataRole.EditRole not in roles and Qt.ItemDataRole.UserRole not in roles:
            return
        self.refresh_rows(range(top_left.row(), bottom_right.row() + 1))

    @override
    def setFilterFixedString(self, pattern: str) -> None:
        super().setFilterFixedString(pattern.lower())
        self._rebuild_proxy_group_shades()

    @override
    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        is_desc = order == Qt.SortOrder.DescendingOrder
        if is_desc != self._last_group_descending:
            self._last_group_descending = is_desc
            self._row_group_id.clear()
            self._row_group_sort_prefix.clear()
            if self._group_sort_enabled:
                self._populated_sort_cols.clear()
        keys_repopulated = column >= 0 and column not in self._populated_sort_cols
        self._ensure_column_sort_keys(column)
        if keys_repopulated and column == self.sortColumn() and order == self.sortOrder():
            self.invalidate()
        else:
            super().sort(column, order)
        self._rebuild_proxy_group_shades()

    def prepare_sort_and_invalidate(self) -> None:
        """Ensure sort keys are populated for the active sort column, then invalidate the proxy."""
        self._ensure_column_sort_keys(self.sortColumn())
        self.invalidate()
        self._rebuild_proxy_group_shades()


def _make_readonly_item(text: str, user_data: object = None, *, tooltip: str = '') -> QStandardItem:
    """Create a read-only `QStandardItem` with optional `UserRole` data and tooltip."""
    item = QStandardItem(text)
    item.setFlags(_READONLY_ITEM_FLAGS)
    if user_data is not None:
        item.setData(user_data, Qt.ItemDataRole.UserRole)
    if tooltip:
        item.setToolTip(tooltip)
    return item


def _make_timestamp_item(iso_value: str | None) -> QStandardItem:
    """Create a read-only timestamp `QStandardItem` storing the raw ISO string in `UserRole`."""
    display_text = format_iso_timestamp_display(iso_value)
    return _make_readonly_item(display_text, iso_value, tooltip=iso_value or '')


def build_entry_row_items(
    entry: UserIPEntryModel,
    *,
    index: int = 0,
    database: tuple[str, Path] | None = None,
    looky_icon: QIcon | None = None,
    persisted: bool = True,
) -> list[QStandardItem]:
    """Construct the 12 `QStandardItem` instances for a single `UserIPEntryModel` row."""
    if not persisted and entry.ip:
        entry, _ = enrich_userip_entry_from_logs(entry)
    index_item = _make_readonly_item(str(index) if index > 0 else '', index)
    if not persisted:
        index_item.setData(0, IS_PERSISTED_ROLE)
    index_item.setData(f'{max(0, index):010d}\x00{_ip_sort_str(entry.ip)}', SORT_KEY_ROLE)

    username_item = QStandardItem(entry.username)
    if entry.is_looky:
        if looky_icon is not None:
            username_item.setIcon(looky_icon)
        username_item.setForeground(_LOOKY_FOREGROUND_BRUSH)
        username_item.setToolTip('Added automatically by Looky System')
        username_item.setData(entry.is_looky, Qt.ItemDataRole.UserRole)

    is_single_ip = bool(entry.ip and '/' not in entry.ip and '-' not in entry.ip)
    if not persisted and is_single_ip:
        try:
            IPv4Address(entry.ip)
        except ValueError:
            is_single_ip = False

    ip_item, range_item = QStandardItem(entry.ip if is_single_ip else ''), QStandardItem('' if is_single_ip else entry.ip)
    db_name = database[0] if database else ''
    db_item = _make_readonly_item(db_name, str(database[1]) if database is not None else None)
    notes_item = QStandardItem(entry.notes)
    source_item = _make_readonly_item(entry.source, entry.source, tooltip=USERIP_SOURCE_TOOLTIPS.get(entry.source, ''))
    detections_item = _make_readonly_item(str(entry.detections_count), entry.detections_count)
    added_item, updated_item = _make_timestamp_item(entry.added_at), _make_timestamp_item(entry.updated_at)
    first_seen_item, last_seen_item = _make_timestamp_item(entry.first_seen_at), _make_timestamp_item(entry.last_seen_at)
    search_vals = (entry.username, entry.ip, db_name, entry.notes, entry.source, added_item.text(), updated_item.text(), first_seen_item.text(), last_seen_item.text())
    index_item.setData('\x1f'.join(val.lower() for val in search_vals if val), SEARCH_TEXT_ROLE)
    return [index_item, username_item, ip_item, range_item, db_item, notes_item, source_item, detections_item, added_item, updated_item, first_seen_item, last_seen_item]


def append_entry_rows(model: QStandardItemModel, rows: list[list[QStandardItem]]) -> None:
    """Insert prepared entry rows in one model operation, then populate their cells."""
    if not rows:
        return
    first_row = model.rowCount()
    model.insertRows(first_row, len(rows))
    with QSignalBlocker(model):
        for row_index, row_items in enumerate(rows, start=first_row):
            for column, item in enumerate(row_items):
                model.setItem(row_index, column, item)


def is_row_persisted(model: QStandardItemModel, row: int) -> bool:
    """Return `True` if the row was loaded from or previously saved to disk."""
    return model.item(row, INDEX_COLUMN).data(IS_PERSISTED_ROLE) not in (0, False)


def mark_row_persisted(model: QStandardItemModel, row: int) -> None:
    """Mark a row in *model* as persisted on disk."""
    model.item(row, INDEX_COLUMN).setData(1, IS_PERSISTED_ROLE)


def set_row_updated_at(model: QStandardItemModel, row: int, updated_iso: str | None = None) -> None:
    """Update the `Updated` column item of *row* with *updated_iso* (defaults to current local ISO timestamp)."""
    iso_val = updated_iso if updated_iso is not None else get_current_iso_timestamp()
    updated_item = model.item(row, UPDATED_AT_COLUMN)
    updated_item.setText(format_iso_timestamp_display(iso_val))
    updated_item.setData(iso_val, Qt.ItemDataRole.UserRole)
    updated_item.setToolTip(iso_val)


def clear_row_looky_badge(model: QStandardItemModel, row: int) -> None:
    """Clear the Looky badge and reset `Looky` source to `Manual` on *row* when manually edited or renamed."""
    username_item = model.item(row, USERNAME_COLUMN)
    if username_item.data(Qt.ItemDataRole.UserRole):
        username_item.setData(None, Qt.ItemDataRole.UserRole)
        username_item.setIcon(QIcon())
        username_item.setForeground(QBrush())
        username_item.setToolTip('')
        source_item = model.item(row, SOURCE_COLUMN)
        if source_item.data(Qt.ItemDataRole.UserRole) == 'Looky':
            source_item.setText('Manual')
            source_item.setData('Manual', Qt.ItemDataRole.UserRole)
            source_item.setToolTip(USERIP_SOURCE_TOOLTIPS['Manual'])


def extract_entry_model_from_row(model: QStandardItemModel, row: int) -> tuple[str, str, str, UserIPEntryModel | None]:
    """Read all columns of *row* in *model* and build a `UserIPEntryModel` when username and IP are present."""
    username_item = model.item(row, USERNAME_COLUMN)
    username = username_item.text().strip()
    ip_text = model.item(row, IP_COLUMN).text().strip() or model.item(row, RANGE_COLUMN).text().strip()
    notes = model.item(row, NOTES_COLUMN).text().strip()
    if not username or not ip_text:
        return username, ip_text, notes, None

    raw_meta: dict[str, Any] = {
        'source': model.item(row, SOURCE_COLUMN).data(Qt.ItemDataRole.UserRole),
        'detections_count': model.item(row, DETECTIONS_COLUMN).data(Qt.ItemDataRole.UserRole),
        'added_at': model.item(row, ADDED_AT_COLUMN).data(Qt.ItemDataRole.UserRole),
        'updated_at': model.item(row, UPDATED_AT_COLUMN).data(Qt.ItemDataRole.UserRole),
        'first_seen_at': model.item(row, FIRST_SEEN_AT_COLUMN).data(Qt.ItemDataRole.UserRole),
        'last_seen_at': model.item(row, LAST_SEEN_AT_COLUMN).data(Qt.ItemDataRole.UserRole),
    }
    entry_model, _ = UserIPEntryModel.from_raw_entry_dict(raw_meta, username=username, ip=ip_text, is_looky=bool(username_item.data(Qt.ItemDataRole.UserRole)), notes=notes)
    entry_model, was_enriched = enrich_userip_entry_from_logs(entry_model)
    if was_enriched:
        row_ip_key = _ip_sort_str(ip_text)
        with QSignalBlocker(model):
            det_item = model.item(row, DETECTIONS_COLUMN)
            det_item.setText(str(entry_model.detections_count))
            det_item.setData(entry_model.detections_count, Qt.ItemDataRole.UserRole)
            det_item.setData(_compute_cell_sort_key(model, row, DETECTIONS_COLUMN, row_ip_key), SORT_KEY_ROLE)
            for col, iso_val in ((ADDED_AT_COLUMN, entry_model.added_at), (FIRST_SEEN_AT_COLUMN, entry_model.first_seen_at), (LAST_SEEN_AT_COLUMN, entry_model.last_seen_at)):
                ts_item = model.item(row, col)
                ts_item.setText(format_iso_timestamp_display(iso_val))
                ts_item.setData(iso_val, Qt.ItemDataRole.UserRole)
                ts_item.setToolTip(iso_val or '')
                ts_item.setData(_compute_cell_sort_key(model, row, col, row_ip_key), SORT_KEY_ROLE)
            _compute_row_search_blob(model, row)
        model.dataChanged.emit(model.index(row, 0), model.index(row, max(0, model.columnCount() - 1)), [SEARCH_TEXT_ROLE, SORT_KEY_ROLE])
    return username, ip_text, notes, entry_model


BYTES_PER_UNIT = 1024


def human_readable_size(size_bytes: int) -> str:
    """Format a byte count into a human-readable string."""
    value = float(size_bytes)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < BYTES_PER_UNIT:
            return f'{value:.1f} {unit}' if unit != 'B' else f'{int(value)} {unit}'
        value /= BYTES_PER_UNIT
    return f'{value:.1f} TB'


def parse_userip_database_content(
    content: str, *, default_settings: UserIPSettingsModel | None = None, cached_entries: list[UserIPEntryModel] | None = None,
) -> UserIPDatabaseFile:
    """Parse raw JSON *content* into a validated `UserIPDatabaseFile` model."""
    fallback = (default_settings or NEW_DATABASE_SETTINGS).model_copy()
    if not content.strip():
        return UserIPDatabaseFile(settings=fallback, entries=[])
    try:
        raw_data: object = json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning('Failed to parse UserIP database JSON content: %s', e)
        return UserIPDatabaseFile(settings=fallback, entries=[])
    if not isinstance(raw_data, dict):
        return UserIPDatabaseFile(settings=fallback, entries=[])
    typed_data = cast('dict[str, Any]', raw_data)
    raw_settings_obj: object = typed_data.get('settings')
    settings = UserIPSettingsModel.validate_settings(cast('dict[str, Any]', raw_settings_obj))[0] if isinstance(raw_settings_obj, dict) else fallback
    if cached_entries is not None:
        return UserIPDatabaseFile(settings=settings, entries=cached_entries)
    raw_entries_obj: object = typed_data.get('entries')
    raw_entries = cast('list[object]', raw_entries_obj) if isinstance(raw_entries_obj, list) else []
    entries = [enrich_userip_entry_from_logs(parsed[0])[0] for raw_entry in raw_entries if (parsed := UserIPEntryModel.parse_raw_entry(raw_entry)) is not None]
    return UserIPDatabaseFile(settings=settings, entries=entries)


def load_userip_database_model(path: Path) -> UserIPDatabaseFile:
    """Read and parse a UserIP `.json` database file into a `UserIPDatabaseFile` model."""
    default_settings = DEFAULT_USERIP_FILES_SETTINGS.get(path.name) if path.parent == USERIP_DATABASES_DIR_PATH else None
    if not path.is_file():
        return UserIPDatabaseFile(settings=(default_settings or NEW_DATABASE_SETTINGS).model_copy(), entries=[])
    try:
        content = path.read_text(encoding='utf-8')
    except OSError as e:
        logger.warning('Failed to read UserIP database "%s": %s', path, e)
        return UserIPDatabaseFile(settings=(default_settings or NEW_DATABASE_SETTINGS).model_copy(), entries=[])
    return parse_userip_database_content(content, default_settings=default_settings, cached_entries=get_cached_userip_database_entries(path))


def save_userip_database_model(path: Path, db_model: UserIPDatabaseFile) -> None:
    """Serialize and write a `UserIPDatabaseFile` model to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with userip_database_write(path):
        path.write_text(db_model.serialize_to_json(), encoding='utf-8')


def refresh_userip_and_wake_renderer() -> None:
    """Rebuild UserIP lookup structures immediately and wake the rendering loop."""
    update_userip_databases()
    wake_rendering_core()


def iter_userip_databases() -> Iterator[tuple[Path, list[UserIPEntryModel]]]:
    """Yield `(database_path, entries)` for every UserIP `.json` database file, sorted by path."""
    USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)
    yield from get_cached_userip_databases()


def dedup_userip_entries(entries: Iterable[UserIPEntryModel]) -> list[UserIPEntryModel]:
    """Deduplicate `(username, ip)` pairs while preserving order and merging metadata."""
    deduplicated: list[UserIPEntryModel] = []
    seen_pairs: dict[tuple[str, str], int] = {}
    for entry in entries:
        pair_key = (entry.username.casefold(), entry.ip)
        if pair_key in seen_pairs:
            existing_index = seen_pairs[pair_key]
            deduplicated[existing_index] = deduplicated[existing_index].merge_duplicate(entry)
            continue
        seen_pairs[pair_key] = len(deduplicated)
        deduplicated.append(entry)
    return deduplicated


def rewrite_db_without_entries(db_path: Path, to_remove: set[tuple[str, str]]) -> None:
    """Remove specific `(username, ip)` pairs from a database file in-place."""
    if not to_remove or not db_path.is_file():
        return
    db_model = load_userip_database_model(db_path)
    filtered_entries = [entry for entry in db_model.entries if (entry.username, entry.ip) not in to_remove]
    if len(filtered_entries) != len(db_model.entries):
        db_model.entries = filtered_entries
        save_userip_database_model(db_path, db_model)


def rewrite_db_rename_entries(db_path: Path, pairs: list[tuple[str, str]], new_username: str, *, match_ip_ranges: bool = False) -> int:
    """Replace matched `(old_username, ip_or_range)` entries with *new_username* in-place and return the count renamed."""
    if not db_path.is_file() or not pairs:
        return 0
    db_model = load_userip_database_model(db_path)
    target_pairs = set(pairs)
    renamed_count = 0
    updated_entries: list[UserIPEntryModel] = []
    now_iso = get_current_iso_timestamp()

    for entry in db_model.entries:
        matched = (
            any(pair_user == entry.username and (entry.ip == pair_ip or entry_ip_covers_ip(entry.ip, pair_ip)) for pair_user, pair_ip in pairs)
            if match_ip_ranges
            else (entry.username, entry.ip) in target_pairs
        )
        if matched:
            renamed_count += 1
            new_source = 'Manual' if entry.source == 'Looky' else entry.source
            updated_entries.append(entry.model_copy(update={'username': new_username, 'is_looky': False, 'source': new_source, 'updated_at': now_iso}))
        else:
            updated_entries.append(entry)

    if renamed_count:
        db_model.entries = dedup_userip_entries(updated_entries)
        save_userip_database_model(db_path, db_model)
    return renamed_count


def rewrite_db_edit_entry_ip(db_path: Path, old_ip_or_range: str, new_ip_or_range: str, *, username: str | None = None) -> int:
    """Replace an entry's IP or range in a database file in-place and return the number of entries replaced."""
    if not db_path.is_file():
        return 0
    db_model = load_userip_database_model(db_path)
    replaced_count = 0
    updated_entries: list[UserIPEntryModel] = []
    now_iso = get_current_iso_timestamp()

    for entry in db_model.entries:
        if entry.ip == old_ip_or_range and (username is None or entry.username == username):
            replaced_count += 1
            new_source = 'Manual' if entry.source == 'Looky' else entry.source
            updated_entries.append(
                enrich_userip_entry_from_logs(entry.model_copy(update={'ip': new_ip_or_range, 'is_looky': False, 'source': new_source, 'updated_at': now_iso}))[0],
            )
        else:
            updated_entries.append(entry)

    if replaced_count:
        db_model.entries = dedup_userip_entries(updated_entries)
        save_userip_database_model(db_path, db_model)
    return replaced_count


def rewrite_db_edit_entry_note(db_path: Path, username: str, ip_or_range: str, new_note: str) -> bool:
    """Update the `notes` field for a specific `(username, ip_or_range)` entry in *db_path*."""
    if not db_path.is_file():
        return False
    db_model, cleaned_note, modified, now_iso = load_userip_database_model(db_path), new_note.strip(), False, get_current_iso_timestamp()
    for i, entry in enumerate(db_model.entries):
        if entry.username == username and entry.ip == ip_or_range and entry.notes != cleaned_note:
            db_model.entries[i] = entry.model_copy(update={'notes': cleaned_note, 'updated_at': now_iso})
            modified = True
    if modified:
        save_userip_database_model(db_path, db_model)
    return modified


def rewrite_db_edit_ip_notes(db_path: Path, ip_address: str, new_note: str) -> int:
    """Update the `notes` field for all entries in *db_path* covering *ip_address* and return the match count."""
    if not db_path.is_file():
        return 0
    db_model, cleaned_note, matched_count, modified, now_iso = load_userip_database_model(db_path), new_note.strip(), 0, False, get_current_iso_timestamp()
    for i, entry in enumerate(db_model.entries):
        if entry_ip_covers_ip(entry.ip, ip_address):
            matched_count += 1
            if entry.notes != cleaned_note:
                db_model.entries[i] = entry.model_copy(update={'notes': cleaned_note, 'updated_at': now_iso})
                modified = True
    if modified:
        save_userip_database_model(db_path, db_model)
    return matched_count


def append_userip_entries(db_path: Path, entries: Sequence[UserIPEntryModel], *, anchor_usernames_by_ip: Mapping[str, str] | None = None) -> set[tuple[str, str]]:
    """Add entries to a UserIP `.json` database file, inserting next to matching IPs or usernames and avoiding duplicates."""
    db_model = load_userip_database_model(db_path)
    existing_by_pair: dict[tuple[str, str], UserIPEntryModel] = {(entry.username.casefold(), entry.ip): entry for entry in db_model.entries}
    added_pairs: set[tuple[str, str]] = set()
    modified = False
    now_iso = get_current_iso_timestamp()

    for entry in entries:
        username, ip_or_range = entry.username.strip(), entry.ip.strip()
        if not username or not ip_or_range:
            continue
        cf_pair = (username.casefold(), ip_or_range)
        existing_entry = existing_by_pair.get(cf_pair)
        if existing_entry is None:
            new_entry, _ = enrich_userip_entry_from_logs(entry.model_copy(update={'username': username, 'ip': ip_or_range, 'notes': entry.notes.strip()}))
            existing_by_pair[cf_pair] = new_entry
            added_pairs.add((username, ip_or_range))
            anchor_user = anchor_usernames_by_ip.get(ip_or_range, '') if anchor_usernames_by_ip is not None else ''
            db_model.entries.insert(find_userip_insert_index(db_model.entries, username, ip_or_range, anchor_username=anchor_user), new_entry)
            modified = True
        elif (entry.is_looky and not existing_entry.is_looky) or (entry.notes.strip() and not existing_entry.notes):
            existing_index = db_model.entries.index(existing_entry)
            upgraded_looky = existing_entry.is_looky or entry.is_looky
            new_src = 'Looky' if upgraded_looky else existing_entry.source
            upd = {'is_looky': upgraded_looky, 'source': new_src, 'notes': existing_entry.notes or entry.notes.strip(), 'updated_at': now_iso}
            updated_entry, _ = enrich_userip_entry_from_logs(existing_entry.model_copy(update=upd))
            db_model.entries[existing_index] = updated_entry
            existing_by_pair[cf_pair] = updated_entry
            if entry.is_looky and not existing_entry.is_looky:
                added_pairs.add((existing_entry.username, ip_or_range))
            modified = True

    if modified:
        save_userip_database_model(db_path, db_model)
    return added_pairs


def populate_userip_databases_menu(
    parent_menu: QMenu,
    database_paths: list[Path],
    tooltip: str,
    handler_factory: Callable[[Path], Callable[[], None]],
    *,
    disabled_path: Path | None = None,
) -> int:
    """Add database entries to *parent_menu*, nesting subfolders as child menus, and return the enabled action count."""
    folder_menus: dict[tuple[str, ...], QMenu] = {}
    menus_with_folders: set[QMenu] = set()
    enabled_count = 0

    def _sort_key(db_path: Path) -> tuple[tuple[int, str], ...]:
        rel = db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
        return tuple((0, part.casefold()) if i < len(rel.parts) - 1 else (1, part.casefold()) for i, part in enumerate(rel.parts))

    for db_path in sorted(database_paths, key=_sort_key):
        rel = db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
        current_menu = parent_menu
        for depth in range(len(rel.parts) - 1):
            folder_key = rel.parts[: depth + 1]
            if folder_key not in folder_menus:
                folder_menu = current_menu.addMenu(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'folder.svg')), rel.parts[depth])
                folder_menu.setToolTipsVisible(True)
                folder_menus[folder_key] = folder_menu
                menus_with_folders.add(current_menu)
            current_menu = folder_menus[folder_key]

        if current_menu in menus_with_folders:
            current_menu.addSeparator()
            menus_with_folders.remove(current_menu)

        action = current_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')), rel.parts[-1])
        action.setToolTip(tooltip)
        action.triggered.connect(handler_factory(db_path))
        if disabled_path is not None and db_path == disabled_path:
            action.setEnabled(False)
        else:
            enabled_count += 1

    return enabled_count


# ---- Common subnet descriptions for the slider ----
_SUBNET_NOTES: dict[int, str] = {32: '  (single host)', 24: '  (common home network)', 16: '  (large corporate network)'}
_SUBNET_SLIDER_OPTIONS: list[tuple[int, str]] = [
    (p, f'/{p}  —  {1 << (32 - p):,} address{pluralize(1 << (32 - p), "", "es")}{_SUBNET_NOTES.get(p, "")}') for p in range(32, 15, -1)
]

_SUBNET_PREFIX_MIN_INDEX = 0
_SUBNET_PREFIX_MAX_INDEX = len(_SUBNET_SLIDER_OPTIONS) - 1
_SUBNET_DEFAULT_SLIDER_INDEX = 8  # /24

_MODE_SINGLE = 0
_MODE_RANGE = 1
_MODE_SUBNET = 2


class IPRangeBuilderDialog(QDialog):
    """User-friendly dialog for building IP range entries without needing to know CIDR notation."""

    def __init__(self, parent: QWidget | None, initial_ip: str | None = None, initial_entry: str | None = None, *, allow_single_ip: bool = True) -> None:
        """Build the IP Range Builder dialog."""
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle(f'IP Range Builder - {TITLE}')
        self.setMinimumWidth(scale_by_ui(520))
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)

        layout = QVBoxLayout(self)

        # --- Mode selection ---
        mode_group = QGroupBox('Range Type')
        mode_layout = QVBoxLayout(mode_group)
        self._mode_group = QButtonGroup(self)
        self._radio_single = QRadioButton('Single IP address')
        self._radio_range = QRadioButton('IP range  (from one address to another)')
        self._radio_subnet = QRadioButton('Subnet  (block of addresses starting from a base IP)')
        for btn_id, radio in ((_MODE_SINGLE, self._radio_single), (_MODE_RANGE, self._radio_range), (_MODE_SUBNET, self._radio_subnet)):
            self._mode_group.addButton(radio, btn_id)
            mode_layout.addWidget(radio)
        layout.addWidget(mode_group)

        # --- Input fields ---
        input_group = QGroupBox('Details')
        input_layout = QGridLayout(input_group)
        self._single_label, self._single_input = QLabel('IP Address:'), self._create_ip_input('e.g. 192.168.1.1')
        self._range_from_label, self._range_from_input = QLabel('From:'), self._create_ip_input('e.g. 192.168.1.100')
        self._range_to_label, self._range_to_input = QLabel('To:'), self._create_ip_input('e.g. 192.168.1.200')
        self._subnet_ip_label, self._subnet_ip_input = QLabel('Base IP:'), self._create_ip_input('e.g. 192.168.1.0')
        input_pairs = (
            (self._single_label, self._single_input), (self._range_from_label, self._range_from_input),
            (self._range_to_label, self._range_to_input), (self._subnet_ip_label, self._subnet_ip_input),
        )
        for row_idx, (lbl, inp) in enumerate(input_pairs):
            input_layout.addWidget(lbl, row_idx, 0)
            input_layout.addWidget(inp, row_idx, 1)
            inp.textChanged.connect(self._update_preview)

        self._subnet_size_label, self._subnet_slider = QLabel('Block size:'), QSlider(Qt.Orientation.Horizontal)
        self._subnet_slider.setRange(_SUBNET_PREFIX_MIN_INDEX, _SUBNET_PREFIX_MAX_INDEX)
        self._subnet_slider.setValue(_SUBNET_DEFAULT_SLIDER_INDEX)
        self._subnet_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self._subnet_slider.setTickInterval(1)
        input_layout.addWidget(self._subnet_size_label, 4, 0)
        input_layout.addWidget(self._subnet_slider, 4, 1)

        self._subnet_desc_label = QLabel('')
        self._subnet_desc_label.setStyleSheet(SUBNET_DESC_LABEL_STYLESHEET)
        input_layout.addWidget(self._subnet_desc_label, 5, 0, 1, 2)
        layout.addWidget(input_group)

        # --- Preview ---
        preview_group = QGroupBox('Preview')
        preview_layout = QVBoxLayout(preview_group)
        self._preview = QLabel('', wordWrap=True)
        self._preview.setStyleSheet(IP_RANGE_PREVIEW_EMPTY_STYLESHEET)
        preview_layout.addWidget(self._preview)
        layout.addWidget(preview_group)

        # --- Buttons ---
        self._buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self._ok_button = self._buttons.button(QDialogButtonBox.StandardButton.Ok)
        if self._ok_button:
            self._ok_button.setEnabled(False)
        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

        self._mode_group.idToggled.connect(self._on_mode_changed)
        self._subnet_slider.valueChanged.connect(self._on_slider_changed)

        # Hide the single-IP option when the dialog is used for range-only operations
        if not allow_single_ip:
            self._radio_single.setVisible(False)
        (self._radio_single if allow_single_ip else self._radio_subnet).setChecked(True)
        self._on_mode_changed()

        if initial_ip is not None:
            self._single_input.setText(initial_ip)
            self._range_from_input.setText(initial_ip)
            self._subnet_ip_input.setText(initial_ip)
            self._radio_subnet.setChecked(True)

        if initial_entry is not None:
            if '/' in initial_entry:
                base_ip, _, prefix_str = initial_entry.partition('/')
                with contextlib.suppress(ValueError):
                    cidr_prefix = int(prefix_str)
                    self._subnet_slider.setValue(next((i for i, (p_len, _) in enumerate(_SUBNET_SLIDER_OPTIONS) if p_len == cidr_prefix), _SUBNET_DEFAULT_SLIDER_INDEX))
                self._subnet_ip_input.setText(base_ip)
                self._radio_subnet.setChecked(True)
            elif '-' in initial_entry:
                from_ip, _, to_ip = initial_entry.partition('-')
                self._range_from_input.setText(from_ip)
                self._range_to_input.setText(to_ip)
                self._radio_range.setChecked(True)
            else:
                self._single_input.setText(initial_entry)
                self._radio_single.setChecked(True)

    @staticmethod
    def _create_ip_input(placeholder: str) -> QLineEdit:
        """Create a QLineEdit configured for IPv4 address entry."""
        line_edit = QLineEdit(placeholderText=placeholder, maxLength=15)
        line_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
        return line_edit

    def _on_mode_changed(self, *_args: object) -> None:
        """Show/hide input fields based on the selected mode."""
        mode = self._mode_group.checkedId()
        w: QWidget
        for w in (self._single_label, self._single_input):
            w.setVisible(mode == _MODE_SINGLE)
        for w in (self._range_from_label, self._range_from_input, self._range_to_label, self._range_to_input):
            w.setVisible(mode == _MODE_RANGE)
        for w in (self._subnet_ip_label, self._subnet_ip_input, self._subnet_size_label, self._subnet_slider, self._subnet_desc_label):
            w.setVisible(mode == _MODE_SUBNET)
        if mode == _MODE_SUBNET:
            self._on_slider_changed()
        self._update_preview()

    def _on_slider_changed(self, *_args: object) -> None:
        """Update the subnet description label when the slider moves."""
        index = self._subnet_slider.value()
        if _SUBNET_PREFIX_MIN_INDEX <= index <= _SUBNET_PREFIX_MAX_INDEX:
            self._subnet_desc_label.setText(_SUBNET_SLIDER_OPTIONS[index][1])
        self._update_preview()

    def _update_preview(self, *_args: object) -> None:
        """Refresh the preview panel based on current inputs."""
        mode = self._mode_group.checkedId()
        if mode == _MODE_SINGLE:
            self._update_single_preview()
        elif mode == _MODE_RANGE:
            self._update_range_preview()
        elif mode == _MODE_SUBNET:
            self._update_subnet_preview()

    def _update_single_preview(self) -> None:
        if not (text := self._single_input.text().strip()):
            self._set_preview('', valid=None)
            return
        try:
            self._set_preview(f'Single host: {IPv4Address(text)}', valid=True)
        except ValueError:
            self._set_preview('Enter a valid IPv4 address', valid=False)

    def _update_range_preview(self) -> None:
        from_text, to_text = self._range_from_input.text().strip(), self._range_to_input.text().strip()
        if not from_text and not to_text:
            self._set_preview('', valid=None)
            return
        try:
            start, end = IPv4Address(from_text), IPv4Address(to_text)
        except ValueError:
            self._set_preview('Enter valid IPv4 addresses in both fields', valid=False)
            return
        if start > end:
            self._set_preview('"From" address must be less than or equal to "To" address', valid=False)
            return
        count = int(end) - int(start) + 1
        self._set_preview(f'Range: {start} - {end}\nCovers {count:,} address{pluralize(count, "", "es")}', valid=True)

    def _update_subnet_preview(self) -> None:
        text, slider_index = self._subnet_ip_input.text().strip(), self._subnet_slider.value()
        if not text or not _SUBNET_PREFIX_MIN_INDEX <= slider_index <= _SUBNET_PREFIX_MAX_INDEX:
            self._set_preview('', valid=None)
            return
        prefix, _ = _SUBNET_SLIDER_OPTIONS[slider_index]
        try:
            network = ipaddress.ip_network(f'{text}/{prefix}', strict=False)
        except ValueError:
            self._set_preview('Enter a valid base IPv4 address', valid=False)
            return
        usable = max(0, network.num_addresses - 2) if prefix < _IPV4_BROADCAST_FREE_PREFIX and network.version == _IPV4_VERSION else network.num_addresses
        self._set_preview(
            f'Network: {network.network_address}/{prefix}\nRange: {network.network_address} - {network.broadcast_address}\n'
            f'Addresses: {network.num_addresses:,} total, {usable:,} usable',
            valid=True,
        )

    def _set_preview(self, text: str, *, valid: bool | None) -> None:
        """Update the preview label text and style, and toggle the OK button."""
        self._preview.setText(text)
        style = IP_RANGE_PREVIEW_EMPTY_STYLESHEET if valid is None else (IP_RANGE_PREVIEW_VALID_STYLESHEET if valid else IP_RANGE_PREVIEW_ERROR_STYLESHEET)
        self._preview.setStyleSheet(style)
        if self._ok_button:
            self._ok_button.setEnabled(valid is True)

    def result_entry(self) -> str:
        """Return the constructed IP/range string for insertion into the database."""
        mode = self._mode_group.checkedId()
        if mode == _MODE_SINGLE:
            return self._single_input.text().strip()
        if mode == _MODE_RANGE:
            return f'{self._range_from_input.text().strip()}-{self._range_to_input.text().strip()}'
        if mode == _MODE_SUBNET:
            text = self._subnet_ip_input.text().strip()
            prefix, _ = _SUBNET_SLIDER_OPTIONS[self._subnet_slider.value()]
            with contextlib.suppress(ValueError):
                return str(ipaddress.ip_network(f'{text}/{prefix}', strict=False))
            return text
        return ''
