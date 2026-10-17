"""Shared helpers, constants, and dialogs for the UserIP Databases Manager."""

import contextlib
import ipaddress
import json
import logging
from datetime import datetime
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, cast, override

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QRegularExpression, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor, QIcon, QRegularExpressionValidator, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMenu,
    QRadioButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import (
    IP_RANGE_PREVIEW_EMPTY_STYLESHEET,
    IP_RANGE_PREVIEW_ERROR_STYLESHEET,
    IP_RANGE_PREVIEW_VALID_STYLESHEET,
    SUBNET_DESC_LABEL_STYLESHEET,
)
from session_sniffer.models.userip_settings_model import (
    DEFAULT_USERIP_FILES_SETTINGS,
    UserIPDatabaseFile,
    UserIPEntryModel,
    UserIPSettingsModel,
    format_iso_timestamp_display,
    get_current_iso_timestamp,
)
from session_sniffer.networking.ip_range import entry_ip_covers_ip
from session_sniffer.text_utils import pluralize, split_usernames
from session_sniffer.utils import custom_str_to_bool
from session_sniffer.utils_exceptions import InvalidBooleanValueError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Sequence
    from pathlib import Path
    from typing import Any

logger = logging.getLogger(__name__)

INDEX_COLUMN = 0
USERNAME_COLUMN = 1
IP_COLUMN = 2
RANGE_COLUMN = 3
NOTES_COLUMN = 4
SOURCE_COLUMN = 5
DETECTIONS_COLUMN = 6
ADDED_AT_COLUMN = 7
UPDATED_AT_COLUMN = 8
FIRST_SEEN_AT_COLUMN = 9
LAST_SEEN_AT_COLUMN = 10
DATABASE_COLUMN = 11

TIMESTAMP_COLUMNS = (ADDED_AT_COLUMN, UPDATED_AT_COLUMN, FIRST_SEEN_AT_COLUMN, LAST_SEEN_AT_COLUMN)

FILTERABLE_COLUMNS = (
    USERNAME_COLUMN,
    IP_COLUMN,
    RANGE_COLUMN,
    NOTES_COLUMN,
    SOURCE_COLUMN,
    ADDED_AT_COLUMN,
    UPDATED_AT_COLUMN,
    FIRST_SEEN_AT_COLUMN,
    LAST_SEEN_AT_COLUMN,
    DATABASE_COLUMN,
)

ENTRY_TABLE_HEADERS = ['#', 'Username', 'IP', 'Range', 'Notes', 'Source', 'Detections', 'Added', 'Updated', 'First Seen', 'Last Seen', 'Database']

IS_PERSISTED_ROLE = Qt.ItemDataRole.UserRole + 1

DUPLICATE_HIGHLIGHT_BRUSH = QBrush(QColor(255, 165, 0, 60))

_IPV4_BROADCAST_FREE_PREFIX = 31
_IPV4_VERSION = 4

NEW_DATABASE_SETTINGS = UserIPSettingsModel(
    ENABLED=True,
    COLOR='',
    LOG=True,
    NOTIFICATIONS=True,
    VOICE_NOTIFICATIONS=False,
    PROTECTION=False,
    PROTECTION_SUSPEND_PROCESS_MODE='Auto',
)


class EntriesSortProxy(QSortFilterProxyModel):
    """Proxy that uses IP address as a secondary sort key when the primary column values are equal."""

    @staticmethod
    def _ip_sort_key(value: str) -> tuple[int, ...]:
        """Return a numeric tuple for valid IPs so they sort numerically."""
        try:
            return tuple(ipaddress.ip_address(value).packed)
        except ValueError:
            return tuple(byte_val for char_val in value.encode() for byte_val in (char_val,))

    @staticmethod
    def _timestamp_sort_key(value: object) -> float:
        """Return a numeric POSIX timestamp for ISO-8601 strings, sorting empty values first."""
        if isinstance(value, str) and value:
            with contextlib.suppress(ValueError):
                return datetime.fromisoformat(value).timestamp()
        return float('-inf')

    @override
    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex | QPersistentModelIndex) -> bool:
        """Filter rows across all searchable entry and metadata columns."""
        model = self.sourceModel()
        if not model:
            return True
        regex = self.filterRegularExpression()
        if not regex.pattern():
            return True
        for column in FILTERABLE_COLUMNS:
            index = model.index(source_row, column, source_parent)
            data = model.data(index, self.filterRole())
            if data is not None and regex.match(str(data)).hasMatch():
                return True
        return False

    @override
    def lessThan(self, left: QModelIndex | QPersistentModelIndex, right: QModelIndex | QPersistentModelIndex) -> bool:
        """Compare two indexes, sorting numeric/IP/timestamp columns appropriately and using IP as a tiebreaker."""
        model = self.sourceModel()
        if model:
            sort_col = self.sortColumn()
            if sort_col in (INDEX_COLUMN, DETECTIONS_COLUMN):
                left_val = model.data(left, Qt.ItemDataRole.UserRole)
                right_val = model.data(right, Qt.ItemDataRole.UserRole)
                if isinstance(left_val, int) and isinstance(right_val, int) and left_val != right_val:
                    return left_val < right_val
            elif sort_col in (IP_COLUMN, RANGE_COLUMN):
                left_ip = model.data(left)
                right_ip = model.data(right)
                if left_ip is not None and right_ip is not None:
                    return self._ip_sort_key(left_ip) < self._ip_sort_key(right_ip)
            elif sort_col in TIMESTAMP_COLUMNS:
                left_ts = self._timestamp_sort_key(model.data(left, Qt.ItemDataRole.UserRole))
                right_ts = self._timestamp_sort_key(model.data(right, Qt.ItemDataRole.UserRole))
                if left_ts != right_ts:
                    return left_ts < right_ts
            else:
                left_data = model.data(left)
                right_data = model.data(right)
                if left_data != right_data:
                    return super().lessThan(left, right)

            left_ip = model.data(cast('QModelIndex', left).siblingAtColumn(IP_COLUMN))
            right_ip = model.data(cast('QModelIndex', right).siblingAtColumn(IP_COLUMN))
            if left_ip is not None and right_ip is not None:
                return self._ip_sort_key(left_ip) < self._ip_sort_key(right_ip)
        return super().lessThan(left, right)


def _make_readonly_item(text: str, user_data: object = None, *, tooltip: str = '') -> QStandardItem:
    """Create a read-only `QStandardItem` with optional `UserRole` data and tooltip."""
    item = QStandardItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
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
    index_item = _make_readonly_item(str(index) if index > 0 else '', index)
    index_item.setData(1 if persisted else 0, IS_PERSISTED_ROLE)

    username_item = QStandardItem(entry.username)
    if entry.is_looky:
        if looky_icon is not None:
            username_item.setIcon(looky_icon)
        username_item.setForeground(QBrush(QColor('#a855f7')))
        username_item.setToolTip('Added automatically by Looky System')
        username_item.setData(entry.is_looky, Qt.ItemDataRole.UserRole)

    is_single_ip = False
    if entry.ip:
        with contextlib.suppress(ValueError):
            IPv4Address(entry.ip)
            is_single_ip = True

    ip_item = QStandardItem(entry.ip if is_single_ip else '')
    range_item = QStandardItem('' if is_single_ip else entry.ip)
    notes_item = QStandardItem(entry.notes)
    source_item = _make_readonly_item(entry.source, entry.source)
    detections_item = _make_readonly_item(str(entry.detections_count), entry.detections_count)
    added_item = _make_timestamp_item(entry.added_at)
    updated_item = _make_timestamp_item(entry.updated_at)
    first_seen_item = _make_timestamp_item(entry.first_seen_at)
    last_seen_item = _make_timestamp_item(entry.last_seen_at)
    db_item = _make_readonly_item(database[0] if database else '', str(database[1]) if database is not None else None)
    return [index_item, username_item, ip_item, range_item, notes_item, source_item, detections_item, added_item, updated_item, first_seen_item, last_seen_item, db_item]


def is_row_persisted(model: QStandardItemModel, row: int) -> bool:
    """Return `True` if the row was loaded from or previously saved to disk."""
    return bool(model.item(row, INDEX_COLUMN).data(IS_PERSISTED_ROLE))


def mark_row_persisted(model: QStandardItemModel, row: int) -> None:
    """Mark a row in *model* as persisted on disk."""
    model.item(row, INDEX_COLUMN).setData(1, IS_PERSISTED_ROLE)


def set_row_updated_at(model: QStandardItemModel, row: int, updated_iso: str | None = None) -> str:
    """Update the `Updated` column item of *row* with *updated_iso* (defaults to current local ISO timestamp)."""
    iso_val = updated_iso if updated_iso is not None else get_current_iso_timestamp()
    updated_item = model.item(row, UPDATED_AT_COLUMN)
    updated_item.setText(format_iso_timestamp_display(iso_val))
    updated_item.setData(iso_val, Qt.ItemDataRole.UserRole)
    updated_item.setToolTip(iso_val)
    return iso_val


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
    entry_model, _ = UserIPEntryModel.from_raw_entry_dict(
        raw_meta,
        username=username,
        ip=ip_text,
        is_looky=bool(username_item.data(Qt.ItemDataRole.UserRole)),
        notes=notes,
    )
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
    content: str,
    *,
    default_settings: UserIPSettingsModel | None = None,
) -> UserIPDatabaseFile:
    """Parse raw JSON *content* into a validated `UserIPDatabaseFile` model."""
    fallback_settings = default_settings if default_settings is not None else NEW_DATABASE_SETTINGS
    if not content.strip():
        return UserIPDatabaseFile(settings=fallback_settings.model_copy(), entries=[])

    try:
        raw_data: object = json.loads(content)
    except json.JSONDecodeError as e:
        logger.warning('Failed to parse UserIP database JSON content: %s', e)
        return UserIPDatabaseFile(settings=fallback_settings.model_copy(), entries=[])

    if not isinstance(raw_data, dict):
        return UserIPDatabaseFile(settings=fallback_settings.model_copy(), entries=[])

    typed_data = cast('dict[str, Any]', raw_data)
    raw_settings_obj: object = typed_data.get('settings')
    if isinstance(raw_settings_obj, dict):
        validated_settings, _ = UserIPSettingsModel.validate_settings(cast('dict[str, Any]', raw_settings_obj))
    else:
        validated_settings = fallback_settings.model_copy()

    raw_entries_obj: object = typed_data.get('entries')
    raw_entries = cast('list[object]', raw_entries_obj) if isinstance(raw_entries_obj, list) else []

    entries: list[UserIPEntryModel] = []
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict):
            continue
        entry_dict = cast('dict[str, Any]', raw_entry)
        raw_username = entry_dict.get('username')
        raw_ip = entry_dict.get('ip')
        if not isinstance(raw_username, str) or not isinstance(raw_ip, str):
            continue
        username_str = raw_username.strip()
        ip_str = raw_ip.strip()
        if not username_str or not ip_str:
            continue

        raw_is_looky = entry_dict.get('is_looky', False)
        is_looky = raw_is_looky if isinstance(raw_is_looky, bool) else False
        if isinstance(raw_is_looky, str):
            with contextlib.suppress(InvalidBooleanValueError):
                is_looky, _ = custom_str_to_bool(raw_is_looky.strip())

        raw_notes = entry_dict.get('notes', '')
        notes_str = raw_notes.strip() if isinstance(raw_notes, str) else ''
        base_entry, _ = UserIPEntryModel.from_raw_entry_dict(
            entry_dict,
            username=username_str,
            ip=ip_str,
            is_looky=is_looky,
            notes=notes_str,
        )
        entries.extend(base_entry.model_copy(update={'username': individual_username}) for individual_username in split_usernames(username_str))

    return UserIPDatabaseFile(settings=validated_settings, entries=entries)


def load_userip_database_model(path: Path) -> UserIPDatabaseFile:
    """Read and parse a UserIP `.json` database file into a `UserIPDatabaseFile` model."""
    default_settings = DEFAULT_USERIP_FILES_SETTINGS.get(path.name) if path.parent == USERIP_DATABASES_DIR_PATH else None
    if not path.is_file():
        fallback = default_settings if default_settings is not None else NEW_DATABASE_SETTINGS
        return UserIPDatabaseFile(settings=fallback.model_copy(), entries=[])
    try:
        content = path.read_text(encoding='utf-8')
    except OSError as e:
        logger.warning('Failed to read UserIP database "%s": %s', path, e)
        fallback = default_settings if default_settings is not None else NEW_DATABASE_SETTINGS
        return UserIPDatabaseFile(settings=fallback.model_copy(), entries=[])
    return parse_userip_database_content(content, default_settings=default_settings)


def save_userip_database_model(path: Path, db_model: UserIPDatabaseFile) -> None:
    """Serialize and write a `UserIPDatabaseFile` model to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(db_model.serialize_to_json(), encoding='utf-8')


def iter_userip_databases() -> Iterator[tuple[Path, list[UserIPEntryModel]]]:
    """Yield `(database_path, entries)` for every UserIP `.json` database file, sorted by path."""
    USERIP_DATABASES_DIR_PATH.mkdir(parents=True, exist_ok=True)
    for json_path in sorted(USERIP_DATABASES_DIR_PATH.rglob('*.json')):
        if not json_path.is_file():
            continue
        yield json_path, load_userip_database_model(json_path).entries


def dedup_userip_entries(entries: Iterable[UserIPEntryModel]) -> list[UserIPEntryModel]:
    """Deduplicate `(username, ip)` pairs while preserving order and merging metadata."""
    deduplicated: list[UserIPEntryModel] = []
    seen_pairs: dict[tuple[str, str], int] = {}
    for entry in entries:
        pair_key = (entry.username, entry.ip)
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


def rewrite_db_rename_entries(
    db_path: Path,
    pairs: list[tuple[str, str]],
    new_username: str,
    *,
    match_ip_ranges: bool = False,
) -> int:
    """Replace matched `(old_username, ip_or_range)` entries with *new_username* in-place.

    Returns the number of entries renamed.
    """
    if not db_path.is_file() or not pairs:
        return 0
    db_model = load_userip_database_model(db_path)
    target_pairs = set(pairs)
    renamed_count = 0
    updated_entries: list[UserIPEntryModel] = []
    now_iso = get_current_iso_timestamp()

    for entry in db_model.entries:
        if match_ip_ranges:
            matched = any(
                pair_user == entry.username and (entry.ip == pair_ip or entry_ip_covers_ip(entry.ip, pair_ip))
                for pair_user, pair_ip in pairs
            )
        else:
            matched = (entry.username, entry.ip) in target_pairs
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


def rewrite_db_edit_entry_ip(
    db_path: Path,
    old_ip_or_range: str,
    new_ip_or_range: str,
    *,
    username: str | None = None,
) -> int:
    """Replace an entry's IP or range in a database file in-place.

    Args:
        db_path: Path to the UserIP database file.
        old_ip_or_range: The current IP address or range string to replace.
        new_ip_or_range: The new IP address or range string.
        username: If provided, only replaces the entry for this specific username.
            If None, replaces all occurrences of `old_ip_or_range`.

    Returns:
        The number of entries replaced.
    """
    if not db_path.is_file():
        return 0
    db_model = load_userip_database_model(db_path)
    replaced_count = 0
    updated_entries: list[UserIPEntryModel] = []
    now_iso = get_current_iso_timestamp()

    for entry in db_model.entries:
        if entry.ip == old_ip_or_range and (username is None or entry.username == username):
            replaced_count += 1
            updated_entries.append(entry.model_copy(update={'ip': new_ip_or_range, 'updated_at': now_iso}))
        else:
            updated_entries.append(entry)

    if replaced_count:
        db_model.entries = dedup_userip_entries(updated_entries)
        save_userip_database_model(db_path, db_model)
    return replaced_count


def rewrite_db_edit_entry_note(
    db_path: Path,
    username: str,
    ip_or_range: str,
    new_note: str,
) -> bool:
    """Update the `notes` field for a specific `(username, ip_or_range)` entry in *db_path*."""
    if not db_path.is_file():
        return False
    db_model = load_userip_database_model(db_path)
    cleaned_note = new_note.strip()
    modified = False
    now_iso = get_current_iso_timestamp()

    for i, entry in enumerate(db_model.entries):
        if entry.username == username and entry.ip == ip_or_range and entry.notes != cleaned_note:
            db_model.entries[i] = entry.model_copy(update={'notes': cleaned_note, 'updated_at': now_iso})
            modified = True

    if modified:
        save_userip_database_model(db_path, db_model)
    return modified


def rewrite_db_edit_ip_notes(
    db_path: Path,
    ip_address: str,
    new_note: str,
) -> int:
    """Update the `notes` field for all entries in *db_path* covering *ip_address*.

    Returns the number of entries matched.
    """
    if not db_path.is_file():
        return 0
    db_model = load_userip_database_model(db_path)
    cleaned_note = new_note.strip()
    matched_count = 0
    modified = False
    now_iso = get_current_iso_timestamp()

    for i, entry in enumerate(db_model.entries):
        if entry_ip_covers_ip(entry.ip, ip_address):
            matched_count += 1
            if entry.notes != cleaned_note:
                db_model.entries[i] = entry.model_copy(update={'notes': cleaned_note, 'updated_at': now_iso})
                modified = True

    if modified:
        save_userip_database_model(db_path, db_model)
    return matched_count


def append_userip_entries(db_path: Path, entries: Sequence[UserIPEntryModel]) -> set[tuple[str, str]]:
    """Add entries to a UserIP `.json` database file, inserting next to matching IPs and avoiding exact duplicates.

    Args:
        db_path: The target UserIP database file path.
        entries: Sequence of `UserIPEntryModel` instances to add.

    Returns:
        The set of `(username, ip_or_range)` pairs actually added (excluding exact duplicates already present).
    """
    db_model = load_userip_database_model(db_path)
    existing_by_pair: dict[tuple[str, str], UserIPEntryModel] = {
        (entry.username.casefold(), entry.ip): entry for entry in db_model.entries
    }
    added_pairs: set[tuple[str, str]] = set()
    modified = False
    now_iso = get_current_iso_timestamp()

    for entry in entries:
        username = entry.username.strip()
        ip_or_range = entry.ip.strip()
        if not username or not ip_or_range:
            continue
        cf_pair = (username.casefold(), ip_or_range)
        existing_entry = existing_by_pair.get(cf_pair)
        if existing_entry is None:
            new_entry = entry.model_copy(update={'username': username, 'ip': ip_or_range, 'notes': entry.notes.strip()})
            existing_by_pair[cf_pair] = new_entry
            added_pairs.add((username, ip_or_range))
            last_ip_index = next((i for i in range(len(db_model.entries) - 1, -1, -1) if db_model.entries[i].ip == ip_or_range), None)
            if last_ip_index is not None:
                db_model.entries.insert(last_ip_index + 1, new_entry)
            else:
                db_model.entries.append(new_entry)
            modified = True
        elif (entry.is_looky and not existing_entry.is_looky) or (entry.notes.strip() and not existing_entry.notes):
            existing_index = db_model.entries.index(existing_entry)
            upgraded_looky = existing_entry.is_looky or entry.is_looky
            updated_entry = existing_entry.model_copy(
                update={
                    'is_looky': upgraded_looky,
                    'source': 'Looky' if upgraded_looky else existing_entry.source,
                    'notes': existing_entry.notes or entry.notes.strip(),
                    'updated_at': now_iso,
                },
            )
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
    """Add database entries to *parent_menu*, nesting subfolders as child menus.

    Returns the count of enabled database actions added to the menu.
    """
    folder_menus: dict[tuple[str, ...], QMenu] = {}
    menus_with_folders: set[QMenu] = set()
    enabled_count = 0

    def _sort_key(db_path: Path) -> tuple[tuple[int, str], ...]:
        rel = db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
        return tuple((0, part.casefold()) if i < len(rel.parts) - 1 else (1, part.casefold()) for i, part in enumerate(rel.parts))

    for db_path in sorted(database_paths, key=_sort_key):
        rel = db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')

        if len(rel.parts) == 1:
            if parent_menu in menus_with_folders:
                parent_menu.addSeparator()
                menus_with_folders.remove(parent_menu)
            action = parent_menu.addAction(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'database.svg')), rel.parts[0])
            action.setToolTip(tooltip)
            action.triggered.connect(handler_factory(db_path))
            if disabled_path is not None and db_path == disabled_path:
                action.setEnabled(False)
            else:
                enabled_count += 1
        else:
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
_SUBNET_SLIDER_OPTIONS: list[tuple[int, str]] = [
    (32, '/32  —  1 address  (single host)'),
    (31, '/31  —  2 addresses'),
    (30, '/30  —  4 addresses'),
    (29, '/29  —  8 addresses'),
    (28, '/28  —  16 addresses'),
    (27, '/27  —  32 addresses'),
    (26, '/26  —  64 addresses'),
    (25, '/25  —  128 addresses'),
    (24, '/24  —  256 addresses  (common home network)'),
    (23, '/23  —  512 addresses'),
    (22, '/22  —  1,024 addresses'),
    (21, '/21  —  2,048 addresses'),
    (20, '/20  —  4,096 addresses'),
    (19, '/19  —  8,192 addresses'),
    (18, '/18  —  16,384 addresses'),
    (17, '/17  —  32,768 addresses'),
    (16, '/16  —  65,536 addresses  (large corporate network)'),
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
        self.setMinimumWidth(520)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)

        layout = QVBoxLayout(self)

        # --- Mode selection ---
        mode_group = QGroupBox('Range Type')
        mode_layout = QVBoxLayout(mode_group)

        self._mode_group = QButtonGroup(self)

        self._radio_single = QRadioButton('Single IP address')
        self._radio_range = QRadioButton('IP range  (from one address to another)')
        self._radio_subnet = QRadioButton('Subnet  (block of addresses starting from a base IP)')

        self._mode_group.addButton(self._radio_single, _MODE_SINGLE)
        self._mode_group.addButton(self._radio_range, _MODE_RANGE)
        self._mode_group.addButton(self._radio_subnet, _MODE_SUBNET)

        mode_layout.addWidget(self._radio_single)
        mode_layout.addWidget(self._radio_range)
        mode_layout.addWidget(self._radio_subnet)
        layout.addWidget(mode_group)

        # --- Input fields ---
        input_group = QGroupBox('Details')
        input_layout = QGridLayout(input_group)

        # Single IP fields
        self._single_label = QLabel('IP Address:')
        self._single_input = QLineEdit()
        self._single_input.setPlaceholderText('e.g. 192.168.1.1')
        self._single_input.setMaxLength(15)
        self._single_input.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
        input_layout.addWidget(self._single_label, 0, 0)
        input_layout.addWidget(self._single_input, 0, 1)

        # Range fields
        self._range_from_label = QLabel('From:')
        self._range_from_input = QLineEdit()
        self._range_from_input.setPlaceholderText('e.g. 192.168.1.100')
        self._range_from_input.setMaxLength(15)
        self._range_from_input.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
        self._range_to_label = QLabel('To:')
        self._range_to_input = QLineEdit()
        self._range_to_input.setPlaceholderText('e.g. 192.168.1.200')
        self._range_to_input.setMaxLength(15)
        self._range_to_input.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
        input_layout.addWidget(self._range_from_label, 1, 0)
        input_layout.addWidget(self._range_from_input, 1, 1)
        input_layout.addWidget(self._range_to_label, 2, 0)
        input_layout.addWidget(self._range_to_input, 2, 1)

        # Subnet fields
        self._subnet_ip_label = QLabel('Base IP:')
        self._subnet_ip_input = QLineEdit()
        self._subnet_ip_input.setPlaceholderText('e.g. 192.168.1.0')
        self._subnet_ip_input.setMaxLength(15)
        self._subnet_ip_input.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
        input_layout.addWidget(self._subnet_ip_label, 3, 0)
        input_layout.addWidget(self._subnet_ip_input, 3, 1)

        self._subnet_size_label = QLabel('Block size:')
        self._subnet_slider = QSlider(Qt.Orientation.Horizontal)
        self._subnet_slider.setMinimum(_SUBNET_PREFIX_MIN_INDEX)
        self._subnet_slider.setMaximum(_SUBNET_PREFIX_MAX_INDEX)
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
        self._preview = QLabel('')
        self._preview.setWordWrap(True)
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

        # --- Connections ---
        self._mode_group.idToggled.connect(self._on_mode_changed)
        self._single_input.textChanged.connect(self._update_preview)
        self._range_from_input.textChanged.connect(self._update_preview)
        self._range_to_input.textChanged.connect(self._update_preview)
        self._subnet_ip_input.textChanged.connect(self._update_preview)
        self._subnet_slider.valueChanged.connect(self._on_slider_changed)

        # Hide the single-IP option when the dialog is used for range-only operations
        if not allow_single_ip:
            self._radio_single.setVisible(False)

        # Start with the default mode (single IP, or subnet when single is not allowed)
        if allow_single_ip:
            self._radio_single.setChecked(True)
        else:
            self._radio_subnet.setChecked(True)
        self._on_mode_changed()

        # Pre-fill fields when an initial IP is provided
        if initial_ip is not None:
            self._single_input.setText(initial_ip)
            self._range_from_input.setText(initial_ip)
            self._subnet_ip_input.setText(initial_ip)
            self._radio_subnet.setChecked(True)

        # Pre-fill fields from an existing stored entry (single IP, range, or subnet)
        if initial_entry is not None:
            if '/' in initial_entry:
                parts = initial_entry.split('/', 1)
                base_ip = parts[0]
                try:
                    cidr_prefix = int(parts[1])

                    slider_index = next(
                        (i for i, (prefix_length, _) in enumerate(_SUBNET_SLIDER_OPTIONS) if prefix_length == cidr_prefix),
                        _SUBNET_DEFAULT_SLIDER_INDEX,
                    )
                except ValueError:
                    slider_index = _SUBNET_DEFAULT_SLIDER_INDEX
                self._subnet_ip_input.setText(base_ip)
                self._subnet_slider.setValue(slider_index)
                self._radio_subnet.setChecked(True)
            elif '-' in initial_entry:
                from_ip, _, to_ip = initial_entry.partition('-')
                self._range_from_input.setText(from_ip)
                self._range_to_input.setText(to_ip)
                self._radio_range.setChecked(True)
            else:
                self._single_input.setText(initial_entry)
                self._radio_single.setChecked(True)

    def _on_mode_changed(self, *_args: object) -> None:
        """Show/hide input fields based on the selected mode."""
        mode = self._mode_group.checkedId()

        # Single IP
        single_visible = mode == _MODE_SINGLE
        self._single_label.setVisible(single_visible)
        self._single_input.setVisible(single_visible)

        # Range
        range_visible = mode == _MODE_RANGE
        self._range_from_label.setVisible(range_visible)
        self._range_from_input.setVisible(range_visible)
        self._range_to_label.setVisible(range_visible)
        self._range_to_input.setVisible(range_visible)

        # Subnet
        subnet_visible = mode == _MODE_SUBNET
        self._subnet_ip_label.setVisible(subnet_visible)
        self._subnet_ip_input.setVisible(subnet_visible)
        self._subnet_size_label.setVisible(subnet_visible)
        self._subnet_slider.setVisible(subnet_visible)
        self._subnet_desc_label.setVisible(subnet_visible)

        if subnet_visible:
            self._on_slider_changed()

        self._update_preview()

    def _on_slider_changed(self, *_args: object) -> None:
        """Update the subnet description label when the slider moves."""
        index = self._subnet_slider.value()
        if _SUBNET_PREFIX_MIN_INDEX <= index <= _SUBNET_PREFIX_MAX_INDEX:
            _, desc = _SUBNET_SLIDER_OPTIONS[index]
            self._subnet_desc_label.setText(desc)
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
        text = self._single_input.text().strip()
        if not text:
            self._set_preview('', valid=None)
            return
        try:
            addr = IPv4Address(text)
            self._set_preview(f'Single host: {addr}', valid=True)
        except ValueError:
            self._set_preview('Enter a valid IPv4 address', valid=False)

    def _update_range_preview(self) -> None:
        from_text = self._range_from_input.text().strip()
        to_text = self._range_to_input.text().strip()
        if not from_text and not to_text:
            self._set_preview('', valid=None)
            return
        try:
            start = IPv4Address(from_text)
            end = IPv4Address(to_text)
        except ValueError:
            self._set_preview('Enter valid IPv4 addresses in both fields', valid=False)
            return
        if start > end:
            self._set_preview('"From" address must be less than or equal to "To" address', valid=False)
            return
        count = int(end) - int(start) + 1
        self._set_preview(
            f'Range: {start} - {end}\nCovers {count:,} address{pluralize(count, "", "es")}',
            valid=True,
        )

    def _update_subnet_preview(self) -> None:
        text = self._subnet_ip_input.text().strip()
        slider_index = self._subnet_slider.value()
        if not text:
            self._set_preview('', valid=None)
            return
        if not _SUBNET_PREFIX_MIN_INDEX <= slider_index <= _SUBNET_PREFIX_MAX_INDEX:
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
            f'Network: {network.network_address}/{prefix}\n'
            f'Range: {network.network_address} - {network.broadcast_address}\n'
            f'Addresses: {network.num_addresses:,} total, {usable:,} usable',
            valid=True,
        )

    def _set_preview(self, text: str, *, valid: bool | None) -> None:
        """Update the preview label text and style, and toggle the OK button."""
        self._preview.setText(text)
        if valid is None:
            self._preview.setStyleSheet(IP_RANGE_PREVIEW_EMPTY_STYLESHEET)
        elif valid:
            self._preview.setStyleSheet(IP_RANGE_PREVIEW_VALID_STYLESHEET)
        else:
            self._preview.setStyleSheet(IP_RANGE_PREVIEW_ERROR_STYLESHEET)
        if self._ok_button:
            self._ok_button.setEnabled(valid is True)

    def result_entry(self) -> str:
        """Return the constructed IP/range string for insertion into the database."""
        mode = self._mode_group.checkedId()

        if mode == _MODE_SINGLE:
            return self._single_input.text().strip()

        if mode == _MODE_RANGE:
            from_text = self._range_from_input.text().strip()
            to_text = self._range_to_input.text().strip()
            return f'{from_text}-{to_text}'

        if mode == _MODE_SUBNET:
            text = self._subnet_ip_input.text().strip()
            slider_index = self._subnet_slider.value()
            prefix, _ = _SUBNET_SLIDER_OPTIONS[slider_index]
            try:
                network = ipaddress.ip_network(f'{text}/{prefix}', strict=False)
            except ValueError:
                return text
            return str(network)

        return ''
