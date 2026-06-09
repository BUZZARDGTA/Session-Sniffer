"""Shared helpers, constants, and dialogs for the UserIP Databases Manager."""

import ipaddress
import re
from ipaddress import IPv4Address
from typing import TYPE_CHECKING, override

from PyQt6.QtCore import QEvent, QModelIndex, QObject, QRegularExpression, QSortFilterProxyModel, Qt
from PyQt6.QtGui import QBrush, QColor, QFontMetrics, QHelpEvent, QRegularExpressionValidator, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QDialog,
    QDialogButtonBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListView,
    QPushButton,
    QRadioButton,
    QSlider,
    QToolTip,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import (
    DIALOG_BUTTON_STYLESHEET,
    DIALOG_PRIMARY_BUTTON_STYLESHEET,
    IP_RANGE_PREVIEW_EMPTY_STYLESHEET,
    IP_RANGE_PREVIEW_ERROR_STYLESHEET,
    IP_RANGE_PREVIEW_VALID_STYLESHEET,
    SUBNET_DESC_LABEL_STYLESHEET,
)
from session_sniffer.guis.utils import apply_search_icon

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

RE_USERIP_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<username>[^=]+)=(?P<ip>[^;#]+)')
RE_SETTINGS_INI_PARSER_PATTERN = re.compile(r'^(?![;#])(?P<key>[^=]+)=(?P<value>.*)')

SECTION_SETTINGS = 'Settings'
SECTION_USERIP = 'UserIP'

INDEX_COLUMN = 0
USERNAME_COLUMN = 1
IP_COLUMN = 2
RANGE_COLUMN = 3
DATABASE_COLUMN = 4

DUPLICATE_HIGHLIGHT_BRUSH = QBrush(QColor(255, 165, 0, 60))

_IPV4_BROADCAST_FREE_PREFIX = 31
_IPV4_VERSION = 4


def handle_ini_section_header(
    raw_line: str,
    stripped: str,
    new_lines: list[str],
    *,
    in_section: bool,
    section_name: str,
) -> tuple[bool, bool]:
    """Check whether *stripped* is an INI section header.

    If it is, append *raw_line* to *new_lines* and return `(True, is_target_section)`.
    Otherwise return `(False, in_section)` unchanged.
    """
    if stripped.startswith('[') and stripped.endswith(']'):
        new_lines.append(raw_line)
        return True, stripped[1:-1] == section_name
    return False, in_section


SETTINGS_KEYS_ORDER: list[str] = [
    'ENABLED', 'COLOR', 'LOG', 'NOTIFICATIONS', 'VOICE_NOTIFICATIONS',
    'PROTECTION', 'PROTECTION_SUSPEND_PROCESS_MODE',
]

SETTINGS_DEFAULTS: dict[str, str] = {
    'ENABLED': 'True',
    'COLOR': '',
    'LOG': 'True',
    'NOTIFICATIONS': 'True',
    'VOICE_NOTIFICATIONS': 'False',
    'PROTECTION': 'False',
    'PROTECTION_SUSPEND_PROCESS_MODE': 'Auto',
}


def parse_settings_from_lines(settings_lines: list[str]) -> dict[str, str]:
    """Parse raw `[Settings]` lines into a `{KEY: value}` dictionary.

    Unknown keys are silently ignored.  Missing keys are filled from defaults.
    """
    parsed: dict[str, str] = {}

    for raw_line in settings_lines:
        line = raw_line.strip()
        if not line or line.startswith((';', '#')):
            continue

        match = RE_SETTINGS_INI_PARSER_PATTERN.search(line)
        if not match:
            continue

        key_raw = match.group('key')
        value_raw = match.group('value')
        if key_raw is None or value_raw is None:
            continue

        key = key_raw.strip()
        value = value_raw.strip()

        if key in SETTINGS_KEYS_ORDER and key not in parsed:
            parsed[key] = value

    # Fill missing keys with defaults
    for key in SETTINGS_KEYS_ORDER:
        if key not in parsed:
            parsed[key] = SETTINGS_DEFAULTS[key]

    return parsed


def parse_settings_from_content(content: str) -> dict[str, str]:
    """Parse the `[Settings]` section of raw INI *content* into a `{KEY: value}` dictionary.

    Convenience wrapper around :func:`parse_settings_from_lines` that accepts the full
    file content as a string rather than a pre-split list of lines.
    """
    settings_lines: list[str] = []
    current_section: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1]
            continue
        if current_section == SECTION_SETTINGS:
            settings_lines.append(raw_line)

    return parse_settings_from_lines(settings_lines)


class EntriesSortProxy(QSortFilterProxyModel):
    """Proxy that uses IP address as a secondary sort key when the primary column values are equal."""

    @staticmethod
    def _ip_sort_key(value: str) -> tuple[int, ...]:
        """Return a numeric tuple for valid IPs so they sort numerically."""
        try:
            return tuple(ipaddress.ip_address(value).packed)
        except ValueError:
            return tuple(b for c in value.encode() for b in (c,))

    @override
    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        """Filter rows by Username, IP, and Database columns only (skip the Index column)."""
        model = self.sourceModel()
        if model is None:
            return True
        regex = self.filterRegularExpression()
        if not regex.pattern():
            return True
        for col in (USERNAME_COLUMN, IP_COLUMN, RANGE_COLUMN, DATABASE_COLUMN):
            index = model.index(source_row, col, source_parent)
            data = model.data(index, self.filterRole())
            if data is not None and regex.match(str(data)).hasMatch():
                return True
        return False

    @override
    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        """Compare two indexes, sorting IPs numerically and using IP as a tiebreaker."""
        model = self.sourceModel()
        if model is not None:
            # When sorting the Index column, compare numerically via UserRole.
            if self.sortColumn() == INDEX_COLUMN:
                left_val = model.data(left, Qt.ItemDataRole.UserRole)
                right_val = model.data(right, Qt.ItemDataRole.UserRole)
                if isinstance(left_val, int) and isinstance(right_val, int):
                    return left_val < right_val
            # When sorting the IP column directly, compare numerically.
            elif self.sortColumn() in (IP_COLUMN, RANGE_COLUMN):
                left_ip = model.data(left)
                right_ip = model.data(right)
                if left_ip is not None and right_ip is not None:
                    return self._ip_sort_key(left_ip) < self._ip_sort_key(right_ip)
            else:
                left_data = model.data(left)
                right_data = model.data(right)
                if left_data == right_data:
                    left_ip = model.data(left.siblingAtColumn(IP_COLUMN))
                    right_ip = model.data(right.siblingAtColumn(IP_COLUMN))
                    if left_ip is not None and right_ip is not None:
                        return self._ip_sort_key(left_ip) < self._ip_sort_key(right_ip)
        return bool(super().lessThan(left, right))


class ElidedTooltipFilter(QObject):
    """Event filter that shows a tooltip only when the cell text is visually truncated."""

    def __init__(self, view: QAbstractItemView) -> None:
        """Initialize the filter attached to the given item view."""
        super().__init__(view)
        self._view = view

    def _get_header(self) -> QHeaderView | None:
        """Return the horizontal header regardless of view type."""
        if isinstance(self._view, QTreeView):
            return self._view.header()
        return getattr(self._view, 'horizontalHeader', lambda: None)()

    @override
    def eventFilter(self, a0: QObject | None, a1: QEvent | None) -> bool:
        """Show tooltip for elided cells, hide otherwise."""
        if a1 is not None and a1.type() == QEvent.Type.ToolTip and isinstance(a1, QHelpEvent):
            index = self._view.indexAt(a1.pos())
            if index.isValid():
                text = index.data(Qt.ItemDataRole.DisplayRole)
                if text:
                    header = self._get_header()
                    col_width = header.sectionSize(index.column()) if header is not None else 0
                    fm = QFontMetrics(self._view.font())
                    if fm.horizontalAdvance(str(text)) + 8 > col_width:
                        QToolTip.showText(a1.globalPos(), str(text), self._view)
                    else:
                        QToolTip.hideText()
                else:
                    QToolTip.hideText()
                return True
        return super().eventFilter(a0, a1)


BYTES_PER_UNIT = 1024

NEW_DATABASE_TEMPLATE = """\
[Settings]
ENABLED=True
COLOR=
LOG=True
NOTIFICATIONS=True
VOICE_NOTIFICATIONS=False
PROTECTION=False
PROTECTION_SUSPEND_PROCESS_MODE=Auto

[UserIP]
"""


def human_readable_size(size_bytes: int) -> str:
    """Format a byte count into a human-readable string."""
    value = float(size_bytes)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < BYTES_PER_UNIT:
            return f'{value:.1f} {unit}' if unit != 'B' else f'{int(value)} {unit}'
        value /= BYTES_PER_UNIT
    return f'{value:.1f} TB'


def iter_userip_entries(content: str) -> Iterator[tuple[str, str]]:
    """Yield `(username, ip)` pairs from the `[UserIP]` section of INI content."""
    current_section: str | None = None

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1]
            continue

        if current_section != SECTION_USERIP:
            continue

        match = RE_USERIP_INI_PARSER_PATTERN.search(line)
        if not match:
            continue

        username_raw = match.group('username')
        ip_raw = match.group('ip')
        if username_raw is None or ip_raw is None:
            continue

        username = username_raw.strip()
        ip = ip_raw.strip()
        if not username or not ip:
            continue

        yield username, ip


def read_preserved_sections(path: Path) -> tuple[list[str], list[str]]:
    """Read the file and return (header_lines_before_sections, settings_section_lines).

    Everything before the first `[section]` is considered the header (comments, etc.).
    Lines inside `[Settings]` are preserved.  `[UserIP]` is rebuilt by the caller.
    """
    header_lines: list[str] = []
    settings_lines: list[str] = []
    current_section: str | None = None
    found_first_section = False

    if not path.is_file():
        return header_lines, settings_lines

    content = path.read_text('utf-8')

    for raw_line in content.splitlines():
        line = raw_line.strip()

        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1]
            found_first_section = True
            continue

        if not found_first_section:
            header_lines.append(raw_line)
            continue

        if current_section == SECTION_SETTINGS:
            settings_lines.append(raw_line)

    return header_lines, settings_lines


def rewrite_db_without_entries(db_path: Path, to_remove: set[tuple[str, str]]) -> None:
    """Remove specific (username, ip) pairs from a database file in-place."""
    new_lines: list[str] = []
    in_userip_section = False
    for raw_line in db_path.read_text('utf-8').splitlines():
        stripped = raw_line.strip()
        is_header, in_userip_section = handle_ini_section_header(raw_line, stripped, new_lines, in_section=in_userip_section, section_name=SECTION_USERIP)
        if is_header:
            continue
        if in_userip_section and to_remove:
            m = RE_USERIP_INI_PARSER_PATTERN.search(stripped)
            if m:
                u = m.group('username').strip()
                i = m.group('ip').strip()
                if u and i and (u, i) in to_remove:
                    to_remove.discard((u, i))
                    continue
        new_lines.append(raw_line)
    db_path.write_text('\n'.join(new_lines), encoding='utf-8')


class RenameUsernameDialog(QDialog):
    """Compact dialog for picking an existing username to rename entries to."""

    def __init__(self, parent: QWidget | None, usernames: list[str], current_username: str) -> None:
        """Build the rename username picker dialog."""
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle(f'Rename Username - {TITLE}')
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.setMinimumSize(320, 400)
        self.resize(360, 460)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(f'Current:  <b>{current_username}</b>'))

        self._search = QLineEdit()
        self._search.setPlaceholderText('Filter usernames…')
        apply_search_icon(self._search)
        layout.addWidget(self._search)

        self._list_model = QStandardItemModel()
        for name in sorted(set(usernames), key=str.lower):
            self._list_model.appendRow(QStandardItem(name))

        self._proxy = QSortFilterProxyModel()
        self._proxy.setSourceModel(self._list_model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        self._list = QListView()
        self._list.setModel(self._proxy)
        self._list.setAlternatingRowColors(True)
        layout.addWidget(self._list, stretch=1)

        self._search.textChanged.connect(self._proxy.setFilterFixedString)
        self._list.doubleClicked.connect(self.accept)

        button_row = QHBoxLayout()
        button_row.addStretch()

        rename_btn = QPushButton('Rename')
        rename_btn.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        rename_btn.clicked.connect(self.accept)
        button_row.addWidget(rename_btn)

        cancel_btn = QPushButton('Cancel')
        cancel_btn.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_btn.clicked.connect(self.reject)
        button_row.addWidget(cancel_btn)

        layout.addLayout(button_row)

    def selected_username(self) -> str | None:
        """Return the username selected in the list, or None."""
        indexes = self._list.selectedIndexes()
        if not indexes:
            return None
        data = self._proxy.data(indexes[0], Qt.ItemDataRole.DisplayRole)
        return str(data) if data else None


class RemoveUsernameDialog(QDialog):
    """Dialog for selecting one or more usernames to remove from a UserIP database entry."""

    def __init__(self, parent: QWidget | None, usernames: list[str], ip_address: str) -> None:
        """Build the remove username picker dialog."""
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle(f'Remove Username - {TITLE}')
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)
        self.setMinimumSize(320, 400)
        self.resize(360, 460)

        self._total_count = len(usernames)

        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(f'IP address:  <b>{ip_address}</b>'))
        layout.addWidget(QLabel('Select usernames to remove:'))

        self._search = QLineEdit()
        self._search.setPlaceholderText('Filter usernames…')
        apply_search_icon(self._search)
        layout.addWidget(self._search)

        self._list_model = QStandardItemModel()
        for name in sorted(set(usernames), key=str.lower):
            self._list_model.appendRow(QStandardItem(name))

        self._proxy = QSortFilterProxyModel()
        self._proxy.setSourceModel(self._list_model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)

        self._list = QListView()
        self._list.setModel(self._proxy)
        self._list.setAlternatingRowColors(True)
        self._list.setSelectionMode(QListView.SelectionMode.ExtendedSelection)
        layout.addWidget(self._list, stretch=1)

        self._search.textChanged.connect(self._proxy.setFilterFixedString)

        button_row = QHBoxLayout()
        button_row.addStretch()

        remove_btn = QPushButton('Remove')
        remove_btn.setStyleSheet(DIALOG_PRIMARY_BUTTON_STYLESHEET)
        remove_btn.clicked.connect(self.accept)
        button_row.addWidget(remove_btn)

        cancel_btn = QPushButton('Cancel')
        cancel_btn.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_btn.clicked.connect(self.reject)
        button_row.addWidget(cancel_btn)

        layout.addLayout(button_row)

    def selected_usernames(self) -> list[str] | None:
        """Return the usernames selected in the list, or None if nothing selected."""
        indexes = self._list.selectedIndexes()
        if not indexes:
            return None
        result: list[str] = []
        for idx in indexes:
            data = self._proxy.data(idx, Qt.ItemDataRole.DisplayRole)
            if data:
                result.append(str(data))
        return result or None

    def is_all_selected(self) -> bool:
        """Return True if every username in the list is selected."""
        selected = self.selected_usernames()
        return selected is not None and len(selected) >= self._total_count


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
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint)

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
        if self._ok_button is not None:
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
                    prefix = int(parts[1])
                    slider_idx = next(
                        (i for i, (p, _) in enumerate(_SUBNET_SLIDER_OPTIONS) if p == prefix),
                        _SUBNET_DEFAULT_SLIDER_INDEX,
                    )
                except ValueError:
                    slider_idx = _SUBNET_DEFAULT_SLIDER_INDEX
                self._subnet_ip_input.setText(base_ip)
                self._subnet_slider.setValue(slider_idx)
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
        idx = self._subnet_slider.value()
        if _SUBNET_PREFIX_MIN_INDEX <= idx <= _SUBNET_PREFIX_MAX_INDEX:
            _, desc = _SUBNET_SLIDER_OPTIONS[idx]
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
            f'Range: {start} - {end}\n'
            f'Covers {count:,} address{"es" if count != 1 else ""}',
            valid=True,
        )

    def _update_subnet_preview(self) -> None:
        text = self._subnet_ip_input.text().strip()
        slider_idx = self._subnet_slider.value()
        if not text:
            self._set_preview('', valid=None)
            return
        if not _SUBNET_PREFIX_MIN_INDEX <= slider_idx <= _SUBNET_PREFIX_MAX_INDEX:
            self._set_preview('', valid=None)
            return
        prefix, _ = _SUBNET_SLIDER_OPTIONS[slider_idx]
        try:
            network = ipaddress.ip_network(f'{text}/{prefix}', strict=False)
        except ValueError:
            self._set_preview('Enter a valid base IPv4 address', valid=False)
            return
        host_count = network.num_addresses
        usable = max(0, host_count - 2) if prefix < _IPV4_BROADCAST_FREE_PREFIX and network.version == _IPV4_VERSION else host_count
        self._set_preview(
            f'Network: {network.network_address}/{prefix}\n'
            f'Range: {network.network_address} - {network.broadcast_address}\n'
            f'Addresses: {host_count:,} total, {usable:,} usable',
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
        if self._ok_button is not None:
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
            slider_idx = self._subnet_slider.value()
            prefix, _ = _SUBNET_SLIDER_OPTIONS[slider_idx]
            try:
                network = ipaddress.ip_network(f'{text}/{prefix}', strict=False)
            except ValueError:
                return text
            return str(network)

        return ''
