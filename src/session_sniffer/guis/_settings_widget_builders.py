"""Widget factory helpers shared by `SettingsDialog`."""

import re
from typing import TYPE_CHECKING

from PyQt6.QtCore import QRegularExpression, Qt
from PyQt6.QtGui import QAction, QIcon, QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.guis.stylesheets import COMPACT_BUTTON_STYLESHEET
from session_sniffer.guis.userip_manager_helpers import IPRangeBuilderDialog
from session_sniffer.settings import SETTING_DEFAULTS, SettingMeta, SettingType
from session_sniffer.settings.settings import Settings

if TYPE_CHECKING:
    from collections.abc import Callable

RESTART_INDICATOR = ' \u27F3'


def create_boolean_widget(meta: SettingMeta) -> QCheckBox:
    """Create a checkbox widget for a boolean setting."""
    checkbox = QCheckBox()
    if meta.tooltip:
        checkbox.setToolTip(meta.tooltip)
    return checkbox


def create_text_widget(meta: SettingMeta) -> QLineEdit:
    """Create a line-edit widget for a string/IPv4/MAC setting.

    For secret fields (`meta.secret=True`) a reveal toggle action is embedded
    as a trailing icon inside the `QLineEdit` itself.
    """
    le = QLineEdit()
    if meta.setting_type == SettingType.IPV4:
        le.setPlaceholderText('e.g. 192.168.1.100')
        le.setMaxLength(15)
        le.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9.]{0,15}')))
    elif meta.setting_type == SettingType.MAC_ADDRESS:
        le.setPlaceholderText('e.g. AA:BB:CC:DD:EE:FF')
        le.setMaxLength(17)
        le.setValidator(QRegularExpressionValidator(QRegularExpression(r'[0-9A-Fa-f:]{0,17}')))

        def _auto_format_mac(text: str, widget: QLineEdit = le) -> None:
            cursor = widget.cursorPosition()
            hex_before = sum(1 for c in text[:cursor] if c in '0123456789ABCDEFabcdef')
            hex_only = ''.join(c for c in text.upper() if c in '0123456789ABCDEF')[:12]
            formatted = ':'.join(hex_only[i:i + 2] for i in range(0, len(hex_only), 2))
            if formatted == text:
                return
            widget.blockSignals(True)  # noqa: FBT003
            widget.setText(formatted)
            widget.blockSignals(False)  # noqa: FBT003
            new_pos = len(formatted)
            hex_count = 0
            for i, c in enumerate(formatted):
                if hex_count == hex_before:
                    new_pos = i
                    break
                if c != ':':
                    hex_count += 1
            widget.setCursorPosition(new_pos)

        le.textEdited.connect(_auto_format_mac)
    if meta.max_length is not None:
        le.setMaxLength(meta.max_length)
    if meta.validator_pattern is not None:
        _char_rx = re.compile(meta.validator_pattern)

        def _filter_chars(text: str, _le: QLineEdit = le, _rx: re.Pattern[str] = _char_rx) -> None:
            filtered = ''.join(_rx.findall(text))
            if filtered == text:
                return
            _le.blockSignals(True)  # noqa: FBT003
            _le.setText(filtered)
            _le.blockSignals(False)  # noqa: FBT003

        le.textEdited.connect(_filter_chars)
    if meta.tooltip:
        le.setToolTip(meta.tooltip)
    if meta.secret:
        le.setEchoMode(QLineEdit.EchoMode.Password)
        _icons_dir = RESOURCES_DIR_PATH / 'icons'
        icon_show = QIcon(str(_icons_dir / 'eye_show.svg'))
        icon_hide = QIcon(str(_icons_dir / 'eye_hide.svg'))
        reveal_action = le.addAction(icon_hide, QLineEdit.ActionPosition.TrailingPosition)
        if reveal_action is None:
            msg = 'QLineEdit.addAction returned None'
            raise RuntimeError(msg)
        _act: QAction = reveal_action
        _act.setCheckable(True)
        _act.setToolTip('Show')

        def _toggle_echo(checked: bool, _le: QLineEdit = le, _show: QIcon = icon_show, _hide: QIcon = icon_hide, _a: QAction = _act) -> None:  # noqa: FBT001
            _le.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password)
            _a.setIcon(_show if checked else _hide)
            _a.setToolTip('Hide' if checked else 'Show')

        _act.toggled.connect(_toggle_echo)
    return le


def create_float_widget(meta: SettingMeta) -> QDoubleSpinBox:
    """Create a double spin-box widget for a float setting."""
    spin = QDoubleSpinBox()
    spin.setDecimals(1)
    spin.setSingleStep(0.5)
    spin.setMinimum(meta.min_value if meta.min_value is not None else 0.0)
    spin.setMaximum(meta.max_value if meta.max_value is not None else 99999.0)
    if meta.tooltip:
        spin.setToolTip(meta.tooltip)
    return spin


def create_integer_widget(meta: SettingMeta) -> QSpinBox:
    """Create a spin-box widget for an integer setting."""
    spin = QSpinBox()
    spin.setSingleStep(int(meta.step) if meta.step is not None else 1)
    spin.setMinimum(int(meta.min_value) if meta.min_value is not None else 0)
    spin.setMaximum(int(meta.max_value) if meta.max_value is not None else 99999)
    if meta.tooltip:
        spin.setToolTip(meta.tooltip)
    return spin


def create_integer_or_all_widget(meta: SettingMeta) -> QSpinBox:
    """Create a spin-box widget for an integer-or-all setting (0 displays as special text)."""
    spin = QSpinBox()
    spin.setSingleStep(int(meta.step) if meta.step is not None else 1)
    spin.setMinimum(0)
    spin.setMaximum(int(meta.max_value) if meta.max_value is not None else 99999)
    spin.setSpecialValueText(meta.special_value_text)
    if meta.tooltip:
        spin.setToolTip(meta.tooltip)
    return spin


def create_enum_widget(meta: SettingMeta) -> QComboBox:
    """Create a combo-box widget for an enum setting."""
    combo = QComboBox()
    if meta.allowed_values:
        combo.addItems(meta.allowed_values)
    if meta.tooltip:
        combo.setToolTip(meta.tooltip)
    return combo


def create_bool_or_enum_widget(meta: SettingMeta) -> QComboBox:
    """Create a combo-box widget for a bool-or-enum setting (first item is 'Disabled')."""
    combo = QComboBox()
    items = ['Disabled']
    if meta.allowed_values:
        items.extend(meta.allowed_values)
    combo.addItems(items)
    if meta.tooltip:
        combo.setToolTip(meta.tooltip)
    return combo


def create_column_tuple_widget(key: str, meta: SettingMeta) -> QGroupBox:
    """Create a scrollable multi-column grid of checkboxes for column visibility."""
    allowed_attr = meta.allowed_columns_attr or ''
    allowed_columns: tuple[str, ...] = getattr(Settings, allowed_attr, ())
    default_columns: tuple[str, ...] = tuple(SETTING_DEFAULTS.get(key, ()))

    title = meta.display_label
    if meta.requires_capture_restart:
        title += RESTART_INDICATOR
    group = QGroupBox(title)
    if meta.tooltip:
        group.setToolTip(meta.tooltip)

    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setMaximumHeight(340)
    scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    inner = QWidget()
    grid = QGridLayout(inner)
    grid.setContentsMargins(4, 4, 4, 4)
    grid.setSpacing(2)

    num_columns = 3
    for i, col_name in enumerate(allowed_columns):
        display_text = meta.display_labels.get(col_name, col_name) if meta.display_labels else col_name
        checkbox = QCheckBox(display_text)
        checkbox.setObjectName(col_name)
        grid.addWidget(checkbox, i // num_columns, i % num_columns)

    scroll.setWidget(inner)

    btn_select_all = QPushButton('Select All')
    btn_deselect_all = QPushButton('Deselect All')
    btn_reset = QPushButton('Reset')
    btn_reset.setToolTip('Reset to default selected columns')
    for btn in (btn_select_all, btn_deselect_all, btn_reset):
        btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
    btn_select_all.clicked.connect(lambda: set_all_checkboxes(inner, checked=True))
    btn_deselect_all.clicked.connect(lambda: set_all_checkboxes(inner, checked=False))
    btn_reset.clicked.connect(lambda: set_checkboxes_to(inner, default_columns))

    btn_row = QHBoxLayout()
    btn_row.setContentsMargins(0, 0, 0, 0)
    btn_row.setSpacing(6)
    btn_row.addWidget(btn_select_all)
    btn_row.addWidget(btn_deselect_all)
    btn_row.addWidget(btn_reset)
    btn_row.addStretch()

    outer = QVBoxLayout(group)
    outer.setSpacing(4)
    outer.addLayout(btn_row)
    outer.addWidget(scroll, 1)
    return group


def create_third_party_servers_split_widget(key: str, meta: SettingMeta) -> QWidget:
    """Create a widget with checkable presets and a single list of server checkboxes."""
    allowed_attr = meta.allowed_columns_attr or ''
    allowed_columns: tuple[str, ...] = getattr(Settings, allowed_attr, ())
    default_columns: tuple[str, ...] = tuple(SETTING_DEFAULTS.get(key, ()))
    display_labels = meta.display_labels or {}

    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(10)

    # Presets group box
    presets_group = QGroupBox('Presets')
    presets_group.setToolTip('Select presets to automatically block their required IP ranges. You can check multiple presets.')
    presets_grid_container = QWidget()
    presets_grid = QGridLayout(presets_grid_container)
    presets_grid.setContentsMargins(4, 4, 4, 4)
    presets_grid.setSpacing(2)

    preset_names = [
        'GTA V PC',
        'GTA V PlayStation',
        'GTA V Xbox One',
        'Minecraft Bedrock',
        'OmeTV',
        'Discord',
        'RustDesk',
        'Steam',
        'Call of Duty: WWII',
    ]

    preset_checkboxes: dict[str, QCheckBox] = {}
    presets_num_columns = 3
    for i, pname in enumerate(preset_names):
        cb = QCheckBox(pname)
        cb.setObjectName(pname)
        preset_checkboxes[pname] = cb
        presets_grid.addWidget(cb, i // presets_num_columns, i % presets_num_columns)

    preset_btn_select_all = QPushButton('Select All')
    preset_btn_deselect_all = QPushButton('Deselect All')
    preset_btn_reset = QPushButton('Reset')
    preset_btn_reset.setToolTip('Reset to default presets')
    for btn in (preset_btn_select_all, preset_btn_deselect_all, preset_btn_reset):
        btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    preset_btn_row = QHBoxLayout()
    preset_btn_row.setContentsMargins(0, 0, 0, 0)
    preset_btn_row.setSpacing(6)
    preset_btn_row.addWidget(preset_btn_select_all)
    preset_btn_row.addWidget(preset_btn_deselect_all)
    preset_btn_row.addWidget(preset_btn_reset)
    preset_btn_row.addStretch()

    presets_scroll = QScrollArea()
    presets_scroll.setWidgetResizable(True)
    presets_scroll.setMaximumHeight(110)
    presets_scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    presets_scroll.setWidget(presets_grid_container)

    presets_layout = QVBoxLayout(presets_group)
    presets_layout.setSpacing(4)
    presets_layout.addLayout(preset_btn_row)
    presets_layout.addWidget(presets_scroll)

    # Checklist container
    title_checklist = meta.display_label
    if meta.requires_capture_restart:
        title_checklist += RESTART_INDICATOR

    checklist_group = QGroupBox(title_checklist)
    if meta.tooltip:
        checklist_group.setToolTip(meta.tooltip)

    grid_container = QWidget()
    grid = QGridLayout(grid_container)
    grid.setContentsMargins(4, 4, 4, 4)
    grid.setSpacing(2)

    checkboxes: dict[str, QCheckBox] = {}
    num_columns = 3
    for i, col_name in enumerate(allowed_columns):
        display_text = display_labels.get(col_name, col_name)
        checkbox = QCheckBox(display_text)
        checkbox.setObjectName(col_name)
        checkboxes[col_name] = checkbox
        grid.addWidget(checkbox, i // num_columns, i % num_columns)

    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setMaximumHeight(350)
    scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
    scroll.setWidget(grid_container)

    btn_select_all = QPushButton('Select All')
    btn_deselect_all = QPushButton('Deselect All')
    btn_reset = QPushButton('Reset')
    btn_reset.setToolTip('Reset to default selected options')
    for btn in (btn_select_all, btn_deselect_all, btn_reset):
        btn.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    btn_select_all.clicked.connect(lambda: set_all_checkboxes(grid_container, checked=True))
    btn_deselect_all.clicked.connect(lambda: set_all_checkboxes(grid_container, checked=False))
    btn_reset.clicked.connect(lambda: set_checkboxes_to(grid_container, default_columns))

    btn_row = QHBoxLayout()
    btn_row.setContentsMargins(0, 0, 0, 0)
    btn_row.setSpacing(6)
    btn_row.addWidget(btn_select_all)
    btn_row.addWidget(btn_deselect_all)
    btn_row.addWidget(btn_reset)
    btn_row.addStretch()

    group_layout = QVBoxLayout(checklist_group)
    group_layout.setSpacing(4)
    group_layout.addLayout(btn_row)
    group_layout.addWidget(scroll, 1)

    layout.addWidget(presets_group)
    layout.addWidget(checklist_group)

    # Preset mappings
    presets_map: dict[str, set[str]] = {
        'GTA V PC': {
            'TAKETWO_INTERACTIVE',
            'BATTLEYE',
            'UK_MINISTRY_OF_DEFENCE',
            'US_DEPARTMENT_OF_DEFENSE',
        },
        'GTA V PlayStation': {
            'TAKETWO_INTERACTIVE',
            'TELLAS_GREECE',
            'PLAYSTATION_SONY',
            'UK_MINISTRY_OF_DEFENCE',
            'US_DEPARTMENT_OF_DEFENSE',
        },
        'GTA V Xbox One': {
            'TAKETWO_INTERACTIVE',
            'MICROSOFT',
            'UK_MINISTRY_OF_DEFENCE',
            'US_DEPARTMENT_OF_DEFENSE',
        },
        'Minecraft Bedrock': {
            'MICROSOFT',
        },
        'OmeTV': {
            'OVH',
            'GOOGLE_LLC',
        },
        'Discord': {
            'DISCORD',
            'CLOUDFLARE',
        },
        'RustDesk': {
            'RUSTDESK',
        },
        'Steam': {
            'VALVE',
        },
        'Call of Duty: WWII': {
            'THE_CONSTANT_COMPANY',
            'TENCENT',
            'DEMONWARE',
            'US_DEPARTMENT_OF_DEFENSE',
            'TSEFLOW',
            'LATITUDE_SH',
            'FRIEND_IT',
        },
    }

    is_updating = False

    def update_presets_from_ranges() -> None:
        nonlocal is_updating
        if is_updating:
            return
        is_updating = True
        try:
            checked_ranges = {rname for rname, cb in checkboxes.items() if cb.isChecked()}
            for pname, preset_set in presets_map.items():
                is_active = preset_set.issubset(checked_ranges)
                preset_checkboxes[pname].blockSignals(True)  # noqa: FBT003
                preset_checkboxes[pname].setChecked(is_active)
                preset_checkboxes[pname].blockSignals(False)  # noqa: FBT003
        finally:
            is_updating = False

    def on_preset_clicked(pname: str, checked: bool) -> None:  # noqa: FBT001
        nonlocal is_updating
        if is_updating:
            return
        is_updating = True
        try:
            preset_set = presets_map[pname]
            if checked:
                for rname in preset_set:
                    if rname in checkboxes:
                        checkboxes[rname].blockSignals(True)  # noqa: FBT003
                        checkboxes[rname].setChecked(True)
                        checkboxes[rname].blockSignals(False)  # noqa: FBT003
            else:
                other_required: set[str] = set()
                for other_name, other_cb in preset_checkboxes.items():
                    if other_name != pname and other_cb.isChecked():
                        other_required.update(presets_map[other_name])
                for rname in preset_set:
                    if rname not in other_required and rname in checkboxes:
                        checkboxes[rname].blockSignals(True)  # noqa: FBT003
                        checkboxes[rname].setChecked(False)
                        checkboxes[rname].blockSignals(False)  # noqa: FBT003

            checked_ranges = {rname for rname, cb in checkboxes.items() if cb.isChecked()}
            for other_name, other_set in presets_map.items():
                is_active = other_set.issubset(checked_ranges)
                preset_checkboxes[other_name].blockSignals(True)  # noqa: FBT003
                preset_checkboxes[other_name].setChecked(is_active)
                preset_checkboxes[other_name].blockSignals(False)  # noqa: FBT003
        finally:
            is_updating = False

    def make_handler(name: str) -> Callable[[bool], None]:
        def handler(checked: bool) -> None:  # noqa: FBT001
            on_preset_clicked(name, checked)
        return handler

    def select_all_presets() -> None:
        nonlocal is_updating
        is_updating = True
        try:
            for cb in preset_checkboxes.values():
                cb.blockSignals(True)  # noqa: FBT003
                cb.setChecked(True)
                cb.blockSignals(False)  # noqa: FBT003
            for preset_set in presets_map.values():
                for rname in preset_set:
                    if rname in checkboxes:
                        checkboxes[rname].blockSignals(True)  # noqa: FBT003
                        checkboxes[rname].setChecked(True)
                        checkboxes[rname].blockSignals(False)  # noqa: FBT003
        finally:
            is_updating = False
        update_presets_from_ranges()

    def deselect_all_presets() -> None:
        nonlocal is_updating
        is_updating = True
        try:
            for cb in preset_checkboxes.values():
                cb.blockSignals(True)  # noqa: FBT003
                cb.setChecked(False)
                cb.blockSignals(False)  # noqa: FBT003
            for preset_set in presets_map.values():
                for rname in preset_set:
                    if rname in checkboxes:
                        checkboxes[rname].blockSignals(True)  # noqa: FBT003
                        checkboxes[rname].setChecked(False)
                        checkboxes[rname].blockSignals(False)  # noqa: FBT003
        finally:
            is_updating = False
        update_presets_from_ranges()

    def reset_presets() -> None:
        set_checkboxes_to(grid_container, default_columns)

    preset_btn_select_all.clicked.connect(select_all_presets)
    preset_btn_deselect_all.clicked.connect(deselect_all_presets)
    preset_btn_reset.clicked.connect(reset_presets)

    for pname, p_cb in preset_checkboxes.items():
        p_cb.clicked.connect(make_handler(pname))

    for cb in checkboxes.values():
        cb.toggled.connect(update_presets_from_ranges)

    update_presets_from_ranges()

    return container


def create_ip_range_tuple_widget(meta: SettingMeta, parent: QWidget) -> QGroupBox:
    """Create an add/remove list widget for managing a tuple of IP addresses and ranges."""
    title = meta.display_label
    if meta.requires_capture_restart:
        title += RESTART_INDICATOR
    group = QGroupBox(title)
    if meta.tooltip:
        group.setToolTip(meta.tooltip)

    list_widget = QListWidget()
    list_widget.setMaximumHeight(180)
    list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
    list_widget.setSortingEnabled(True)

    add_button = QPushButton('\u2795 Add')
    add_button.setToolTip('Add a new blocked IP address, range, or subnet')
    add_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
    add_button.setCursor(Qt.CursorShape.PointingHandCursor)
    add_button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    remove_button = QPushButton('\U0001f5d1 Remove')
    remove_button.setToolTip('Remove the selected entries')
    remove_button.setStyleSheet(COMPACT_BUTTON_STYLESHEET)
    remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
    remove_button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)

    def _add_entry() -> None:
        dialog = IPRangeBuilderDialog(parent)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        entry = dialog.result_entry()
        if not entry:
            return
        existing = {item.text() for i in range(list_widget.count()) if (item := list_widget.item(i)) is not None}
        if entry not in existing:
            list_widget.addItem(entry)

    def _remove_entries() -> None:
        for item in list_widget.selectedItems():
            list_widget.takeItem(list_widget.row(item))

    add_button.clicked.connect(_add_entry)
    remove_button.clicked.connect(_remove_entries)

    btn_row = QHBoxLayout()
    btn_row.setContentsMargins(0, 0, 0, 0)
    btn_row.setSpacing(6)
    btn_row.addWidget(add_button)
    btn_row.addWidget(remove_button)
    btn_row.addStretch()

    outer_layout = QVBoxLayout(group)
    outer_layout.setSpacing(4)
    outer_layout.addLayout(btn_row)
    outer_layout.addWidget(list_widget, 1)
    return group


def set_all_checkboxes(container: QWidget, *, checked: bool) -> None:
    """Set all QCheckBox children of `container` to `checked`."""
    for checkbox in container.findChildren(QCheckBox):
        checkbox.setChecked(checked)


def set_checkboxes_to(container: QWidget, selected: tuple[str, ...]) -> None:
    """Check exactly the QCheckBox children whose objectName is in `selected`."""
    wanted = set(selected)
    for checkbox in container.findChildren(QCheckBox):
        checkbox.setChecked(checkbox.objectName() in wanted)
