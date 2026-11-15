"""Private helper module: shared styles, widget helpers, and dialogs for combo-rule editing."""

from typing import TYPE_CHECKING, ClassVar, Literal, cast, override

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtGui import QIcon, QMouseEvent, QStandardItemModel
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import MAX_SUSPEND_DURATION_SECONDS
from session_sniffer.guis.country_data import (
    CONTINENT_NAMES,
    COUNTRY_NAMES,
    normalize_continent_name,
    normalize_country_name,
)
from session_sniffer.guis.live_language import set_i18n_colon_label
from session_sniffer.guis.stylesheets import GROUPBOX_STYLE, HINT_LABEL_STYLESHEET, LIST_WIDGET_STYLE
from session_sniffer.guis.theming import ICONS_DIR_PATH, themed_qss
from session_sniffer.guis.userip_manager_helpers import IPRangeBuilderDialog
from session_sniffer.guis.utils import (
    SUSPEND_TOOLTIP_AUTO,
    SUSPEND_TOOLTIP_DISABLED,
    SUSPEND_TOOLTIP_MANUAL,
    create_section_separator,
    load_country_flag_icon,
    scale_by_ui,
)
from session_sniffer.i18n import tr
from session_sniffer.models.combo_rules import DUAL_OPERATOR_CONDITIONS, NEGATABLE_CONDITIONS, NEGATED_PREFIX, ComboRule, split_condition_key
from session_sniffer.networking.ip_range import is_valid_ip_range_entry
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


def populate_voice_combo(combo: QComboBox) -> None:
    """Populate *combo* with localized voice choices and canonical `userData` keys."""
    combo.clear()
    for key in ('Disabled', 'Male', 'Female'):
        combo.addItem(tr(key), key)


def retranslate_voice_combo(combo: QComboBox) -> None:
    """Refresh localized display labels in *combo* from canonical `userData` keys."""
    with QSignalBlocker(combo):
        for i in range(combo.count()):
            key = str(combo.itemData(i) or '')
            if key:
                combo.setItemText(i, tr(key))


def populate_suspend_mode_combo(combo: QComboBox) -> None:
    """Populate *combo* with localized suspend mode items, tooltips, and canonical `userData` keys."""
    combo.clear()
    for key, tooltip_key in (
        ('Disabled', SUSPEND_TOOLTIP_DISABLED),
        ('Auto', SUSPEND_TOOLTIP_AUTO),
        ('Manual', SUSPEND_TOOLTIP_MANUAL),
    ):
        combo.addItem(tr(key), key)
        combo.setItemData(combo.count() - 1, tr(tooltip_key), Qt.ItemDataRole.ToolTipRole)


def retranslate_suspend_mode_combo(combo: QComboBox) -> None:
    """Refresh localized display labels and tooltips in *combo* from canonical `userData` keys."""
    tooltips_by_key = {
        'Disabled': SUSPEND_TOOLTIP_DISABLED,
        'Auto': SUSPEND_TOOLTIP_AUTO,
        'Manual': SUSPEND_TOOLTIP_MANUAL,
    }
    with QSignalBlocker(combo):
        for i in range(combo.count()):
            key = str(combo.itemData(i) or '')
            if key:
                combo.setItemText(i, tr(key))
                if (tip := tooltips_by_key.get(key)) is not None:
                    combo.setItemData(i, tr(tip), Qt.ItemDataRole.ToolTipRole)


def set_duration_widgets_helper(combo: QComboBox, spin: QSpinBox, duration: int | str) -> None:
    """Set duration combo and spin box from a stored duration value."""
    if isinstance(duration, int):
        idx = combo.findData('Manual')
        combo.setCurrentIndex(idx if idx >= 0 else 2)
        spin.setValue(max(1, duration))
        spin.setVisible(True)
    elif duration == 'Disabled':
        idx = combo.findData('Disabled')
        combo.setCurrentIndex(max(idx, 0))
        spin.setValue(DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS)
        spin.setVisible(False)
    else:
        idx = combo.findData('Auto')
        combo.setCurrentIndex(idx if idx >= 0 else 1)
        spin.setValue(DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS)
        spin.setVisible(False)


def read_duration_widgets_helper(combo: QComboBox, spin: QSpinBox) -> int | Literal['Auto']:
    """Read duration value from combo and spin box widgets."""
    if combo.currentData() == 'Manual':
        return spin.value()
    return 'Auto'


def set_voice_combo_helper(combo: QComboBox, *, value: Literal['Male', 'Female'] | bool) -> None:
    """Set voice combo from a stored voice notification value."""
    key = value if value in ('Male', 'Female') else 'Disabled'
    idx = combo.findData(key)
    combo.setCurrentIndex(max(idx, 0))


def read_voice_combo_helper(combo: QComboBox) -> Literal['Male', 'Female', False]:
    """Read voice notification value from a combo widget."""
    data = combo.currentData()
    if data == 'Male':
        return 'Male'
    if data == 'Female':
        return 'Female'
    return False


def _toggle_list_item_check_state(item: QListWidgetItem) -> None:
    """Allow clicking the item text (not just the checkbox indicator) to toggle check state."""
    list_widget = item.listWidget()
    # Note: Qt toggles the checkbox automatically when the indicator itself is clicked;
    # only toggle manually when the user clicked the row outside the indicator.
    cursor_pos = list_widget.viewport().mapFromGlobal(list_widget.cursor().pos())
    item_rect = list_widget.visualItemRect(item)
    if cursor_pos.x() > item_rect.left() + scale_by_ui(28):
        item.setCheckState(Qt.CheckState.Unchecked if item.checkState() == Qt.CheckState.Checked else Qt.CheckState.Checked)


class _ClickablePickerLineEdit(QLineEdit):
    """Read-only line edit that opens its associated picker dialog when clicked."""

    def __init__(self, on_click: Callable[[], None], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._on_click = on_click
        self.setReadOnly(True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    @override
    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._on_click()
            event.accept()
            return
        super().mousePressEvent(event)


class _CheckableSelectionDialog(QDialog):
    """Base modal multi-select dialog with a checkable `QListWidget` and bulk selection buttons."""

    def __init__(self, parent: QWidget, title: str, min_size: tuple[int, int], hint_text: str) -> None:
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle(title)
        self.setMinimumWidth(scale_by_ui(min_size[0]))
        self.setMinimumHeight(scale_by_ui(min_size[1]))
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)

        self._layout = QVBoxLayout(self)
        hint = QLabel(hint_text)
        hint.setStyleSheet(HINT_LABEL_STYLESHEET)
        self._layout.addWidget(hint)

        self._list = QListWidget()
        self._list.setStyleSheet(LIST_WIDGET_STYLE)
        self._list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self._list.itemClicked.connect(_toggle_list_item_check_state)

    def _populate_items(
        self,
        names_by_code: dict[str, str],
        existing_names: set[str] | None,
        preselected_normalized: set[str],
        icon_loader: Callable[[str], QIcon | None] | None = None,
    ) -> None:
        for code in sorted(names_by_code, key=lambda item_code: names_by_code[item_code]):
            name = names_by_code[code]
            if existing_names is not None and name in existing_names:
                continue
            item = QListWidgetItem(f'{code} - {name}')
            item.setData(Qt.ItemDataRole.UserRole, name)
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if name in preselected_normalized else Qt.CheckState.Unchecked)
            if icon_loader is not None and (icon := icon_loader(code)) is not None:
                item.setIcon(icon)
            self._list.addItem(item)
        self._layout.addWidget(self._list, stretch=1)

    def _add_footer_controls(self, select_button_label: str) -> None:
        actions_row = QHBoxLayout()
        select_btn = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), select_button_label)
        select_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        select_btn.clicked.connect(lambda: self._set_visible_checked(checked=True))
        actions_row.addWidget(select_btn)

        clear_btn = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square.svg')), f" {tr('Clear Selection')}")
        clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_btn.clicked.connect(self._clear_all_checked)
        actions_row.addWidget(clear_btn)
        actions_row.addStretch()
        self._layout.addLayout(actions_row)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self._layout.addWidget(buttons)

    def _set_visible_checked(self, *, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for i in range(self._list.count()):
            item = self._list.item(i)
            if not item.isHidden():
                item.setCheckState(state)

    def _clear_all_checked(self) -> None:
        for i in range(self._list.count()):
            self._list.item(i).setCheckState(Qt.CheckState.Unchecked)

    def _checked_item_values(self) -> list[str]:
        selected: list[str] = []
        for i in range(self._list.count()):
            item = self._list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                data = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(data, str) and data:
                    selected.append(data)
        return selected


class ContinentSelectionDialog(_CheckableSelectionDialog):
    """Multi-select continent selection dialog with checkboxes."""

    def __init__(
        self,
        parent: QWidget,
        existing_continents: set[str] | None = None,
        *,
        preselected_continents: Iterable[str] = (),
        title: str | None = None,
    ) -> None:
        resolved_title = tr('Select Continent(s)') if title is None else title
        super().__init__(parent, resolved_title, (420, 360), tr('Select one or more continents:'))
        preselected_normalized = {normalize_continent_name(c) or c for c in preselected_continents if c}
        self._populate_items(CONTINENT_NAMES, existing_continents, preselected_normalized)
        self._add_footer_controls(f" {tr('Select All')}")

    def selected_continents(self) -> list[str]:
        """Return all checked continent names in display order."""
        return self._checked_item_values()


class CountrySelectionDialog(_CheckableSelectionDialog):
    """Searchable multi-select country selection dialog with flag icons and checkboxes."""

    def __init__(
        self,
        parent: QWidget,
        existing_countries: set[str] | None = None,
        *,
        preselected_countries: Iterable[str] = (),
        title: str | None = None,
    ) -> None:
        resolved_title = tr('Select Country / Countries') if title is None else title
        super().__init__(parent, resolved_title, (460, 480), tr('Type to filter by country name or code, and check one or more countries:'))
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText(tr('e.g. Switzerland, US, Russia\u2026'))
        self._search_edit.setClearButtonEnabled(True)
        self._search_edit.textChanged.connect(self._filter_items)
        self._layout.addWidget(self._search_edit)

        preselected_normalized = {normalize_country_name(c) or c for c in preselected_countries if c}
        self._populate_items(COUNTRY_NAMES, existing_countries, preselected_normalized, icon_loader=load_country_flag_icon)
        self._add_footer_controls(f" {tr('Select Visible')}")

    def _filter_items(self, text: str) -> None:
        query = text.strip().casefold()
        for i in range(self._list.count()):
            item = self._list.item(i)
            item.setHidden(bool(query) and query not in item.text().casefold())

    def selected_countries(self) -> list[str]:
        """Return all checked country names in alphabetical order."""
        return self._checked_item_values()


class ComboRuleEditorDialog(QDialog):
    """Dialog for creating or editing a single combo rule."""

    # Ordered internal condition keys -> canonical English display labels
    _CONDITION_SPECS: ClassVar[tuple[tuple[str, str], ...]] = (
        ('continent', 'Continent'),
        ('country', 'Country'),
        ('city', 'City'),
        ('region', 'Region'),
        ('org', 'Organization'),
        ('isp', 'ISP'),
        ('asn', 'ASN'),
        ('as_name', 'AS Name'),
        ('ip_range', 'IP / Range'),
        ('mobile', 'Mobile Connection'),
        ('vpn', 'VPN / Proxy'),
        ('hosting', 'Hosting / Datacenter'),
        ('event', 'Player Event'),
    )
    _CONDITION_LABELS_BY_KEY: ClassVar[dict[str, str]] = dict(_CONDITION_SPECS)

    _TEXT_CONDITION_PLACEHOLDERS: ClassVar[dict[str, str]] = {
        'city': 'Enter city value...',
        'region': 'Enter region value...',
        'org': 'Enter organization value...',
        'isp': 'Enter ISP value...',
        'asn': 'Enter ASN value...',
        'as_name': 'Enter AS name value...',
    }

    _EVENT_SPECS: ClassVar[tuple[tuple[str, str], ...]] = (
        ('join', 'Player Joined'),
        ('rejoin', 'Player Rejoined'),
        ('leave', 'Player Left'),
    )

    def __init__(self, parent: QWidget, rule: ComboRule | None = None) -> None:
        super().__init__(parent)
        self.setWindowModality(Qt.WindowModality.WindowModal)
        self.setWindowTitle(tr('Edit Combo Rule') if rule else tr('New Combo Rule'))
        self.setMinimumWidth(scale_by_ui(800))
        self.setMinimumHeight(scale_by_ui(700))
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, on=False)

        self._condition_rows: list[tuple[QComboBox, QComboBox, QWidget]] = []
        self._editing_rule = rule

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)

        # Rule name
        name_layout = QHBoxLayout()
        name_label = QLabel()
        set_i18n_colon_label(name_label, 'Rule Name')
        name_layout.addWidget(name_label)
        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText(tr('e.g., Block VPN from Russia'))
        if rule:
            self._name_edit.setText(rule.name)
        name_layout.addWidget(self._name_edit)
        main_layout.addLayout(name_layout)

        # Conditions section
        conditions_group = QGroupBox(tr('Conditions (ALL must match)').replace('&', '&&'))
        conditions_group.setStyleSheet(GROUPBOX_STYLE)
        conditions_layout = QVBoxLayout()

        self._conditions_container = QVBoxLayout()
        self._conditions_container.setSpacing(scale_by_ui(8))
        conditions_layout.addLayout(self._conditions_container)

        self._add_condition_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), f" {tr('Add Condition')}")
        self._add_condition_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._add_condition_button.clicked.connect(self._on_add_condition_clicked)
        conditions_layout.addWidget(self._add_condition_button)
        conditions_layout.addStretch(1)

        conditions_group.setLayout(conditions_layout)

        conditions_scroll = QScrollArea()
        conditions_scroll.setWidgetResizable(True)
        conditions_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        conditions_scroll.setWidget(conditions_group)
        main_layout.addWidget(conditions_scroll, stretch=1)

        # Action settings
        action_group = QGroupBox(tr('Actions').replace('&', '&&'))
        action_group.setStyleSheet(GROUPBOX_STYLE)
        action_layout = QVBoxLayout()

        # Notification Settings
        notification_separator = create_section_separator(tr('Notification Settings'))
        action_layout.addWidget(notification_separator)

        voice_row = QHBoxLayout()
        voice_label = QLabel()
        set_i18n_colon_label(voice_label, 'Voice Notifications')
        voice_row.addWidget(voice_label)
        self._voice_combo = QComboBox()
        self._voice_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        populate_voice_combo(self._voice_combo)
        self._voice_combo.setToolTip(tr('Select voice for text-to-speech notifications'))
        if rule:
            set_voice_combo_helper(self._voice_combo, value=rule.voice_notifications)
        voice_row.addWidget(self._voice_combo)
        voice_row.addStretch()
        action_layout.addLayout(voice_row)

        self._msgbox_checkbox = QCheckBox(tr('Show Message Box'))
        self._msgbox_checkbox.setToolTip(tr('Show a message box popup when this detection triggers'))
        self._msgbox_checkbox.setChecked(rule.message_box if rule else False)
        action_layout.addWidget(self._msgbox_checkbox)

        self._logging_checkbox = QCheckBox(tr('Detection Logging'))
        self._logging_checkbox.setToolTip(tr('Log detection events to the detection logging file'))
        self._logging_checkbox.setChecked(rule.logging if rule else False)
        action_layout.addWidget(self._logging_checkbox)

        # Detection Settings
        # -- Detection section (hidden when neighbour interface / detection not supported) --
        detection_section = QWidget()
        detection_section_layout = QVBoxLayout(detection_section)
        detection_section_layout.setContentsMargins(0, 0, 0, 0)

        detection_separator = create_section_separator(tr('Detection Settings'))
        detection_section_layout.addWidget(detection_separator)

        # Duration
        duration_row = QHBoxLayout()
        suspend_label = QLabel()
        set_i18n_colon_label(suspend_label, 'Suspend Mode')
        duration_row.addWidget(suspend_label)
        self._duration_combo = QComboBox()
        self._duration_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        populate_suspend_mode_combo(self._duration_combo)
        duration_row.addWidget(self._duration_combo)
        self._duration_spin = QSpinBox()
        self._duration_spin.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._duration_spin.setRange(1, MAX_SUSPEND_DURATION_SECONDS)
        self._duration_spin.setValue(DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS)
        self._duration_spin.setSuffix(f" {tr('seconds')}")
        self._duration_spin.setVisible(False)
        self._duration_combo.currentIndexChanged.connect(self._on_duration_mode_changed)
        duration_row.addWidget(self._duration_spin)
        duration_row.addStretch()
        detection_section_layout.addLayout(duration_row)

        if rule:
            set_duration_widgets_helper(
                self._duration_combo,
                self._duration_spin,
                rule.duration if rule.protection_enabled else 'Disabled',
            )

        action_layout.addWidget(detection_section)
        if not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture():
            detection_section.setVisible(False)

        action_group.setLayout(action_layout)
        main_layout.addWidget(action_group)

        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        main_layout.addWidget(buttons)

        # Pre-populate conditions from existing rule
        if rule:
            for key, value in rule.conditions.items():
                self._add_condition_row(preset_key=key, preset_value=value)

    def _on_duration_mode_changed(self) -> None:
        self._duration_spin.setVisible(self._duration_combo.currentData() == 'Manual')

    def _on_add_condition_clicked(self) -> None:
        self._add_condition_row()

    def _sync_available_condition_types(self) -> None:
        """Synchronize available condition types and operators across all condition rows."""
        # Pass 1: Ensure dual-operator conditions ('org', 'isp', 'as_name', 'ip_range') use distinct operators ('Is' vs 'Is Not')
        used_operators_by_key: dict[str, set[bool]] = {}
        for type_combo, operator_combo, _ in self._condition_rows:
            key = str(type_combo.currentData() or '')
            if key not in DUAL_OPERATOR_CONDITIONS:
                continue
            used_ops = used_operators_by_key.setdefault(key, set())
            current_is_negated = bool(operator_combo.currentData())
            if current_is_negated in used_ops:
                current_is_negated = not current_is_negated
                with QSignalBlocker(operator_combo):
                    operator_combo.setCurrentIndex(1 if current_is_negated else 0)
            used_ops.add(current_is_negated)

        # Pass 2: Filter exhausted condition types and lock operators when both slots of a dual-operator condition are active
        selected_keys_by_row = [str(type_combo.currentData() or '') for type_combo, _, _ in self._condition_rows]
        for row_idx, (type_combo, operator_combo, _) in enumerate(self._condition_rows):
            current_key = selected_keys_by_row[row_idx]

            op_model = operator_combo.model()
            if isinstance(op_model, QStandardItemModel):
                item_is = op_model.item(0)
                item_is_not = op_model.item(1)
                lock_operator = current_key in DUAL_OPERATOR_CONDITIONS and len(used_operators_by_key.get(current_key, set())) > 1
                if lock_operator:
                    row_is_negated = bool(operator_combo.currentData())
                    item_is.setEnabled(not row_is_negated)
                    item_is_not.setEnabled(row_is_negated)
                else:
                    item_is.setEnabled(True)
                    item_is_not.setEnabled(True)

            available_keys: list[str] = []
            for cond_key, _display_label in self._CONDITION_SPECS:
                max_uses = 2 if cond_key in DUAL_OPERATOR_CONDITIONS else 1
                other_uses = sum(1 for idx, other_key in enumerate(selected_keys_by_row) if idx != row_idx and other_key == cond_key)
                if other_uses < max_uses:
                    available_keys.append(cond_key)

            current_keys = [str(type_combo.itemData(i) or '') for i in range(type_combo.count())]
            if current_keys != available_keys:
                with QSignalBlocker(type_combo):
                    type_combo.clear()
                    for cond_key in available_keys:
                        type_combo.addItem(tr(self._CONDITION_LABELS_BY_KEY[cond_key]), cond_key)
                    type_combo.setCurrentIndex(available_keys.index(current_key) if current_key in available_keys else -1)

        max_total_rows = len(self._CONDITION_SPECS) + len(DUAL_OPERATOR_CONDITIONS)
        self._add_condition_button.setEnabled(len(self._condition_rows) < max_total_rows)

    def _add_condition_row(
        self,
        *,
        preset_key: str | None = None,
        preset_value: str | bool | list[str] | None = None,
    ) -> None:
        """Add a new condition row with type selector and value widget."""
        max_total_rows = len(self._CONDITION_SPECS) + len(DUAL_OPERATOR_CONDITIONS)
        if len(self._condition_rows) >= max_total_rows:
            return
        if preset_key is None and self._condition_rows:
            # Validate existing conditions before adding a new row
            conditions = self._read_conditions()
            if len(conditions) < len(self._condition_rows):
                QMessageBox.warning(
                    self,
                    tr('Validation Error'),
                    tr('Please complete all existing conditions before adding a new one.\n\nEnsure every condition has a type selected and a valid value entered.'),
                )
                return

            for ip_key in ('ip_range', f'{NEGATED_PREFIX}ip_range'):
                ip_range_val = conditions.get(ip_key)
                if ip_range_val is not None and (not isinstance(ip_range_val, str) or not is_valid_ip_range_entry(ip_range_val)):
                    QMessageBox.warning(
                        self,
                        tr('Validation Error'),
                        tr('Please enter a valid IP address or range before adding a new condition.'),
                    )
                    return

        row_layout = QHBoxLayout()
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(scale_by_ui(8))
        type_combo = QComboBox()
        type_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        type_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        type_combo.setPlaceholderText(tr('Select condition type...'))
        for cond_key, display_label in self._CONDITION_SPECS:
            type_combo.addItem(tr(display_label), cond_key)
        type_combo.setCurrentIndex(-1)

        operator_combo = QComboBox()
        operator_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        operator_combo.addItem(tr('Is'), userData=False)
        operator_combo.addItem(tr('Is Not'), userData=True)
        operator_combo.setMinimumWidth(scale_by_ui(85))
        operator_combo.setToolTip(tr('Choose whether the condition must match (Is) or must not match (Is Not)'))
        operator_combo.currentIndexChanged.connect(self._sync_available_condition_types)

        value_stack = QWidget()
        value_layout = QVBoxLayout(value_stack)
        value_layout.setContentsMargins(0, 0, 0, 0)

        # Default: text input
        text_edit = QLineEdit()
        text_edit.setPlaceholderText(tr('Enter value...'))
        value_layout.addWidget(text_edit)

        def on_type_changed(_index: int = -1) -> None:
            key = str(type_combo.currentData() or '')
            is_negatable = key in NEGATABLE_CONDITIONS
            operator_combo.setVisible(is_negatable)
            if not is_negatable:
                with QSignalBlocker(operator_combo):
                    operator_combo.setCurrentIndex(0)
            elif key in DUAL_OPERATOR_CONDITIONS:
                other_ops = {
                    bool(other_op.currentData())
                    for other_type, other_op, _ in self._condition_rows
                    if other_op is not operator_combo and str(other_type.currentData() or '') == key
                }
                current_is_negated = bool(operator_combo.currentData())
                if current_is_negated in other_ops and (not current_is_negated) not in other_ops:
                    with QSignalBlocker(operator_combo):
                        operator_combo.setCurrentIndex(0 if current_is_negated else 1)
            # Clear and rebuild value widget
            while value_layout.count():
                child = value_layout.takeAt(0)
                if child is not None:
                    widget = child.widget()
                    if widget is not None:
                        widget.setParent(None)
                        widget.deleteLater()

            if key in ('mobile', 'vpn', 'hosting'):
                bool_combo = QComboBox()
                bool_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
                bool_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                bool_combo.addItem(tr('Yes'), userData=True)
                bool_combo.addItem(tr('No'), userData=False)
                value_layout.addWidget(bool_combo)
            elif key == 'event':
                events_widget = QFrame()
                events_widget.setObjectName('EventsContainer')
                events_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
                events_widget.setStyleSheet(
                    themed_qss('#EventsContainer { background-color: #1e1e1e; border: 1px solid #3e3e42; border-radius: 4px; min-height: 24px; }'),
                )
                events_layout = QHBoxLayout(events_widget)
                events_layout.setContentsMargins(12, 4, 12, 4)

                events_layout.addStretch()
                for i, (event_key, display_name) in enumerate(self._EVENT_SPECS):
                    checkbox = QCheckBox(tr(display_name))
                    checkbox.setProperty('event_key', event_key)
                    events_layout.addWidget(checkbox)
                    if i < len(self._EVENT_SPECS) - 1:
                        events_layout.addStretch()
                events_layout.addStretch()

                value_layout.addWidget(events_widget)
            elif key in ('continent', 'country'):
                picker_widget = self._create_multi_select_picker_widget(key)
                value_layout.addWidget(picker_widget)
            elif key == 'ip_range':
                ip_widget = QWidget()
                ip_layout = QHBoxLayout(ip_widget)
                ip_layout.setContentsMargins(0, 0, 0, 0)
                ip_layout.setSpacing(6)

                ip_edit = QLineEdit()
                ip_edit.setPlaceholderText(tr('e.g. 1.2.3.4, 192.168.1.0/24, 10.0.0.1-10.0.0.50, or 1.2.3.*'))
                ip_layout.addWidget(ip_edit, stretch=1)

                builder_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), '')
                builder_button.setToolTip(tr('Open IP Range Builder'))
                builder_button.setMaximumWidth(scale_by_ui(40))
                builder_button.setCursor(Qt.CursorShape.PointingHandCursor)

                def open_builder() -> None:
                    dialog = IPRangeBuilderDialog(self, initial_entry=ip_edit.text().strip() or None)
                    if dialog.exec() == QDialog.DialogCode.Accepted:
                        entry = dialog.result_entry()
                        if entry:
                            ip_edit.setText(entry)

                builder_button.clicked.connect(open_builder)
                ip_layout.addWidget(builder_button)

                value_layout.addWidget(ip_widget)
            else:
                new_edit = QLineEdit()
                placeholder_key = self._TEXT_CONDITION_PLACEHOLDERS.get(key, 'Enter value...')
                new_edit.setPlaceholderText(tr(placeholder_key))
                value_layout.addWidget(new_edit)
            self._sync_available_condition_types()

        type_combo.currentIndexChanged.connect(on_type_changed)

        remove_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), '')
        remove_button.setMaximumWidth(scale_by_ui(40))
        remove_button.setCursor(Qt.CursorShape.PointingHandCursor)

        row_widget = QWidget()
        row_layout.addWidget(type_combo, stretch=1)
        row_layout.addWidget(operator_combo)
        row_layout.addWidget(value_stack, stretch=2)
        row_layout.addWidget(remove_button)
        row_widget.setLayout(row_layout)

        self._conditions_container.addWidget(row_widget)
        self._condition_rows.append((type_combo, operator_combo, value_stack))
        self._sync_available_condition_types()

        def remove_row() -> None:
            self._condition_rows.remove((type_combo, operator_combo, value_stack))
            row_widget.deleteLater()
            self._sync_available_condition_types()

        remove_button.clicked.connect(remove_row)

        # Set preset values if provided
        if preset_key is not None:
            base_key, is_negated = split_condition_key(preset_key)
            if is_negated and base_key in NEGATABLE_CONDITIONS:
                with QSignalBlocker(operator_combo):
                    operator_combo.setCurrentIndex(1)
            preset_index = type_combo.findData(base_key)
            if preset_index >= 0:
                type_combo.setCurrentIndex(preset_index)
            # Now set the value
            if base_key in ('mobile', 'vpn', 'hosting') and isinstance(preset_value, bool):
                bool_combo_widget: QComboBox | None = value_stack.findChild(QComboBox)
                if bool_combo_widget is not None:
                    index = bool_combo_widget.findData(preset_value)
                    if index >= 0:
                        bool_combo_widget.setCurrentIndex(index)
            elif base_key == 'event' and isinstance(preset_value, list):
                events_widget: QWidget | None = value_stack.findChild(QWidget)
                if events_widget is not None:
                    for checkbox in events_widget.findChildren(QCheckBox):
                        event_key = str(checkbox.property('event_key') or '')
                        checkbox.setChecked(event_key in preset_value)
            elif base_key in ('continent', 'country') and isinstance(preset_value, (str, list)):
                raw_items = [preset_value] if isinstance(preset_value, str) else list(preset_value)
                normalizer: Callable[[str], str | None] = normalize_continent_name if base_key == 'continent' else normalize_country_name
                normalized_items = [normalizer(item) or item.strip() for item in raw_items if item.strip()]
                self._set_multi_select_picker_values(value_stack, normalized_items)
            elif isinstance(preset_value, str):
                line_edit_widget: QLineEdit | None = value_stack.findChild(QLineEdit)
                if line_edit_widget is not None:
                    line_edit_widget.setText(preset_value)

    def _validate_and_accept(self) -> None:
        """Validate rule data and accept dialog."""
        name = self._name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, tr('Validation Error'), tr('Rule name is required.'))
            return

        conditions = self._read_conditions()
        if not conditions:
            QMessageBox.warning(self, tr('Validation Error'), tr('At least one condition is required.'))
            return
        if len(conditions) < len(self._condition_rows):
            QMessageBox.warning(
                self,
                tr('Validation Error'),
                tr('All condition rows must have a condition type selected and a valid value entered.'),
            )
            return

        for ip_key in ('ip_range', f'{NEGATED_PREFIX}ip_range'):
            ip_range_val = conditions.get(ip_key)
            if ip_range_val is not None and (not isinstance(ip_range_val, str) or not is_valid_ip_range_entry(ip_range_val)):
                QMessageBox.warning(
                    self,
                    tr('Validation Error'),
                    tr(
                        'Invalid IP / Range: {value}\n\n'
                        'Please enter a valid IP address, CIDR subnet (e.g. 192.168.1.0/24), '
                        'range (e.g. 192.168.1.1-192.168.1.100), or wildcard (e.g. 192.168.1.*).',
                        value=ip_range_val,
                    ),
                )
                return

        # Require at least one IP condition if event condition is present
        has_event = 'event' in conditions
        has_ip = bool(conditions.keys() - {'event'})
        if has_event and not has_ip:
            QMessageBox.warning(
                self,
                tr('Validation Error'),
                tr('Rules with an event condition must also have at least one IP-based condition.'),
            )
            return

        self.accept()

    def _read_conditions(self) -> dict[str, str | bool | list[str]]:
        """Read conditions from the UI rows."""
        conditions: dict[str, str | bool | list[str]] = {}
        seen_effective_keys: set[str] = set()
        seen_single_base_keys: set[str] = set()
        for type_combo, operator_combo, value_stack in self._condition_rows:
            base_key = type_combo.currentData()
            if not isinstance(base_key, str) or not base_key:
                continue
            is_negated = bool(operator_combo.currentData()) and base_key in NEGATABLE_CONDITIONS
            effective_key = f'{NEGATED_PREFIX}{base_key}' if is_negated else base_key
            if effective_key in seen_effective_keys or (base_key not in DUAL_OPERATOR_CONDITIONS and base_key in seen_single_base_keys):
                continue

            if base_key in ('mobile', 'vpn', 'hosting'):
                bool_combo_widget: QComboBox | None = value_stack.findChild(QComboBox)
                if bool_combo_widget is not None:
                    conditions[effective_key] = bool(bool_combo_widget.currentData())
                    seen_effective_keys.add(effective_key)
                    seen_single_base_keys.add(base_key)
            elif base_key == 'event':
                selected = self._read_event_checkboxes(value_stack)
                if selected:
                    conditions[effective_key] = selected
                    seen_effective_keys.add(effective_key)
                    seen_single_base_keys.add(base_key)
            elif base_key in ('continent', 'country'):
                selected_items = self._read_multi_select_picker_values(value_stack)
                if selected_items:
                    conditions[effective_key] = selected_items if len(selected_items) > 1 else selected_items[0]
                    seen_effective_keys.add(effective_key)
                    seen_single_base_keys.add(base_key)
            else:
                line_edit_widget: QLineEdit | None = value_stack.findChild(QLineEdit)
                if line_edit_widget is not None:
                    trimmed_text = line_edit_widget.text().strip()
                    if trimmed_text:
                        conditions[effective_key] = trimmed_text
                        seen_effective_keys.add(effective_key)
                        seen_single_base_keys.add(base_key)
        return conditions

    def _read_event_checkboxes(self, value_stack: QWidget) -> list[str]:
        """Read selected event checkboxes from a value stack widget."""
        events_widget: QWidget | None = value_stack.findChild(QWidget)
        if events_widget is None:
            return []
        selected: list[str] = []
        for checkbox in events_widget.findChildren(QCheckBox):
            if checkbox.isChecked():
                event_key = str(checkbox.property('event_key') or '')
                if event_key:
                    selected.append(event_key)
        return selected

    def _create_multi_select_picker_widget(self, key: str) -> QWidget:
        """Build a clickable read-only line edit + picker button widget for continent/country selection."""
        picker_widget = QWidget()
        picker_layout = QHBoxLayout(picker_widget)
        picker_layout.setContentsMargins(0, 0, 0, 0)
        picker_layout.setSpacing(6)

        def open_picker() -> None:
            current_raw = display_edit.property('selected_items')
            current_items = [item for item in cast('list[object]', current_raw) if isinstance(item, str)] if isinstance(current_raw, list) else []
            if key == 'continent':
                continent_dialog = ContinentSelectionDialog(self, preselected_continents=current_items)
                if continent_dialog.exec() == QDialog.DialogCode.Accepted:
                    chosen = continent_dialog.selected_continents()
                    display_edit.setProperty('selected_items', chosen)
                    display_edit.setText(', '.join(chosen))
            else:
                country_dialog = CountrySelectionDialog(self, preselected_countries=current_items)
                if country_dialog.exec() == QDialog.DialogCode.Accepted:
                    chosen = country_dialog.selected_countries()
                    display_edit.setProperty('selected_items', chosen)
                    display_edit.setText(', '.join(chosen))

        display_edit = _ClickablePickerLineEdit(open_picker)
        if key == 'continent':
            display_edit.setPlaceholderText(tr('Select continent(s)...'))
            button_tooltip = tr('Select Continent(s)')
        else:
            display_edit.setPlaceholderText(tr('Select country/countries...'))
            button_tooltip = tr('Select Country / Countries')
        display_edit.setToolTip(button_tooltip)
        display_edit.setProperty('selected_items', [])
        picker_layout.addWidget(display_edit, stretch=1)

        picker_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), '')
        picker_button.setToolTip(button_tooltip)
        picker_button.setMaximumWidth(scale_by_ui(40))
        picker_button.setCursor(Qt.CursorShape.PointingHandCursor)
        picker_button.clicked.connect(open_picker)
        picker_layout.addWidget(picker_button)
        return picker_widget

    @staticmethod
    def _set_multi_select_picker_values(value_stack: QWidget, items: list[str]) -> None:
        """Populate a multi-select picker widget with *items*."""
        display_edit: QLineEdit | None = value_stack.findChild(QLineEdit)
        if display_edit is not None:
            display_edit.setProperty('selected_items', list(items))
            display_edit.setText(', '.join(items))

    @staticmethod
    def _read_multi_select_picker_values(value_stack: QWidget) -> list[str]:
        """Read the selected items list from a multi-select picker widget."""
        display_edit: QLineEdit | None = value_stack.findChild(QLineEdit)
        if display_edit is None:
            return []
        raw = display_edit.property('selected_items')
        if isinstance(raw, list):
            return [item for item in cast('list[object]', raw) if isinstance(item, str) and item]
        return []

    def get_rule(self) -> ComboRule:
        """Build a ComboRule from dialog state."""
        return ComboRule(
            name=self._name_edit.text().strip(),
            enabled=self._editing_rule.enabled if self._editing_rule else True,
            conditions=self._read_conditions(),
            protection_enabled=self._duration_combo.currentData() not in ('Disabled', None),
            duration=read_duration_widgets_helper(self._duration_combo, self._duration_spin),
            voice_notifications=read_voice_combo_helper(self._voice_combo),
            logging=self._logging_checkbox.isChecked(),
            message_box=self._msgbox_checkbox.isChecked(),
        )
