"""Detections Manager dialog for configuring advanced per-detection rules."""

import json
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast, override

from pydantic import TypeAdapter, ValidationError
from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtGui import QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.background import clear_voice_notification_queue, retrigger_detections_scan
from session_sniffer.constants.local import COMBO_RULES_PATH, DETECTIONS_JSON_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._combo_rule_editor import (
    ComboRuleEditorDialog,
    read_duration_widgets_helper,
    read_voice_combo_helper,
    set_duration_widgets_helper,
    set_voice_combo_helper,
)
from session_sniffer.guis._detections_manager_tabs import DetectionsManagerTabsMixin
from session_sniffer.guis._dialog_mixins import (
    equalize_button_sizes,
    setup_tab_reset_buttons,
)
from session_sniffer.guis.country_data import normalize_continent_name, normalize_country_name
from session_sniffer.guis.delegates import ComboRuleCardDelegate
from session_sniffer.guis.live_language import register_language_refresh
from session_sniffer.guis.stylesheets import (
    COMBO_RULES_LIST_STYLE,
    DESC_LABEL_STYLESHEET,
    DETECTIONS_MANAGER_HEADER_STYLESHEET,
    DIALOG_BUTTON_STYLESHEET,
    SVG_ICON_CONTEXT_MENU_STYLESHEET,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.utils import (
    consume_maximize_on_show,
    resize_window_for_screen,
    scale_by_ui,
    set_dialog_window_flags,
)
from session_sniffer.i18n import tr, tr_plural
from session_sniffer.models.combo_rules import ComboRule
from session_sniffer.models.detections import DetectionsFile
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS

if TYPE_CHECKING:
    from PySide6.QtCore import QPoint
    from PySide6.QtGui import QKeyEvent, QShowEvent
    from PySide6.QtWidgets import QCheckBox, QSpinBox

    from session_sniffer.models.player import Player


_COMBO_RULES_TAB_INDEX = 3
_STANDARD_DETECTION_PREFIXES: tuple[str, ...] = (
    'mobile',
    'vpn',
    'hosting',
    'continent',
    'country',
    'isp',
    'asn',
    'player_join',
    'player_rejoin',
    'player_leave',
)
_ALL_DETECTION_PREFIXES: tuple[str, ...] = (*_STANDARD_DETECTION_PREFIXES, 'gta5_relay')
_DIRECT_DURATION_PREFIXES: frozenset[str] = frozenset({'player_join', 'player_rejoin', 'player_leave', 'gta5_relay'})


def _detection_setting_attrs(prefix: str) -> tuple[str, str]:
    """Return `(enabled_attr, duration_attr)` on `GUIDetectionSettings` for *prefix*."""
    if prefix in _DIRECT_DURATION_PREFIXES:
        return f'{prefix}_enabled', f'{prefix}_duration'
    return f'{prefix}_suspend_enabled', f'{prefix}_suspend_duration'


class DetectionsManagerDialog(DetectionsManagerTabsMixin, QDialog):
    """Comprehensive detections manager with VPN, IP range, and advanced threat detection capabilities."""

    _instance: ClassVar[DetectionsManagerDialog | None] = None

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Detections Manager dialog."""
        super().__init__(parent)
        DetectionsManagerDialog._instance = self
        self.destroyed.connect(lambda: setattr(DetectionsManagerDialog, '_instance', None) if DetectionsManagerDialog._instance is self else None)
        self._loading_settings = False
        self._init_tab_i18n_tracking()
        self.setWindowTitle(tr('{title} - Detections Manager', title=TITLE))
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(720), scale_by_ui(500))
        resize_window_for_screen(self)

        # Static widget references (per-rule controls are accessed dynamically via prefix)
        self.continent_list: QListWidget
        self.country_list: QListWidget
        self.isp_list: QListWidget
        self.asn_list: QListWidget
        self._relay_filter_warning: QWidget
        self.gta5_relay_duration_combo: QComboBox
        self._combo_rules_list: QListWidget

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        self._header_label = QLabel(tr('Advanced Detection & Security Manager'))
        self._header_label.setStyleSheet(DETECTIONS_MANAGER_HEADER_STYLESHEET)
        self._header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._header_label)

        # Tabs
        self._tabs = QTabWidget()
        self._tab_title_keys: list[str] = ['Player Events', 'Network-Based', 'Geography-Based', 'Combo Rules']
        self._tabs.addTab(self.create_player_events_tab(), QIcon(str(ICONS_DIR_PATH / 'user-round.svg')), tr('Player Events'))
        self._tabs.addTab(self.create_network_based_tab(), QIcon(str(ICONS_DIR_PATH / 'ethernet-port.svg')), tr('Network-Based'))
        self._tabs.addTab(self.create_geo_based_tab(), QIcon(str(ICONS_DIR_PATH / 'globe.svg')), tr('Geography-Based'))
        self._tabs.addTab(self.create_combo_rules_tab(), QIcon(str(ICONS_DIR_PATH / 'link.svg')), tr('Combo Rules'))
        if Settings.is_gta5_feature_set():
            self._tab_title_keys.append('GTA5 Relays')
            self._tabs.addTab(self.create_gta5_relays_tab(), QIcon(str(ICONS_DIR_PATH / 'route.svg')), tr('GTA5 Relays'))
        layout.addWidget(self._tabs)

        # Bottom buttons
        self._button_row = QHBoxLayout()

        self._import_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'import.svg')), f" {tr('Import')}")
        self._import_button.setToolTip(tr('Import detection settings from a JSON file'))
        self._import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._import_button.clicked.connect(self._import_detections)
        self._button_row.addWidget(self._import_button)

        self._export_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), f" {tr('Export')}")
        self._export_button.setToolTip(tr('Export detection settings to a JSON file'))
        self._export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._export_button.clicked.connect(self._export_detections)
        self._button_row.addWidget(self._export_button)

        self._reset_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'rotate-ccw.svg')), f" {tr('Reset all…')}")
        self._reset_button.setToolTip(tr('Reset all detection settings to defaults'))
        setup_tab_reset_buttons(
            self._button_row,
            self._reset_button,
            self._reset_to_defaults,
            self._reset_current_tab,
            reset_tab_tooltip=tr('Reset current tab settings to their default values'),
        )
        last_item = self._button_row.itemAt(self._button_row.count() - 1)
        last_widget = last_item.widget() if last_item is not None else None
        self._reset_tab_button: QPushButton | None = last_widget if isinstance(last_widget, QPushButton) else None

        self._close_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'x.svg')), f" {tr('Close')}")
        self._close_button.setToolTip(tr('Close the Detections Manager'))
        self._close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        self._close_button.clicked.connect(self.close)
        self._button_row.addWidget(self._close_button)

        equalize_button_sizes(self._button_row)

        layout.addLayout(self._button_row)

        self.load_current_settings()
        self.refresh_detection_availability()
        if hasattr(self, 'gta5_relay_duration_combo'):
            self.gta5_relay_duration_combo.currentIndexChanged.connect(self._on_gta5_relay_suspend_mode_changed)
        self._connect_auto_save_signals()
        register_language_refresh(self, self._retranslate)

    def _retranslate(self) -> None:
        """Refresh all UI strings when the active application language changes."""
        self.setWindowTitle(tr('{title} - Detections Manager', title=TITLE))
        self._header_label.setText(tr('Advanced Detection & Security Manager'))
        for index, title_key in enumerate(self._tab_title_keys):
            self._tabs.setTabText(index, tr(title_key))
        self._retranslate_tabs()

        self._combo_desc_label.setText(
            tr(
                'Combine multiple conditions into a single rule using AND logic. '
                'All conditions in a rule must match for it to trigger. '
                'Rules with an event condition require at least one IP-based condition.',
            ),
        )
        self._combo_add_button.setText(f" {tr('Add Rule')}")
        self._combo_edit_button.setText(f" {tr('Edit')}")
        self._combo_export_button.setToolTip(tr('Export the selected combo rule(s) to a JSON file'))
        self._combo_clear_button.setText(f" {tr('Clear All')}")
        self._update_combo_rule_buttons()
        if viewport := self._combo_rules_list.viewport():
            viewport.update()

        self._import_button.setText(f" {tr('Import')}")
        self._import_button.setToolTip(tr('Import detection settings from a JSON file'))
        self._export_button.setText(f" {tr('Export')}")
        self._export_button.setToolTip(tr('Export detection settings to a JSON file'))
        self._reset_button.setText(f" {tr('Reset all…')}")
        self._reset_button.setToolTip(tr('Reset all detection settings to defaults'))
        if self._reset_tab_button is not None:
            self._reset_tab_button.setText(f" {tr('Reset')}")
            self._reset_tab_button.setToolTip(tr('Reset current tab settings to their default values'))
        self._close_button.setText(f" {tr('Close')}")
        self._close_button.setToolTip(tr('Close the Detections Manager'))

        for index in range(self._button_row.count()):
            item = self._button_row.itemAt(index)
            widget = item.widget() if item is not None else None
            if isinstance(widget, QPushButton):
                widget.setMinimumWidth(0)
                widget.setMinimumHeight(0)
        equalize_button_sizes(self._button_row)

    @classmethod
    def refresh_if_open(cls) -> None:
        """Reload widget state if a DetectionsManagerDialog instance is currently visible."""
        if cls._instance is not None and cls._instance.isVisible():
            cls._instance.load_current_settings()

    # ------------------------------------------------------------------
    # Detection support restrictions
    # ------------------------------------------------------------------

    def refresh_detection_availability(self) -> None:
        """Refresh detection action visibility based on current runtime support."""
        is_supported = Settings.is_gta5_feature_set() and CaptureState.is_local_capture()
        for prefix in _ALL_DETECTION_PREFIXES:
            if not hasattr(self, f'{prefix}_detection_section'):
                continue
            detection_section = cast('QWidget', getattr(self, f'{prefix}_detection_section'))
            detection_section.setVisible(is_supported)

    # ------------------------------------------------------------------
    # Settings load / save
    # ------------------------------------------------------------------

    @staticmethod
    def _populate_unique_text_list(list_widget: QListWidget, values: list[str]) -> None:
        """Clear *list_widget* and populate it with unique strings from *values* preserving order."""
        list_widget.clear()
        seen: set[str] = set()
        for value in values:
            if value not in seen:
                seen.add(value)
                list_widget.addItem(value)

    def _load_prefix_widgets(self, prefix: str) -> None:
        """Load duration, voice, logging, and message-box widgets for a single detection *prefix*."""
        enabled_attr, duration_attr = _detection_setting_attrs(prefix)
        is_enabled = bool(getattr(GUIDetectionSettings, enabled_attr))
        duration = getattr(GUIDetectionSettings, duration_attr) if is_enabled else 'Disabled'
        set_duration_widgets_helper(
            getattr(self, f'{prefix}_duration_combo'),
            getattr(self, f'{prefix}_duration_spin'),
            duration,
        )
        set_voice_combo_helper(getattr(self, f'{prefix}_voice_combo'), value=getattr(GUIDetectionSettings, f'{prefix}_voice_notifications'))
        getattr(self, f'{prefix}_logging_checkbox').setChecked(bool(getattr(GUIDetectionSettings, f'{prefix}_logging')))
        getattr(self, f'{prefix}_msgbox_checkbox').setChecked(bool(getattr(GUIDetectionSettings, f'{prefix}_message_box')))

    def _save_prefix_widgets(self, prefix: str) -> None:
        """Save duration, voice, logging, and message-box widgets for a single detection *prefix*."""
        enabled_attr, duration_attr = _detection_setting_attrs(prefix)
        duration_combo = cast('QComboBox', getattr(self, f'{prefix}_duration_combo'))
        duration_spin = cast('QSpinBox', getattr(self, f'{prefix}_duration_spin'))
        is_enabled = duration_combo.currentData() not in ('Disabled', None)
        setattr(GUIDetectionSettings, enabled_attr, is_enabled)
        if is_enabled:
            setattr(GUIDetectionSettings, duration_attr, read_duration_widgets_helper(duration_combo, duration_spin))
        setattr(GUIDetectionSettings, f'{prefix}_voice_notifications', read_voice_combo_helper(getattr(self, f'{prefix}_voice_combo')))
        setattr(GUIDetectionSettings, f'{prefix}_logging', getattr(self, f'{prefix}_logging_checkbox').isChecked())
        setattr(GUIDetectionSettings, f'{prefix}_message_box', getattr(self, f'{prefix}_msgbox_checkbox').isChecked())

    def load_current_settings(self) -> None:
        """Read GUIDetectionSettings and populate all widgets."""
        self._loading_settings = True
        try:
            self.continent_list.clear()
            seen_continents: set[str] = set()
            for continent in GUIDetectionSettings.continent_detection_list:
                canonical_continent = normalize_continent_name(continent) or continent
                if canonical_continent not in seen_continents:
                    seen_continents.add(canonical_continent)
                    self._add_continent_item(canonical_continent)

            self.country_list.clear()
            seen_countries: set[str] = set()
            for country in GUIDetectionSettings.country_detection_list:
                canonical_country = normalize_country_name(country) or country
                if canonical_country not in seen_countries:
                    seen_countries.add(canonical_country)
                    self._add_country_item(canonical_country)
            self._populate_unique_text_list(self.isp_list, GUIDetectionSettings.isp_detection_list)
            self._populate_unique_text_list(self.asn_list, GUIDetectionSettings.asn_detection_list)

            for prefix in _STANDARD_DETECTION_PREFIXES:
                self._load_prefix_widgets(prefix)

            if hasattr(self, 'gta5_relay_duration_combo'):
                self._relay_filter_warning.setVisible(any(name in Settings.capture_block_third_party_servers for name in ('TAKETWO_INTERACTIVE', 'MICROSOFT')))
                self._load_prefix_widgets('gta5_relay')

            # Combo Rules
            self.refresh_combo_rules_list()
        finally:
            self._loading_settings = False

    def _connect_auto_save_signals(self) -> None:
        """Connect all detection widget change signals to auto-save."""
        prefixes: tuple[str, ...] = _ALL_DETECTION_PREFIXES if hasattr(self, 'gta5_relay_duration_combo') else _STANDARD_DETECTION_PREFIXES

        for prefix in prefixes:
            cast('QComboBox', getattr(self, f'{prefix}_duration_combo')).currentIndexChanged.connect(self._auto_save_detections)
            cast('QSpinBox', getattr(self, f'{prefix}_duration_spin')).valueChanged.connect(self._auto_save_detections)
            cast('QComboBox', getattr(self, f'{prefix}_voice_combo')).currentIndexChanged.connect(self._auto_save_detections)
            cast('QCheckBox', getattr(self, f'{prefix}_logging_checkbox')).toggled.connect(self._auto_save_detections)
            cast('QCheckBox', getattr(self, f'{prefix}_msgbox_checkbox')).toggled.connect(self._auto_save_detections)

    @override
    def _auto_save_detections(self) -> None:
        """Read widgets, write GUIDetectionSettings, and persist to detections.json in real time."""
        if self._loading_settings:
            return

        # Clear voice queue if any detection's voice notification was newly disabled
        for prefix in _ALL_DETECTION_PREFIXES:
            if not hasattr(self, f'{prefix}_voice_combo'):
                continue
            if getattr(GUIDetectionSettings, f'{prefix}_voice_notifications') and getattr(self, f'{prefix}_voice_combo').currentData() in ('Disabled', None):
                clear_voice_notification_queue()
                break

        self._save_widgets_to_singleton()
        GUIDetectionSettings.export_to_file(DETECTIONS_JSON_PATH)
        retrigger_detections_scan()

    def _export_detections(self) -> None:
        """Export current detection settings (including combo rules) to a JSON file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            tr('Export Detection Settings'),
            'detections.json',
            tr('JSON Files (*.json);;All Files (*.*)'),
        )
        if file_path:
            # Save current widget state to GUIDetectionSettings first
            self._save_widgets_to_singleton()
            # Build combined export: standard detections + combo rules
            model = GUIDetectionSettings.to_model()
            model.combo_rules = list(ComboRulesManager.rules)
            target = Path(file_path)
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(model.model_dump_json(indent=4, by_alias=True), encoding='utf-8')
            except OSError as e:
                QMessageBox.critical(self, tr('Export Error'), tr('Failed to export settings:\n{error}', error=e))
                return
            QMessageBox.information(self, TITLE, tr('Detection settings exported successfully.'))

    def _import_detections(self) -> None:
        """Import detection settings (or a standalone combo-rules list) from a JSON file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            tr('Import Detection Settings'),
            '',
            tr('JSON Files (*.json);;All Files (*.*)'),
        )
        if not file_path:
            return
        source = Path(file_path)
        try:
            raw_text = source.read_text(encoding='utf-8')
            parsed = json.loads(raw_text)
            if isinstance(parsed, list):
                imported_rules = TypeAdapter(list[ComboRule]).validate_python(parsed)
                start_index = len(ComboRulesManager.rules)
                ComboRulesManager.rules.extend(imported_rules)
                ComboRulesManager.save_to_file(COMBO_RULES_PATH)
                self.refresh_combo_rules_list(selected_rows=list(range(start_index, len(ComboRulesManager.rules))))
                if any(rule.enabled for rule in imported_rules):
                    retrigger_detections_scan()
                QMessageBox.information(
                    self,
                    TITLE,
                    tr_plural('Imported {count} combo rule successfully.', 'Imported {count} combo rules successfully.', len(imported_rules)),
                )
                return
            GUIDetectionSettings.import_from_file(source)
            GUIDetectionSettings.export_to_file(DETECTIONS_JSON_PATH)
        except (ValidationError, OSError, json.JSONDecodeError) as e:
            QMessageBox.critical(self, tr('Import Error'), tr('Failed to import settings:\n{error}', error=e))
            return
        self.load_current_settings()
        retrigger_detections_scan()
        QMessageBox.information(self, TITLE, tr('Detection settings imported successfully.'))

    def _reset_tab_to_defaults(self, prefixes: tuple[str, ...]) -> None:
        """Reset all detection widgets for the given *prefixes* to their default values and persist."""
        self._loading_settings = True
        try:
            for prefix in prefixes:
                set_duration_widgets_helper(
                    getattr(self, f'{prefix}_duration_combo'),
                    getattr(self, f'{prefix}_duration_spin'),
                    'Disabled',
                )
                getattr(self, f'{prefix}_duration_spin').setValue(DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS)
                _, duration_attr = _detection_setting_attrs(prefix)
                setattr(GUIDetectionSettings, duration_attr, 'Auto')
                set_voice_combo_helper(getattr(self, f'{prefix}_voice_combo'), value=False)
                getattr(self, f'{prefix}_logging_checkbox').setChecked(False)
                getattr(self, f'{prefix}_msgbox_checkbox').setChecked(False)
                if hasattr(self, f'{prefix}_list'):
                    getattr(self, f'{prefix}_list').clear()
        finally:
            self._loading_settings = False
        self._auto_save_detections()

    def _reset_current_tab(self) -> None:
        """Reset the current tab's detection widgets to their default values after confirmation."""
        current_index = self._tabs.currentIndex()
        if current_index == _COMBO_RULES_TAB_INDEX:
            self._clear_combo_rules()
            return
        index_to_prefixes: dict[int, tuple[str, ...]] = {
            0: ('player_join', 'player_rejoin', 'player_leave'),
            1: ('mobile', 'vpn', 'hosting'),
            2: ('continent', 'country', 'isp', 'asn'),
            4: ('gta5_relay',),
        }
        prefixes = index_to_prefixes.get(current_index)
        if prefixes is None:
            return
        tab_name = self._tabs.tabText(current_index)
        result = QMessageBox.question(
            self,
            TITLE,
            tr('Reset {tab} detection settings to defaults?', tab=tab_name),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return
        self._reset_tab_to_defaults(prefixes)

    def _reset_to_defaults(self) -> None:
        """Reset all detection widget values to defaults after user confirmation."""
        result = QMessageBox.question(
            self,
            TITLE,
            tr('Reset all detection settings to defaults?\n\nThis will clear all current values in the editor.'),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        if any(getattr(GUIDetectionSettings, f'{prefix}_voice_notifications') for prefix in _ALL_DETECTION_PREFIXES):
            clear_voice_notification_queue()
        self._clear_combo_rules(confirm=False)
        GUIDetectionSettings.reset_to_defaults()
        prefixes: tuple[str, ...] = _ALL_DETECTION_PREFIXES if hasattr(self, 'gta5_relay_duration_combo') else _STANDARD_DETECTION_PREFIXES
        self._reset_tab_to_defaults(prefixes)

    def _save_widgets_to_singleton(self) -> None:
        """Write current widget state to GUIDetectionSettings without persisting to disk."""
        GUIDetectionSettings.continent_detection_list = [
            item.data(Qt.ItemDataRole.UserRole) for i in range(self.continent_list.count()) if (item := self.continent_list.item(i))
        ]
        GUIDetectionSettings.country_detection_list = [item.data(Qt.ItemDataRole.UserRole) for i in range(self.country_list.count()) if (item := self.country_list.item(i))]
        GUIDetectionSettings.isp_detection_list = [item.text() for i in range(self.isp_list.count()) if (item := self.isp_list.item(i))]
        GUIDetectionSettings.asn_detection_list = [item.text() for i in range(self.asn_list.count()) if (item := self.asn_list.item(i))]

        for prefix in _STANDARD_DETECTION_PREFIXES:
            self._save_prefix_widgets(prefix)

        if hasattr(self, 'gta5_relay_duration_combo'):
            self._save_prefix_widgets('gta5_relay')

    # ------------------------------------------------------------------
    # Combo Rules tab & management
    # ------------------------------------------------------------------

    def create_combo_rules_tab(self) -> QWidget:
        """Create the combo rules tab with rule list and management buttons."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        desc = QLabel(
            tr(
                'Combine multiple conditions into a single rule using AND logic. '
                'All conditions in a rule must match for it to trigger. '
                'Rules with an event condition require at least one IP-based condition.',
            ),
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(DESC_LABEL_STYLESHEET)
        self._combo_desc_label = desc
        layout.addWidget(desc)

        # Rule list
        self._combo_rules_list = QListWidget()
        self._combo_rules_list.setStyleSheet(COMBO_RULES_LIST_STYLE)
        self._combo_rules_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self._combo_rules_list.setResizeMode(QListWidget.ResizeMode.Adjust)
        self._combo_rules_list.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self._combo_rules_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._combo_rules_list.setMouseTracking(True)
        self._combo_rules_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._combo_rules_list.customContextMenuRequested.connect(self._on_combo_rules_context_menu)
        self._combo_rules_list.setItemDelegate(
            ComboRuleCardDelegate(
                self._combo_rules_list,
                lambda row: ComboRulesManager.rules[row] if 0 <= row < len(ComboRulesManager.rules) else None,
                lambda: Settings.is_gta5_feature_set() and CaptureState.is_local_capture(),
                scale_by_ui,
            ),
        )
        QShortcut(QKeySequence('Delete'), self._combo_rules_list, context=Qt.ShortcutContext.WidgetShortcut).activated.connect(self._remove_combo_rule)
        layout.addWidget(self._combo_rules_list, stretch=1)

        # Buttons row
        button_layout = QHBoxLayout()

        add_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), f" {tr('Add Rule')}")
        add_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_button.clicked.connect(self._add_combo_rule)
        self._combo_add_button = add_button
        button_layout.addWidget(add_button)

        self._combo_toggle_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'toggle-right.svg')), f" {tr('Toggle State')}")
        self._combo_toggle_button.setEnabled(False)
        self._combo_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_toggle_button.setMinimumWidth(scale_by_ui(125))
        self._combo_toggle_button.clicked.connect(self._toggle_combo_rule)
        button_layout.addWidget(self._combo_toggle_button)

        self._combo_edit_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), f" {tr('Edit')}")
        self._combo_edit_button.setEnabled(False)
        self._combo_edit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_edit_button.clicked.connect(self._edit_combo_rule)
        button_layout.addWidget(self._combo_edit_button)

        self._combo_duplicate_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), f" {tr('Duplicate')}")
        self._combo_duplicate_button.setEnabled(False)
        self._combo_duplicate_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_duplicate_button.clicked.connect(self._duplicate_combo_rule)
        button_layout.addWidget(self._combo_duplicate_button)

        self._combo_export_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), f" {tr('Export Rule')}")
        self._combo_export_button.setEnabled(False)
        self._combo_export_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_export_button.setToolTip(tr('Export the selected combo rule(s) to a JSON file'))
        self._combo_export_button.clicked.connect(self._export_selected_combo_rules)
        button_layout.addWidget(self._combo_export_button)

        self._combo_remove_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f" {tr('Remove')}")
        self._combo_remove_button.setEnabled(False)
        self._combo_remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_remove_button.clicked.connect(self._remove_combo_rule)
        button_layout.addWidget(self._combo_remove_button)

        self._combo_clear_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f" {tr('Clear All')}")
        self._combo_clear_button.setEnabled(False)
        self._combo_clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_clear_button.clicked.connect(self._clear_combo_rules)
        button_layout.addWidget(self._combo_clear_button)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        self._combo_rules_list.itemSelectionChanged.connect(self._update_combo_rule_buttons)
        self._combo_rules_list.itemActivated.connect(self._on_combo_item_activated)

        return widget

    def _get_selected_combo_rule_indices(self) -> list[int]:
        """Return sorted valid rule indices for all currently selected combo rule items."""
        total = len(ComboRulesManager.rules)
        return sorted({row for item in self._combo_rules_list.selectedItems() if 0 <= (row := self._combo_rules_list.row(item)) < total})

    def _get_selected_combo_rule_index(self) -> int | None:
        """Return the index of the single selected combo rule, or None."""
        indices = self._get_selected_combo_rule_indices()
        return indices[0] if len(indices) == 1 else None

    def _update_combo_rule_buttons(self) -> None:
        """Synchronize the enabled/disabled state and labels of combo rule management buttons."""
        indices = self._get_selected_combo_rule_indices()
        sel_count = len(indices)
        has_selection = sel_count > 0
        has_items = self._combo_rules_list.count() > 0
        self._combo_edit_button.setEnabled(sel_count == 1)
        self._combo_duplicate_button.setEnabled(has_selection)
        self._combo_duplicate_button.setText(f" {tr('Duplicate ({count})', count=sel_count)}" if sel_count > 1 else f" {tr('Duplicate')}")
        self._combo_export_button.setEnabled(has_selection)
        self._combo_export_button.setText(f" {tr('Export ({count})', count=sel_count)}" if sel_count > 1 else f" {tr('Export Rule')}")
        self._combo_remove_button.setEnabled(has_selection)
        self._combo_remove_button.setText(f" {tr('Remove ({count})', count=sel_count)}" if sel_count > 1 else f" {tr('Remove')}")
        self._combo_toggle_button.setEnabled(has_selection)
        self._combo_clear_button.setEnabled(has_items)

        if sel_count >= 1:
            all_enabled = all(ComboRulesManager.rules[i].enabled for i in indices)
            toggle_text = (
                tr_plural('Disable Rule', 'Disable Rules ({count})', sel_count)
                if all_enabled
                else tr_plural('Enable Rule', 'Enable Rules ({count})', sel_count)
            )
            self._combo_toggle_button.setText(f' {toggle_text}')
            self._combo_toggle_button.setIcon(QIcon(str(ICONS_DIR_PATH / ('toggle-left.svg' if all_enabled else 'toggle-right.svg'))))
        else:
            self._combo_toggle_button.setText(f" {tr('Toggle State')}")
            self._combo_toggle_button.setIcon(QIcon(str(ICONS_DIR_PATH / 'toggle-right.svg')))

    def refresh_combo_rules_list(self, selected_rows: list[int] | None = None) -> None:
        """Reload the combo rules QListWidget from ComboRulesManager, preserving selection."""
        rows_to_select = self._get_selected_combo_rule_indices() if selected_rows is None else selected_rows
        with QSignalBlocker(self._combo_rules_list):
            self._combo_rules_list.clear()
            for rule in ComboRulesManager.rules:
                item = QListWidgetItem(rule.name)
                item.setData(Qt.ItemDataRole.UserRole, id(rule))
                self._combo_rules_list.addItem(item)

            count = self._combo_rules_list.count()
            valid_rows = [row for row in rows_to_select if 0 <= row < count]
            if valid_rows:
                self._combo_rules_list.setCurrentRow(valid_rows[0])
                for row in valid_rows:
                    self._combo_rules_list.item(row).setSelected(True)

        self._update_combo_rule_buttons()

    def _on_combo_rules_context_menu(self, pos: QPoint) -> None:
        """Show a context menu for managing single or multi-selected combo rules."""
        clicked_item = self._combo_rules_list.itemAt(pos)
        if clicked_item is not None and not clicked_item.isSelected():
            self._combo_rules_list.clearSelection()
            self._combo_rules_list.setCurrentItem(clicked_item)
            clicked_item.setSelected(True)

        indices = self._get_selected_combo_rule_indices()
        sel_count = len(indices)
        has_selection = sel_count > 0
        has_items = self._combo_rules_list.count() > 0

        menu = QMenu(self)
        menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)

        add_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), tr('Add Rule…'))
        add_act.triggered.connect(self._add_combo_rule)

        edit_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), tr('Edit Rule…'))
        edit_act.setEnabled(sel_count == 1)
        edit_act.triggered.connect(self._edit_combo_rule)

        all_enabled = has_selection and all(ComboRulesManager.rules[i].enabled for i in indices)
        toggle_label = (
            tr_plural('Disable Rule', 'Disable Rules ({count})', max(sel_count, 1))
            if all_enabled
            else tr_plural('Enable Rule', 'Enable Rules ({count})', max(sel_count, 1))
        )
        toggle_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / ('toggle-left.svg' if all_enabled else 'toggle-right.svg'))), toggle_label)
        toggle_act.setEnabled(has_selection)
        toggle_act.triggered.connect(self._toggle_combo_rule)

        dup_label = tr('Duplicate ({count})', count=sel_count) if sel_count > 1 else tr('Duplicate')
        dup_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), dup_label)
        dup_act.setEnabled(has_selection)
        dup_act.triggered.connect(self._duplicate_combo_rule)

        menu.addSeparator()

        export_label = tr('Export Selected Rules ({count})…', count=sel_count) if sel_count > 1 else tr('Export Selected Rule…')
        export_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), export_label)
        export_act.setEnabled(has_selection)
        export_act.triggered.connect(self._export_selected_combo_rules)

        import_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'download.svg')), tr('Import Combo Rules…'))
        import_act.triggered.connect(self._import_combo_rules_file)

        menu.addSeparator()

        select_all_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), tr('Select All'))
        select_all_act.setShortcut('Ctrl+A')
        select_all_act.setEnabled(has_items)
        select_all_act.triggered.connect(self._combo_rules_list.selectAll)

        remove_label = tr('Remove ({count})', count=sel_count) if sel_count > 1 else tr('Remove')
        remove_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), remove_label)
        remove_act.setShortcut('Delete')
        remove_act.setEnabled(has_selection)
        remove_act.triggered.connect(self._remove_combo_rule)

        clear_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), tr('Clear All'))
        clear_act.setEnabled(has_items)
        clear_act.triggered.connect(self._clear_combo_rules)

        if viewport := self._combo_rules_list.viewport():
            menu.exec(viewport.mapToGlobal(pos))

    def _add_combo_rule(self) -> None:
        """Open editor dialog to create a new combo rule."""
        dialog = ComboRuleEditorDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ComboRulesManager.rules.append(dialog.get_rule())
            ComboRulesManager.save_to_file(COMBO_RULES_PATH)
            self.refresh_combo_rules_list(selected_rows=[len(ComboRulesManager.rules) - 1])
            retrigger_detections_scan()

    def _on_combo_item_activated(self, _item: QListWidgetItem) -> None:
        """Handle double-click/activation on a single combo rule list item."""
        if len(self._get_selected_combo_rule_indices()) == 1:
            self._edit_combo_rule()

    def _edit_combo_rule(self) -> None:
        """Open editor dialog to edit the selected combo rule."""
        index = self._get_selected_combo_rule_index()
        if index is None:
            QMessageBox.information(self, TITLE, tr('Select a single rule to edit.'))
            return
        existing_rule = ComboRulesManager.rules[index]
        dialog = ComboRuleEditorDialog(self, rule=existing_rule)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_rule = dialog.get_rule()
            if existing_rule.enabled and existing_rule.voice_notifications and (not new_rule.enabled or not new_rule.voice_notifications):
                clear_voice_notification_queue()
            ComboRulesManager.rules[index] = new_rule
            ComboRulesManager.save_to_file(COMBO_RULES_PATH)
            self.refresh_combo_rules_list(selected_rows=[index])
            retrigger_detections_scan()

    def _toggle_combo_rule(self) -> None:
        """Toggle the enabled state of the selected combo rule(s)."""
        indices = self._get_selected_combo_rule_indices()
        if not indices:
            return
        target_enabled = not all(ComboRulesManager.rules[i].enabled for i in indices)
        if not target_enabled and any(ComboRulesManager.rules[i].enabled and ComboRulesManager.rules[i].voice_notifications for i in indices):
            clear_voice_notification_queue()
        for index in indices:
            ComboRulesManager.rules[index].enabled = target_enabled
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.refresh_combo_rules_list(selected_rows=indices)
        retrigger_detections_scan()

    def _duplicate_combo_rule(self) -> None:
        """Duplicate the selected combo rule(s)."""
        indices = self._get_selected_combo_rule_indices()
        if not indices:
            QMessageBox.information(self, TITLE, tr('Select at least one rule to duplicate.'))
            return
        start_index = len(ComboRulesManager.rules)
        any_enabled = False
        for index in indices:
            original = ComboRulesManager.rules[index]
            copy = ComboRule(
                name=tr('{name} (Copy)', name=original.name),
                enabled=original.enabled,
                conditions=dict(original.conditions),
                protection_enabled=original.protection_enabled,
                duration=original.duration,
                voice_notifications=original.voice_notifications,
                logging=original.logging,
                message_box=original.message_box,
            )
            ComboRulesManager.rules.append(copy)
            any_enabled = any_enabled or copy.enabled
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.refresh_combo_rules_list(selected_rows=list(range(start_index, len(ComboRulesManager.rules))))
        if any_enabled:
            retrigger_detections_scan()

    def _export_selected_combo_rules(self) -> None:
        """Export the currently selected combo rule(s) to a standalone JSON file."""
        indices = self._get_selected_combo_rule_indices()
        if not indices:
            QMessageBox.information(self, TITLE, tr('Select at least one rule to export.'))
            return
        selected_rules = [ComboRulesManager.rules[i] for i in indices]
        default_name = f'{selected_rules[0].name}.json' if len(selected_rules) == 1 else 'combo_rules.json'
        file_path, _ = QFileDialog.getSaveFileName(self, tr('Export Selected Combo Rules'), default_name, tr('JSON Files (*.json);;All Files (*.*)'))
        if not file_path:
            return
        target = Path(file_path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(TypeAdapter(list[ComboRule]).dump_json(selected_rules, indent=4).decode('utf-8'), encoding='utf-8')
        except OSError as e:
            QMessageBox.critical(self, tr('Export Error'), tr('Failed to export combo rules:\n{error}', error=e))
            return
        QMessageBox.information(
            self,
            TITLE,
            tr_plural('Exported {count} combo rule successfully.', 'Exported {count} combo rules successfully.', len(selected_rules)),
        )

    def _import_combo_rules_file(self) -> None:
        """Import combo rules from either a combo-rules list JSON or a detections JSON file and append them."""
        file_path, _ = QFileDialog.getOpenFileName(self, tr('Import Combo Rules'), '', tr('JSON Files (*.json);;All Files (*.*)'))
        if not file_path:
            return
        try:
            raw_text = Path(file_path).read_text(encoding='utf-8')
            parsed = json.loads(raw_text)
            imported: list[ComboRule] = (
                TypeAdapter(list[ComboRule]).validate_python(parsed)
                if isinstance(parsed, list)
                else (DetectionsFile.model_validate(parsed).combo_rules or [])
            )
        except (ValidationError, OSError, json.JSONDecodeError) as e:
            QMessageBox.critical(self, tr('Import Error'), tr('Failed to import combo rules:\n{error}', error=e))
            return
        if not imported:
            QMessageBox.information(self, TITLE, tr('No combo rules were found in the selected file.'))
            return
        start_index = len(ComboRulesManager.rules)
        ComboRulesManager.rules.extend(imported)
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.refresh_combo_rules_list(selected_rows=list(range(start_index, len(ComboRulesManager.rules))))
        if any(rule.enabled for rule in imported):
            retrigger_detections_scan()
        QMessageBox.information(
            self,
            TITLE,
            tr_plural('Imported {count} combo rule successfully.', 'Imported {count} combo rules successfully.', len(imported)),
        )

    def _remove_combo_rule(self) -> None:
        """Remove the selected combo rule(s)."""
        indices = self._get_selected_combo_rule_indices()
        if not indices:
            return
        prompt = (
            tr('Remove rule "{name}"?', name=ComboRulesManager.rules[indices[0]].name)
            if len(indices) == 1
            else tr('Remove {count} selected combo rules?', count=len(indices))
        )
        reply = QMessageBox.question(self, TITLE, prompt, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        if any(ComboRulesManager.rules[i].enabled and ComboRulesManager.rules[i].voice_notifications for i in indices):
            clear_voice_notification_queue()
        for index in reversed(indices):
            del ComboRulesManager.rules[index]
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        next_row = min(indices[0], len(ComboRulesManager.rules) - 1)
        self.refresh_combo_rules_list(selected_rows=[next_row] if next_row >= 0 else [])
        retrigger_detections_scan()

    def _clear_combo_rules(self, *, confirm: bool = True) -> None:
        """Remove all combo rules."""
        if not ComboRulesManager.rules:
            return
        if confirm:
            reply = QMessageBox.question(
                self,
                TITLE,
                tr('Remove all combo rules?'),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        if any(rule.enabled and rule.voice_notifications for rule in ComboRulesManager.rules):
            clear_voice_notification_queue()
        ComboRulesManager.rules.clear()
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.refresh_combo_rules_list(selected_rows=[])
        retrigger_detections_scan()

    @override
    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Consume Enter/Return when the combo rules list has focus to prevent triggering the default button."""
        if event and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self._combo_rules_list.hasFocus():
            return
        super().keyPressEvent(event)

    @override
    def showEvent(self, a0: QShowEvent) -> None:
        """Handle the window show event, reload current settings, and maximize if required."""
        self.load_current_settings()
        self.refresh_detection_availability()
        super().showEvent(a0)
        if consume_maximize_on_show(self):
            self.showMaximized()


def open_combo_rule_editor_for_player(parent: QWidget, player: Player) -> None:
    """Open the combo rule editor pre-filled with the player's known IP lookup attributes."""
    _placeholder = '...'

    def _safe(value: object) -> str | None:
        return value if isinstance(value, str) and value and value not in {_placeholder, 'N/A'} else None

    conditions: dict[str, str | bool | list[str]] = {}
    if (continent := _safe(player.iplookup.resolve_continent()[0])) is not None:
        conditions['continent'] = normalize_continent_name(continent) or continent
    if (country := _safe(player.iplookup.resolve_country()[0])) is not None:
        conditions['country'] = normalize_country_name(country) or country
    if (isp := _safe(player.iplookup.ipapi.isp)) is not None:
        conditions['isp'] = isp
    if (asn := _safe(player.iplookup.ipapi.asn) or _safe(player.iplookup.geolite2.asn)) is not None:
        conditions['asn'] = asn
    if (as_name := _safe(player.iplookup.ipapi.as_name)) is not None:
        conditions['as_name'] = as_name
    if isinstance(player.iplookup.ipapi.mobile, bool):
        conditions['mobile'] = player.iplookup.ipapi.mobile
    if isinstance(player.iplookup.ipapi.proxy, bool):
        conditions['vpn'] = player.iplookup.ipapi.proxy
    if isinstance(player.iplookup.ipapi.hosting, bool):
        conditions['hosting'] = player.iplookup.ipapi.hosting

    prefilled = ComboRule(name=tr('Rule for {ip}', ip=player.ip), conditions=conditions) if conditions else None
    _exec_and_save_combo_rule(parent, prefilled)


def _exec_and_save_combo_rule(parent: QWidget, initial_rule: ComboRule | None = None) -> None:
    """Open the combo rule editor dialog and persist the rule on accept."""
    dialog = ComboRuleEditorDialog(parent, initial_rule)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        ComboRulesManager.rules.append(dialog.get_rule())
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        DetectionsManagerDialog.refresh_if_open()
        retrigger_detections_scan()


def open_combo_rule_editor(parent: QWidget) -> None:
    """Open a blank combo rule editor and save the new rule on accept."""
    _exec_and_save_combo_rule(parent)
