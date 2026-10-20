"""Detections Manager dialog for configuring advanced per-detection rules."""

import json
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast, override

from pydantic import ValidationError
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.background import clear_voice_notification_queue
from session_sniffer.constants.local import COMBO_RULES_PATH, DETECTIONS_JSON_PATH, RESOURCES_DIR_PATH
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
from session_sniffer.guis.stylesheets import DETECTIONS_MANAGER_HEADER_STYLESHEET, DIALOG_BUTTON_STYLESHEET
from session_sniffer.guis.utils import (
    consume_maximize_on_show,
    resize_window_for_screen,
    scale_by_ui,
    set_dialog_window_flags,
)
from session_sniffer.models.combo_rules import ComboRule
from session_sniffer.models.detections import DetectionsFile
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS

if TYPE_CHECKING:
    from PySide6.QtGui import QKeyEvent, QShowEvent

    from session_sniffer.models.player import Player


_COMBO_RULES_TAB_INDEX = 3


class DetectionsManagerDialog(DetectionsManagerTabsMixin, QDialog):
    """Comprehensive detections manager with VPN, IP range, and advanced threat detection capabilities."""

    _instance: ClassVar[DetectionsManagerDialog | None] = None

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the Detections Manager dialog."""
        super().__init__(parent)
        DetectionsManagerDialog._instance = self
        self.destroyed.connect(lambda: setattr(DetectionsManagerDialog, '_instance', None) if DetectionsManagerDialog._instance is self else None)
        self._loading_settings = False
        self.setWindowTitle(f'{TITLE} - Detections Manager')
        set_dialog_window_flags(self)
        self.setMinimumSize(scale_by_ui(720), scale_by_ui(500))
        resize_window_for_screen(self)

        # Widget references (populated by tab builders)
        # -- Network-based (mobile, vpn, hosting) --
        self.mobile_duration_combo: QComboBox
        self.mobile_duration_spin: QSpinBox
        self.mobile_voice_combo: QComboBox
        self.mobile_logging_checkbox: QCheckBox
        self.mobile_msgbox_checkbox: QCheckBox
        self.vpn_duration_combo: QComboBox
        self.vpn_duration_spin: QSpinBox
        self.vpn_voice_combo: QComboBox
        self.vpn_logging_checkbox: QCheckBox
        self.vpn_msgbox_checkbox: QCheckBox
        self.hosting_duration_combo: QComboBox
        self.hosting_duration_spin: QSpinBox
        self.hosting_voice_combo: QComboBox
        self.hosting_logging_checkbox: QCheckBox
        self.hosting_msgbox_checkbox: QCheckBox
        # -- Geography-based (country, isp, asn) --
        self.country_list: QListWidget
        self.country_duration_combo: QComboBox
        self.country_duration_spin: QSpinBox
        self.country_voice_combo: QComboBox
        self.country_logging_checkbox: QCheckBox
        self.country_msgbox_checkbox: QCheckBox
        self.isp_list: QListWidget
        self.isp_duration_combo: QComboBox
        self.isp_duration_spin: QSpinBox
        self.isp_voice_combo: QComboBox
        self.isp_logging_checkbox: QCheckBox
        self.isp_msgbox_checkbox: QCheckBox
        self.asn_list: QListWidget
        self.asn_duration_combo: QComboBox
        self.asn_duration_spin: QSpinBox
        self.asn_voice_combo: QComboBox
        self.asn_logging_checkbox: QCheckBox
        self.asn_msgbox_checkbox: QCheckBox
        # -- Player events (join, rejoin, leave) --
        self.player_join_duration_combo: QComboBox
        self.player_join_duration_spin: QSpinBox
        self.player_join_voice_combo: QComboBox
        self.player_join_logging_checkbox: QCheckBox
        self.player_join_msgbox_checkbox: QCheckBox
        self.player_rejoin_duration_combo: QComboBox
        self.player_rejoin_duration_spin: QSpinBox
        self.player_rejoin_voice_combo: QComboBox
        self.player_rejoin_logging_checkbox: QCheckBox
        self.player_rejoin_msgbox_checkbox: QCheckBox
        self.player_leave_duration_combo: QComboBox
        self.player_leave_duration_spin: QSpinBox
        self.player_leave_voice_combo: QComboBox
        self.player_leave_logging_checkbox: QCheckBox
        self.player_leave_msgbox_checkbox: QCheckBox
        # -- GTA5 Relays (GTA5 preset only) --
        self._relay_filter_warning: QWidget
        self.gta5_relay_packet_threshold_spin: QSpinBox
        self.gta5_relay_duration_combo: QComboBox
        self.gta5_relay_duration_spin: QSpinBox
        self.gta5_relay_voice_combo: QComboBox
        self.gta5_relay_logging_checkbox: QCheckBox
        self.gta5_relay_msgbox_checkbox: QCheckBox
        # -- Combo rules --
        self._combo_rules_list: QListWidget

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        header = QLabel('Advanced Detection & Security Manager')
        header.setStyleSheet(DETECTIONS_MANAGER_HEADER_STYLESHEET)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Tabs
        self._tabs = QTabWidget()
        self._tabs.addTab(self.create_player_events_tab(), QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'user-round.svg')), 'Player Events')
        self._tabs.addTab(self.create_network_based_tab(), QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ethernet-port.svg')), 'Network-Based')
        self._tabs.addTab(self.create_geo_based_tab(), QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'globe.svg')), 'Geography-Based')
        self._tabs.addTab(self.create_combo_rules_tab(), QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'link.svg')), 'Combo Rules')
        if Settings.is_gta5_feature_set():
            self._tabs.addTab(self.create_gta5_relays_tab(), QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'gamepad-2.svg')), 'GTA5 Relays')
        layout.addWidget(self._tabs)

        # Bottom buttons
        button_row = QHBoxLayout()

        import_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'import.svg')), ' Import')
        import_button.setToolTip('Import detection settings from a JSON file')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.clicked.connect(self._import_detections)
        button_row.addWidget(import_button)

        export_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'upload.svg')), ' Export')
        export_button.setToolTip('Export detection settings to a JSON file')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_detections)
        button_row.addWidget(export_button)

        reset_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'rotate-ccw.svg')), ' Reset all…')
        reset_button.setToolTip('Reset all detection settings to defaults')
        setup_tab_reset_buttons(button_row, reset_button, self._reset_to_defaults, self._reset_current_tab)

        close_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'x.svg')), ' Close')
        close_button.setToolTip('Close the Detections Manager')
        close_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        close_button.clicked.connect(self.close)
        button_row.addWidget(close_button)

        equalize_button_sizes(button_row)

        layout.addLayout(button_row)

        self.load_current_settings()
        self.refresh_detection_availability()
        if hasattr(self, 'gta5_relay_duration_combo'):
            self.gta5_relay_duration_combo.currentTextChanged.connect(self._on_gta5_relay_suspend_mode_changed)
        self._connect_auto_save_signals()

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
        if not Settings.is_gta5_feature_set() or not CaptureState.is_local_capture():
            self._apply_detection_restrictions()
        else:
            self._remove_detection_restrictions()

    def _apply_detection_restrictions(self) -> None:
        """Hide all detection action widgets when detection is not supported (non-GTA5 feature set or neighbour interface)."""
        for prefix in ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave', 'gta5_relay'):
            if not hasattr(self, f'{prefix}_detection_section'):
                continue
            detection_section = cast('QWidget', getattr(self, f'{prefix}_detection_section'))
            detection_section.setVisible(False)

    def _remove_detection_restrictions(self) -> None:
        """Show all detection action widgets when detection is supported."""
        for prefix in ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave', 'gta5_relay'):
            if not hasattr(self, f'{prefix}_detection_section'):
                continue
            detection_section = cast('QWidget', getattr(self, f'{prefix}_detection_section'))
            detection_section.setVisible(True)

    # ------------------------------------------------------------------
    # Settings load / save
    # ------------------------------------------------------------------

    def load_current_settings(self) -> None:
        """Read GUIDetectionSettings and populate all widgets."""
        self._loading_settings = True
        try:
            # Mobile
            set_duration_widgets_helper(
                self.mobile_duration_combo,
                self.mobile_duration_spin,
                GUIDetectionSettings.mobile_suspend_duration if GUIDetectionSettings.mobile_suspend_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.mobile_voice_combo, value=GUIDetectionSettings.mobile_voice_notifications)
            self.mobile_logging_checkbox.setChecked(GUIDetectionSettings.mobile_logging)
            self.mobile_msgbox_checkbox.setChecked(GUIDetectionSettings.mobile_message_box)

            # VPN
            set_duration_widgets_helper(
                self.vpn_duration_combo,
                self.vpn_duration_spin,
                GUIDetectionSettings.vpn_suspend_duration if GUIDetectionSettings.vpn_suspend_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.vpn_voice_combo, value=GUIDetectionSettings.vpn_voice_notifications)
            self.vpn_logging_checkbox.setChecked(GUIDetectionSettings.vpn_logging)
            self.vpn_msgbox_checkbox.setChecked(GUIDetectionSettings.vpn_message_box)

            # Hosting
            set_duration_widgets_helper(
                self.hosting_duration_combo,
                self.hosting_duration_spin,
                GUIDetectionSettings.hosting_suspend_duration if GUIDetectionSettings.hosting_suspend_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.hosting_voice_combo, value=GUIDetectionSettings.hosting_voice_notifications)
            self.hosting_logging_checkbox.setChecked(GUIDetectionSettings.hosting_logging)
            self.hosting_msgbox_checkbox.setChecked(GUIDetectionSettings.hosting_message_box)

            # Country
            self.country_list.clear()
            seen_countries: set[str] = set()
            for country in GUIDetectionSettings.country_detection_list:
                if country not in seen_countries:
                    seen_countries.add(country)
                    self._add_country_item(country)
            set_duration_widgets_helper(
                self.country_duration_combo,
                self.country_duration_spin,
                GUIDetectionSettings.country_suspend_duration if GUIDetectionSettings.country_suspend_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.country_voice_combo, value=GUIDetectionSettings.country_voice_notifications)
            self.country_logging_checkbox.setChecked(GUIDetectionSettings.country_logging)
            self.country_msgbox_checkbox.setChecked(GUIDetectionSettings.country_message_box)

            # ISP
            self.isp_list.clear()
            seen_isps: set[str] = set()
            for isp in GUIDetectionSettings.isp_detection_list:
                if isp not in seen_isps:
                    seen_isps.add(isp)
                    self.isp_list.addItem(isp)
            set_duration_widgets_helper(
                self.isp_duration_combo,
                self.isp_duration_spin,
                GUIDetectionSettings.isp_suspend_duration if GUIDetectionSettings.isp_suspend_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.isp_voice_combo, value=GUIDetectionSettings.isp_voice_notifications)
            self.isp_logging_checkbox.setChecked(GUIDetectionSettings.isp_logging)
            self.isp_msgbox_checkbox.setChecked(GUIDetectionSettings.isp_message_box)

            # ASN
            self.asn_list.clear()
            seen_asns: set[str] = set()
            for asn in GUIDetectionSettings.asn_detection_list:
                if asn not in seen_asns:
                    seen_asns.add(asn)
                    self.asn_list.addItem(asn)
            set_duration_widgets_helper(
                self.asn_duration_combo,
                self.asn_duration_spin,
                GUIDetectionSettings.asn_suspend_duration if GUIDetectionSettings.asn_suspend_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.asn_voice_combo, value=GUIDetectionSettings.asn_voice_notifications)
            self.asn_logging_checkbox.setChecked(GUIDetectionSettings.asn_logging)
            self.asn_msgbox_checkbox.setChecked(GUIDetectionSettings.asn_message_box)

            # Player Join
            set_duration_widgets_helper(
                self.player_join_duration_combo,
                self.player_join_duration_spin,
                GUIDetectionSettings.player_join_duration if GUIDetectionSettings.player_join_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.player_join_voice_combo, value=GUIDetectionSettings.player_join_voice_notifications)
            self.player_join_logging_checkbox.setChecked(GUIDetectionSettings.player_join_logging)
            self.player_join_msgbox_checkbox.setChecked(GUIDetectionSettings.player_join_message_box)

            # Player Rejoin
            set_duration_widgets_helper(
                self.player_rejoin_duration_combo,
                self.player_rejoin_duration_spin,
                GUIDetectionSettings.player_rejoin_duration if GUIDetectionSettings.player_rejoin_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.player_rejoin_voice_combo, value=GUIDetectionSettings.player_rejoin_voice_notifications)
            self.player_rejoin_logging_checkbox.setChecked(GUIDetectionSettings.player_rejoin_logging)
            self.player_rejoin_msgbox_checkbox.setChecked(GUIDetectionSettings.player_rejoin_message_box)

            # Player Leave
            set_duration_widgets_helper(
                self.player_leave_duration_combo,
                self.player_leave_duration_spin,
                GUIDetectionSettings.player_leave_duration if GUIDetectionSettings.player_leave_enabled else 'Disabled',
            )
            set_voice_combo_helper(self.player_leave_voice_combo, value=GUIDetectionSettings.player_leave_voice_notifications)
            self.player_leave_logging_checkbox.setChecked(GUIDetectionSettings.player_leave_logging)
            self.player_leave_msgbox_checkbox.setChecked(GUIDetectionSettings.player_leave_message_box)

            # GTA5 Relay (only when the tab is present)
            if hasattr(self, 'gta5_relay_duration_combo'):
                self._relay_filter_warning.setVisible('TAKETWO_INTERACTIVE' in Settings.capture_block_third_party_servers)
                self.gta5_relay_packet_threshold_spin.setValue(GUIDetectionSettings.gta5_relay_packet_threshold)
                set_duration_widgets_helper(
                    self.gta5_relay_duration_combo,
                    self.gta5_relay_duration_spin,
                    GUIDetectionSettings.gta5_relay_duration if GUIDetectionSettings.gta5_relay_enabled else 'Disabled',
                )
                set_voice_combo_helper(self.gta5_relay_voice_combo, value=GUIDetectionSettings.gta5_relay_voice_notifications)
                self.gta5_relay_logging_checkbox.setChecked(GUIDetectionSettings.gta5_relay_logging)
                self.gta5_relay_msgbox_checkbox.setChecked(GUIDetectionSettings.gta5_relay_message_box)

            # Combo Rules
            self.refresh_combo_rules_list()
        finally:
            self._loading_settings = False

    def _connect_auto_save_signals(self) -> None:
        """Connect all detection widget change signals to auto-save."""
        prefixes: tuple[str, ...] = ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave')
        if hasattr(self, 'gta5_relay_duration_combo'):
            prefixes = (*prefixes, 'gta5_relay')
            self.gta5_relay_packet_threshold_spin.valueChanged.connect(self._auto_save_detections)

        for prefix in prefixes:
            cast('QComboBox', getattr(self, f'{prefix}_duration_combo')).currentTextChanged.connect(self._auto_save_detections)
            cast('QSpinBox', getattr(self, f'{prefix}_duration_spin')).valueChanged.connect(self._auto_save_detections)
            cast('QComboBox', getattr(self, f'{prefix}_voice_combo')).currentTextChanged.connect(self._auto_save_detections)
            cast('QCheckBox', getattr(self, f'{prefix}_logging_checkbox')).toggled.connect(self._auto_save_detections)
            cast('QCheckBox', getattr(self, f'{prefix}_msgbox_checkbox')).toggled.connect(self._auto_save_detections)

    @override
    def _auto_save_detections(self) -> None:
        """Read widgets, write GUIDetectionSettings, and persist to detections.json in real time."""
        if self._loading_settings:
            return

        # Clear voice queue if any detection's voice notification was newly disabled
        checkbox_prefixes = (
            'mobile',
            'vpn',
            'hosting',
            'country',
            'isp',
            'asn',
            'player_join',
            'player_rejoin',
            'player_leave',
            'gta5_relay',
        )
        for prefix in checkbox_prefixes:
            if not hasattr(self, f'{prefix}_voice_combo'):
                continue
            if getattr(GUIDetectionSettings, f'{prefix}_voice_notifications') and getattr(self, f'{prefix}_voice_combo').currentText() == 'Disabled':
                clear_voice_notification_queue()
                break

        self._save_widgets_to_singleton()
        GUIDetectionSettings.export_to_file(DETECTIONS_JSON_PATH)

    def _export_detections(self) -> None:
        """Export current detection settings (including combo rules) to a JSON file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            'Export Detection Settings',
            'detections.json',
            'JSON Files (*.json);;All Files (*.*)',
        )
        if file_path:
            # Save current widget state to GUIDetectionSettings first
            self._save_widgets_to_singleton()
            # Build combined export: standard detections + combo rules
            model = GUIDetectionSettings.to_model()
            model.combo_rules = list(ComboRulesManager.rules)
            target = Path(file_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(model.model_dump_json(indent=4, by_alias=True), encoding='utf-8')
            QMessageBox.information(self, TITLE, 'Detection settings exported successfully.')

    def _import_detections(self) -> None:
        """Import detection settings (including combo rules) from a JSON file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            'Import Detection Settings',
            '',
            'JSON Files (*.json);;All Files (*.*)',
        )
        if file_path:
            try:
                content = Path(file_path).read_text(encoding='utf-8')
                model = DetectionsFile.model_validate_json(content)
                GUIDetectionSettings.apply_model(model)
                GUIDetectionSettings.export_to_file(DETECTIONS_JSON_PATH)
                # Import combo rules if present
                if model.combo_rules is not None:
                    ComboRulesManager.rules = list(model.combo_rules)
                    ComboRulesManager.save_to_file(COMBO_RULES_PATH)
            except (ValidationError, OSError, json.JSONDecodeError) as e:
                QMessageBox.critical(self, 'Import Error', f'Failed to import settings:\n{e}')
                return
            self.load_current_settings()
            QMessageBox.information(self, TITLE, 'Detection settings imported successfully.')

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
                duration_attr = f'{prefix}_duration' if prefix in ('player_join', 'player_rejoin', 'player_leave', 'gta5_relay') else f'{prefix}_suspend_duration'
                setattr(GUIDetectionSettings, duration_attr, 'Auto')
                set_voice_combo_helper(getattr(self, f'{prefix}_voice_combo'), value=False)
                getattr(self, f'{prefix}_logging_checkbox').setChecked(False)
                getattr(self, f'{prefix}_msgbox_checkbox').setChecked(False)
                if hasattr(self, f'{prefix}_list'):
                    getattr(self, f'{prefix}_list').clear()
                if prefix == 'gta5_relay':
                    self.gta5_relay_packet_threshold_spin.setValue(40)
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
            2: ('country', 'isp', 'asn'),
            4: ('gta5_relay',),
        }
        prefixes = index_to_prefixes.get(current_index)
        if prefixes is None:
            return
        tab_name = self._tabs.tabText(current_index)
        result = QMessageBox.question(
            self,
            TITLE,
            f'Reset {tab_name} detection settings to defaults?',
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
            'Reset all detection settings to defaults?\n\nThis will clear all current values in the editor.',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        prefixes: tuple[str, ...] = ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave')
        if hasattr(self, 'gta5_relay_duration_combo'):
            prefixes = (*prefixes, 'gta5_relay')
        self._reset_tab_to_defaults(prefixes)

    def _save_widgets_to_singleton(self) -> None:
        """Write current widget state to GUIDetectionSettings without persisting to disk."""
        # Mobile
        GUIDetectionSettings.mobile_suspend_enabled = self.mobile_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.mobile_suspend_enabled:
            GUIDetectionSettings.mobile_suspend_duration = read_duration_widgets_helper(self.mobile_duration_combo, self.mobile_duration_spin)
        GUIDetectionSettings.mobile_voice_notifications = read_voice_combo_helper(self.mobile_voice_combo)
        GUIDetectionSettings.mobile_logging = self.mobile_logging_checkbox.isChecked()
        GUIDetectionSettings.mobile_message_box = self.mobile_msgbox_checkbox.isChecked()

        # VPN
        GUIDetectionSettings.vpn_suspend_enabled = self.vpn_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.vpn_suspend_enabled:
            GUIDetectionSettings.vpn_suspend_duration = read_duration_widgets_helper(self.vpn_duration_combo, self.vpn_duration_spin)
        GUIDetectionSettings.vpn_voice_notifications = read_voice_combo_helper(self.vpn_voice_combo)
        GUIDetectionSettings.vpn_logging = self.vpn_logging_checkbox.isChecked()
        GUIDetectionSettings.vpn_message_box = self.vpn_msgbox_checkbox.isChecked()

        # Hosting
        GUIDetectionSettings.hosting_suspend_enabled = self.hosting_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.hosting_suspend_enabled:
            GUIDetectionSettings.hosting_suspend_duration = read_duration_widgets_helper(self.hosting_duration_combo, self.hosting_duration_spin)
        GUIDetectionSettings.hosting_voice_notifications = read_voice_combo_helper(self.hosting_voice_combo)
        GUIDetectionSettings.hosting_logging = self.hosting_logging_checkbox.isChecked()
        GUIDetectionSettings.hosting_message_box = self.hosting_msgbox_checkbox.isChecked()

        # Country
        GUIDetectionSettings.country_suspend_enabled = self.country_duration_combo.currentText() != 'Disabled'
        GUIDetectionSettings.country_detection_list = [item.data(Qt.ItemDataRole.UserRole) for i in range(self.country_list.count()) if (item := self.country_list.item(i))]
        if GUIDetectionSettings.country_suspend_enabled:
            GUIDetectionSettings.country_suspend_duration = read_duration_widgets_helper(self.country_duration_combo, self.country_duration_spin)
        GUIDetectionSettings.country_voice_notifications = read_voice_combo_helper(self.country_voice_combo)
        GUIDetectionSettings.country_logging = self.country_logging_checkbox.isChecked()
        GUIDetectionSettings.country_message_box = self.country_msgbox_checkbox.isChecked()

        # ISP
        GUIDetectionSettings.isp_suspend_enabled = self.isp_duration_combo.currentText() != 'Disabled'
        GUIDetectionSettings.isp_detection_list = [item.text() for i in range(self.isp_list.count()) if (item := self.isp_list.item(i))]
        if GUIDetectionSettings.isp_suspend_enabled:
            GUIDetectionSettings.isp_suspend_duration = read_duration_widgets_helper(self.isp_duration_combo, self.isp_duration_spin)
        GUIDetectionSettings.isp_voice_notifications = read_voice_combo_helper(self.isp_voice_combo)
        GUIDetectionSettings.isp_logging = self.isp_logging_checkbox.isChecked()
        GUIDetectionSettings.isp_message_box = self.isp_msgbox_checkbox.isChecked()

        # ASN
        GUIDetectionSettings.asn_suspend_enabled = self.asn_duration_combo.currentText() != 'Disabled'
        GUIDetectionSettings.asn_detection_list = [item.text() for i in range(self.asn_list.count()) if (item := self.asn_list.item(i))]
        if GUIDetectionSettings.asn_suspend_enabled:
            GUIDetectionSettings.asn_suspend_duration = read_duration_widgets_helper(self.asn_duration_combo, self.asn_duration_spin)
        GUIDetectionSettings.asn_voice_notifications = read_voice_combo_helper(self.asn_voice_combo)
        GUIDetectionSettings.asn_logging = self.asn_logging_checkbox.isChecked()
        GUIDetectionSettings.asn_message_box = self.asn_msgbox_checkbox.isChecked()

        # Player Join
        GUIDetectionSettings.player_join_enabled = self.player_join_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.player_join_enabled:
            GUIDetectionSettings.player_join_duration = read_duration_widgets_helper(self.player_join_duration_combo, self.player_join_duration_spin)
        GUIDetectionSettings.player_join_voice_notifications = read_voice_combo_helper(self.player_join_voice_combo)
        GUIDetectionSettings.player_join_logging = self.player_join_logging_checkbox.isChecked()
        GUIDetectionSettings.player_join_message_box = self.player_join_msgbox_checkbox.isChecked()

        # Player Rejoin
        GUIDetectionSettings.player_rejoin_enabled = self.player_rejoin_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.player_rejoin_enabled:
            GUIDetectionSettings.player_rejoin_duration = read_duration_widgets_helper(self.player_rejoin_duration_combo, self.player_rejoin_duration_spin)
        GUIDetectionSettings.player_rejoin_voice_notifications = read_voice_combo_helper(self.player_rejoin_voice_combo)
        GUIDetectionSettings.player_rejoin_logging = self.player_rejoin_logging_checkbox.isChecked()
        GUIDetectionSettings.player_rejoin_message_box = self.player_rejoin_msgbox_checkbox.isChecked()

        # Player Leave
        GUIDetectionSettings.player_leave_enabled = self.player_leave_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.player_leave_enabled:
            GUIDetectionSettings.player_leave_duration = read_duration_widgets_helper(self.player_leave_duration_combo, self.player_leave_duration_spin)
        GUIDetectionSettings.player_leave_voice_notifications = read_voice_combo_helper(self.player_leave_voice_combo)
        GUIDetectionSettings.player_leave_logging = self.player_leave_logging_checkbox.isChecked()
        GUIDetectionSettings.player_leave_message_box = self.player_leave_msgbox_checkbox.isChecked()

        # GTA5 Relay (only when the tab is present)
        if hasattr(self, 'gta5_relay_duration_combo'):
            GUIDetectionSettings.gta5_relay_enabled = self.gta5_relay_duration_combo.currentText() != 'Disabled'
            GUIDetectionSettings.gta5_relay_packet_threshold = self.gta5_relay_packet_threshold_spin.value()
            if GUIDetectionSettings.gta5_relay_enabled:
                GUIDetectionSettings.gta5_relay_duration = read_duration_widgets_helper(self.gta5_relay_duration_combo, self.gta5_relay_duration_spin)
            GUIDetectionSettings.gta5_relay_voice_notifications = read_voice_combo_helper(self.gta5_relay_voice_combo)
            GUIDetectionSettings.gta5_relay_logging = self.gta5_relay_logging_checkbox.isChecked()
            GUIDetectionSettings.gta5_relay_message_box = self.gta5_relay_msgbox_checkbox.isChecked()

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
        return value if isinstance(value, str) and value and value != _placeholder else None

    conditions: dict[str, str | bool | list[str]] = {}
    if (country := _safe(player.iplookup.geolite2.country)) is not None:
        conditions['country'] = country
    if (isp := _safe(player.iplookup.ipapi.isp)) is not None:
        conditions['isp'] = isp
    as_name = _safe(player.iplookup.ipapi.as_name)
    asn_geo = _safe(player.iplookup.geolite2.asn)
    asn_val = as_name if as_name is not None else asn_geo
    if asn_val is not None:
        conditions['as_name' if as_name is not None else 'asn'] = asn_val
    if isinstance(player.iplookup.ipapi.mobile, bool):
        conditions['mobile'] = player.iplookup.ipapi.mobile
    if isinstance(player.iplookup.ipapi.proxy, bool):
        conditions['vpn'] = player.iplookup.ipapi.proxy
    if isinstance(player.iplookup.ipapi.hosting, bool):
        conditions['hosting'] = player.iplookup.ipapi.hosting

    prefilled = ComboRule(name=f'Rule for {player.ip}', conditions=conditions) if conditions else None
    _exec_and_save_combo_rule(parent, prefilled)


def _exec_and_save_combo_rule(parent: QWidget, initial_rule: ComboRule | None = None) -> None:
    """Open the combo rule editor dialog and persist the rule on accept."""
    dialog = ComboRuleEditorDialog(parent, initial_rule)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        ComboRulesManager.rules.append(dialog.get_rule())
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        DetectionsManagerDialog.refresh_if_open()


def open_combo_rule_editor(parent: QWidget) -> None:
    """Open a blank combo rule editor and save the new rule on accept."""
    _exec_and_save_combo_rule(parent)
