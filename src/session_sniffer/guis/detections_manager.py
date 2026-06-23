"""Detections Manager dialog for configuring advanced per-detection rules."""

import json
from pathlib import Path
from typing import TYPE_CHECKING, cast, override

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
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
from session_sniffer.constants.local import COMBO_RULES_PATH, DETECTIONS_JSON_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._combo_rule_editor import ComboRuleEditorDialog
from session_sniffer.guis._detections_manager_tabs import DetectionsManagerTabsMixin
from session_sniffer.guis._dialog_mixins import UnsavedChangesMixin, setup_tab_dialog_buttons
from session_sniffer.guis.stylesheets import DETECTIONS_MANAGER_HEADER_STYLESHEET, DIALOG_BUTTON_STYLESHEET
from session_sniffer.guis.utils import get_screen_size, resize_window_for_screen, set_dialog_window_flags
from session_sniffer.player.combo_rules import ComboRule, ComboRulesManager
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from PyQt6.QtGui import QKeyEvent, QShowEvent

    from session_sniffer.models.player import Player


class DetectionsManagerDialog(UnsavedChangesMixin, DetectionsManagerTabsMixin, QDialog):
    """Comprehensive detections manager with VPN, IP range, and advanced threat detection capabilities."""

    def __init__(self, parent: QWidget) -> None:
        """Initialize the Detections Manager dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'{TITLE} - Detections Manager')
        set_dialog_window_flags(self)
        self.setMinimumSize(720, 560)
        screen_size = get_screen_size()
        resize_window_for_screen(self, screen_size)

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
        self.gta5_relay_detection_section: QWidget
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
        header = QLabel('🛡️ Advanced Detection & Security Manager')
        header.setStyleSheet(DETECTIONS_MANAGER_HEADER_STYLESHEET)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Tabs
        self._tabs = QTabWidget()
        self._tabs.addTab(self.create_player_events_tab(), '👤 Player Events')
        self._tabs.addTab(self.create_network_based_tab(), '🌐 Network-Based')
        self._tabs.addTab(self.create_geo_based_tab(), '🌍 Geography-Based')
        self._tabs.addTab(self.create_combo_rules_tab(), '🔗 Combo Rules')
        if Settings.is_gta5_preset():
            self._tabs.addTab(self.create_gta5_relays_tab(), '🎮 GTA5 Relays')
        layout.addWidget(self._tabs)

        # Bottom buttons
        button_row = QHBoxLayout()

        import_button = QPushButton('📥 Import')
        import_button.setToolTip('Import detection settings from a JSON file')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.clicked.connect(self._import_detections)
        button_row.addWidget(import_button)

        export_button = QPushButton('📤 Export')
        export_button.setToolTip('Export detection settings to a JSON file')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_detections)
        button_row.addWidget(export_button)

        reset_button = QPushButton('🔄 Reset all…')
        reset_button.setToolTip('Reset all detection settings to defaults')
        save_button = setup_tab_dialog_buttons(button_row, reset_button, self._reset_to_defaults, self._reset_current_tab)
        save_button.setToolTip('Save all detection settings')
        save_button.clicked.connect(self._save_and_apply)
        button_row.addWidget(save_button)

        cancel_button = QPushButton('❌ Cancel')
        cancel_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_button.clicked.connect(self.reject)
        button_row.addWidget(cancel_button)

        layout.addLayout(button_row)

        self._load_current_settings()
        self.refresh_detection_availability()
        if hasattr(self, 'gta5_relay_duration_combo'):
            self.gta5_relay_duration_combo.currentTextChanged.connect(self._on_gta5_relay_suspend_mode_changed)
        self._snapshot = self._read_all_widget_values()

    # ------------------------------------------------------------------
    # Detection support restrictions
    # ------------------------------------------------------------------

    def refresh_detection_availability(self) -> None:
        """Refresh detection action visibility based on current runtime support."""
        if not Settings.is_gta5_preset() or not CaptureState.is_local_capture():
            self._apply_detection_restrictions()
        else:
            self._remove_detection_restrictions()

    def _apply_detection_restrictions(self) -> None:
        """Hide all detection action widgets when detection is not supported (non-GTA5 preset or neighbour interface)."""
        for prefix in ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave', 'gta5_relay'):
            if not hasattr(self, f'{prefix}_detection_section'):
                continue
            detection_section: QWidget = getattr(self, f'{prefix}_detection_section')
            detection_section.setVisible(False)

    def _remove_detection_restrictions(self) -> None:
        """Show all detection action widgets when detection is supported."""
        for prefix in ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave', 'gta5_relay'):
            if not hasattr(self, f'{prefix}_detection_section'):
                continue
            detection_section: QWidget = getattr(self, f'{prefix}_detection_section')
            detection_section.setVisible(True)

    # ------------------------------------------------------------------
    # Settings load / save
    # ------------------------------------------------------------------

    def _load_current_settings(self) -> None:
        """Read GUIDetectionSettings and populate all widgets."""
        # Mobile
        self._set_duration_widgets(
            self.mobile_duration_combo,
            self.mobile_duration_spin,
            GUIDetectionSettings.mobile_suspend_duration if GUIDetectionSettings.mobile_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.mobile_voice_combo, GUIDetectionSettings.mobile_voice_notifications)
        self.mobile_logging_checkbox.setChecked(GUIDetectionSettings.mobile_logging)
        self.mobile_msgbox_checkbox.setChecked(GUIDetectionSettings.mobile_message_box)

        # VPN
        self._set_duration_widgets(
            self.vpn_duration_combo,
            self.vpn_duration_spin,
            GUIDetectionSettings.vpn_suspend_duration if GUIDetectionSettings.vpn_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.vpn_voice_combo, GUIDetectionSettings.vpn_voice_notifications)
        self.vpn_logging_checkbox.setChecked(GUIDetectionSettings.vpn_logging)
        self.vpn_msgbox_checkbox.setChecked(GUIDetectionSettings.vpn_message_box)

        # Hosting
        self._set_duration_widgets(
            self.hosting_duration_combo,
            self.hosting_duration_spin,
            GUIDetectionSettings.hosting_suspend_duration if GUIDetectionSettings.hosting_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.hosting_voice_combo, GUIDetectionSettings.hosting_voice_notifications)
        self.hosting_logging_checkbox.setChecked(GUIDetectionSettings.hosting_logging)
        self.hosting_msgbox_checkbox.setChecked(GUIDetectionSettings.hosting_message_box)

        # Country
        self.country_list.clear()
        seen_countries: set[str] = set()
        for country in GUIDetectionSettings.country_detection_list:
            if country not in seen_countries:
                seen_countries.add(country)
                self._add_country_item(country)
        self._set_duration_widgets(
            self.country_duration_combo,
            self.country_duration_spin,
            GUIDetectionSettings.country_suspend_duration if GUIDetectionSettings.country_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.country_voice_combo, GUIDetectionSettings.country_voice_notifications)
        self.country_logging_checkbox.setChecked(GUIDetectionSettings.country_logging)
        self.country_msgbox_checkbox.setChecked(GUIDetectionSettings.country_message_box)

        # ISP
        self.isp_list.clear()
        seen_isps: set[str] = set()
        for isp in GUIDetectionSettings.isp_detection_list:
            if isp not in seen_isps:
                seen_isps.add(isp)
                self.isp_list.addItem(isp)
        self._set_duration_widgets(
            self.isp_duration_combo,
            self.isp_duration_spin,
            GUIDetectionSettings.isp_suspend_duration if GUIDetectionSettings.isp_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.isp_voice_combo, GUIDetectionSettings.isp_voice_notifications)
        self.isp_logging_checkbox.setChecked(GUIDetectionSettings.isp_logging)
        self.isp_msgbox_checkbox.setChecked(GUIDetectionSettings.isp_message_box)

        # ASN
        self.asn_list.clear()
        seen_asns: set[str] = set()
        for asn in GUIDetectionSettings.asn_detection_list:
            if asn not in seen_asns:
                seen_asns.add(asn)
                self.asn_list.addItem(asn)
        self._set_duration_widgets(
            self.asn_duration_combo,
            self.asn_duration_spin,
            GUIDetectionSettings.asn_suspend_duration if GUIDetectionSettings.asn_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.asn_voice_combo, GUIDetectionSettings.asn_voice_notifications)
        self.asn_logging_checkbox.setChecked(GUIDetectionSettings.asn_logging)
        self.asn_msgbox_checkbox.setChecked(GUIDetectionSettings.asn_message_box)

        # Player Join
        self._set_duration_widgets(
            self.player_join_duration_combo,
            self.player_join_duration_spin,
            GUIDetectionSettings.player_join_duration if GUIDetectionSettings.player_join_enabled else 'Disabled',
        )
        self._set_voice_combo(self.player_join_voice_combo, GUIDetectionSettings.player_join_voice_notifications)
        self.player_join_logging_checkbox.setChecked(GUIDetectionSettings.player_join_logging)
        self.player_join_msgbox_checkbox.setChecked(GUIDetectionSettings.player_join_message_box)

        # Player Rejoin
        self._set_duration_widgets(
            self.player_rejoin_duration_combo,
            self.player_rejoin_duration_spin,
            GUIDetectionSettings.player_rejoin_duration if GUIDetectionSettings.player_rejoin_enabled else 'Disabled',
        )
        self._set_voice_combo(self.player_rejoin_voice_combo, GUIDetectionSettings.player_rejoin_voice_notifications)
        self.player_rejoin_logging_checkbox.setChecked(GUIDetectionSettings.player_rejoin_logging)
        self.player_rejoin_msgbox_checkbox.setChecked(GUIDetectionSettings.player_rejoin_message_box)

        # Player Leave
        self._set_duration_widgets(
            self.player_leave_duration_combo,
            self.player_leave_duration_spin,
            GUIDetectionSettings.player_leave_duration if GUIDetectionSettings.player_leave_enabled else 'Disabled',
        )
        self._set_voice_combo(self.player_leave_voice_combo, GUIDetectionSettings.player_leave_voice_notifications)
        self.player_leave_logging_checkbox.setChecked(GUIDetectionSettings.player_leave_logging)
        self.player_leave_msgbox_checkbox.setChecked(GUIDetectionSettings.player_leave_message_box)

        # GTA5 Relay (only when the tab is present)
        if hasattr(self, 'gta5_relay_duration_combo'):
            self.gta5_relay_packet_threshold_spin.setValue(GUIDetectionSettings.gta5_relay_packet_threshold)
            self._set_duration_widgets(
                self.gta5_relay_duration_combo,
                self.gta5_relay_duration_spin,
                GUIDetectionSettings.gta5_relay_duration if GUIDetectionSettings.gta5_relay_enabled else 'Disabled',
            )
            self._set_voice_combo(self.gta5_relay_voice_combo, GUIDetectionSettings.gta5_relay_voice_notifications)
            self.gta5_relay_logging_checkbox.setChecked(GUIDetectionSettings.gta5_relay_logging)
            self.gta5_relay_msgbox_checkbox.setChecked(GUIDetectionSettings.gta5_relay_message_box)

        # Combo Rules
        self.refresh_combo_rules_list()

    def _save_and_apply(self) -> None:
        """Read widgets, write GUIDetectionSettings, persist to Settings.ini, and close."""
        # Clear voice queue if any detection was newly disabled
        enabled_fields = [
            'mobile_suspend_enabled',
            'vpn_suspend_enabled',
            'hosting_suspend_enabled',
            'country_suspend_enabled',
            'isp_suspend_enabled',
            'asn_suspend_enabled',
            'player_join_enabled',
            'player_rejoin_enabled',
            'player_leave_enabled',
            'gta5_relay_enabled',
        ]
        checkbox_prefixes = [
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
        ]
        for field, prefix in zip(enabled_fields, checkbox_prefixes, strict=True):
            if not hasattr(self, f'{prefix}_duration_combo'):
                continue
            if getattr(GUIDetectionSettings, field) and getattr(self, f'{prefix}_duration_combo').currentText() == 'Disabled':
                clear_voice_notification_queue()
                break

        self._save_widgets_to_singleton()

        GUIDetectionSettings.export_to_file(DETECTIONS_JSON_PATH)
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.accept()

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
            target = Path(file_path)
            GUIDetectionSettings.export_to_file(target)
            data: object = json.loads(target.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                message = 'Expected a JSON object in the exported file.'
                raise RuntimeError(message)
            data_dict = cast('dict[str, object]', data)
            data_dict['combo_rules'] = [rule.to_dict() for rule in ComboRulesManager.rules]
            target.write_text(json.dumps(data_dict, indent=4), encoding='utf-8')
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
                raw: object = json.loads(Path(file_path).read_text(encoding='utf-8'))
                GUIDetectionSettings.import_from_file(Path(file_path))
                # Import combo rules if present
                if isinstance(raw, dict):
                    raw_dict = cast('dict[str, object]', raw)
                    combo_data: object = raw_dict.get('combo_rules')
                    if isinstance(combo_data, list):
                        ComboRulesManager.rules = [
                            ComboRule.from_dict(cast('dict[str, object]', entry)) for entry in cast('list[object]', combo_data) if isinstance(entry, dict)
                        ]
            except (ValueError, KeyError, OSError, json.JSONDecodeError) as e:
                QMessageBox.critical(self, 'Import Error', f'Failed to import settings:\n{e}')
                return
            self._load_current_settings()
            QMessageBox.information(self, TITLE, 'Detection settings imported successfully.')

    def _reset_tab_to_defaults(self, prefixes: tuple[str, ...]) -> None:
        """Reset all detection widgets for the given *prefixes* to their default values without saving."""
        for prefix in prefixes:
            self._set_duration_widgets(
                getattr(self, f'{prefix}_duration_combo'),
                getattr(self, f'{prefix}_duration_spin'),
                'Disabled',
            )
            self._set_voice_combo(getattr(self, f'{prefix}_voice_combo'), value=False)
            getattr(self, f'{prefix}_logging_checkbox').setChecked(False)
            getattr(self, f'{prefix}_msgbox_checkbox').setChecked(False)
            if hasattr(self, f'{prefix}_list'):
                getattr(self, f'{prefix}_list').clear()
            if prefix == 'gta5_relay':
                self.gta5_relay_packet_threshold_spin.setValue(40)

    def _reset_current_tab(self) -> None:
        """Reset the current tab's detection widgets to their default values."""
        index_to_prefixes: dict[int, tuple[str, ...]] = {
            0: ('player_join', 'player_rejoin', 'player_leave'),
            1: ('mobile', 'vpn', 'hosting'),
            2: ('country', 'isp', 'asn'),
            4: ('gta5_relay',),
        }
        prefixes = index_to_prefixes.get(self._tabs.currentIndex())
        if prefixes is None:
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
            GUIDetectionSettings.mobile_suspend_duration = self._read_duration_widgets(self.mobile_duration_combo, self.mobile_duration_spin)
        GUIDetectionSettings.mobile_voice_notifications = self._read_voice_combo(self.mobile_voice_combo)
        GUIDetectionSettings.mobile_logging = self.mobile_logging_checkbox.isChecked()
        GUIDetectionSettings.mobile_message_box = self.mobile_msgbox_checkbox.isChecked()

        # VPN
        GUIDetectionSettings.vpn_suspend_enabled = self.vpn_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.vpn_suspend_enabled:
            GUIDetectionSettings.vpn_suspend_duration = self._read_duration_widgets(self.vpn_duration_combo, self.vpn_duration_spin)
        GUIDetectionSettings.vpn_voice_notifications = self._read_voice_combo(self.vpn_voice_combo)
        GUIDetectionSettings.vpn_logging = self.vpn_logging_checkbox.isChecked()
        GUIDetectionSettings.vpn_message_box = self.vpn_msgbox_checkbox.isChecked()

        # Hosting
        GUIDetectionSettings.hosting_suspend_enabled = self.hosting_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.hosting_suspend_enabled:
            GUIDetectionSettings.hosting_suspend_duration = self._read_duration_widgets(self.hosting_duration_combo, self.hosting_duration_spin)
        GUIDetectionSettings.hosting_voice_notifications = self._read_voice_combo(self.hosting_voice_combo)
        GUIDetectionSettings.hosting_logging = self.hosting_logging_checkbox.isChecked()
        GUIDetectionSettings.hosting_message_box = self.hosting_msgbox_checkbox.isChecked()

        # Country
        GUIDetectionSettings.country_suspend_enabled = self.country_duration_combo.currentText() != 'Disabled'
        GUIDetectionSettings.country_detection_list = [
            item.data(Qt.ItemDataRole.UserRole) for i in range(self.country_list.count()) if (item := self.country_list.item(i)) is not None
        ]
        if GUIDetectionSettings.country_suspend_enabled:
            GUIDetectionSettings.country_suspend_duration = self._read_duration_widgets(self.country_duration_combo, self.country_duration_spin)
        GUIDetectionSettings.country_voice_notifications = self._read_voice_combo(self.country_voice_combo)
        GUIDetectionSettings.country_logging = self.country_logging_checkbox.isChecked()
        GUIDetectionSettings.country_message_box = self.country_msgbox_checkbox.isChecked()

        # ISP
        GUIDetectionSettings.isp_suspend_enabled = self.isp_duration_combo.currentText() != 'Disabled'
        GUIDetectionSettings.isp_detection_list = [item.text() for i in range(self.isp_list.count()) if (item := self.isp_list.item(i)) is not None]
        if GUIDetectionSettings.isp_suspend_enabled:
            GUIDetectionSettings.isp_suspend_duration = self._read_duration_widgets(self.isp_duration_combo, self.isp_duration_spin)
        GUIDetectionSettings.isp_voice_notifications = self._read_voice_combo(self.isp_voice_combo)
        GUIDetectionSettings.isp_logging = self.isp_logging_checkbox.isChecked()
        GUIDetectionSettings.isp_message_box = self.isp_msgbox_checkbox.isChecked()

        # ASN
        GUIDetectionSettings.asn_suspend_enabled = self.asn_duration_combo.currentText() != 'Disabled'
        GUIDetectionSettings.asn_detection_list = [item.text() for i in range(self.asn_list.count()) if (item := self.asn_list.item(i)) is not None]
        if GUIDetectionSettings.asn_suspend_enabled:
            GUIDetectionSettings.asn_suspend_duration = self._read_duration_widgets(self.asn_duration_combo, self.asn_duration_spin)
        GUIDetectionSettings.asn_voice_notifications = self._read_voice_combo(self.asn_voice_combo)
        GUIDetectionSettings.asn_logging = self.asn_logging_checkbox.isChecked()
        GUIDetectionSettings.asn_message_box = self.asn_msgbox_checkbox.isChecked()

        # Player Join
        GUIDetectionSettings.player_join_enabled = self.player_join_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.player_join_enabled:
            GUIDetectionSettings.player_join_duration = self._read_duration_widgets(self.player_join_duration_combo, self.player_join_duration_spin)
        GUIDetectionSettings.player_join_voice_notifications = self._read_voice_combo(self.player_join_voice_combo)
        GUIDetectionSettings.player_join_logging = self.player_join_logging_checkbox.isChecked()
        GUIDetectionSettings.player_join_message_box = self.player_join_msgbox_checkbox.isChecked()

        # Player Rejoin
        GUIDetectionSettings.player_rejoin_enabled = self.player_rejoin_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.player_rejoin_enabled:
            GUIDetectionSettings.player_rejoin_duration = self._read_duration_widgets(self.player_rejoin_duration_combo, self.player_rejoin_duration_spin)
        GUIDetectionSettings.player_rejoin_voice_notifications = self._read_voice_combo(self.player_rejoin_voice_combo)
        GUIDetectionSettings.player_rejoin_logging = self.player_rejoin_logging_checkbox.isChecked()
        GUIDetectionSettings.player_rejoin_message_box = self.player_rejoin_msgbox_checkbox.isChecked()

        # Player Leave
        GUIDetectionSettings.player_leave_enabled = self.player_leave_duration_combo.currentText() != 'Disabled'
        if GUIDetectionSettings.player_leave_enabled:
            GUIDetectionSettings.player_leave_duration = self._read_duration_widgets(self.player_leave_duration_combo, self.player_leave_duration_spin)
        GUIDetectionSettings.player_leave_voice_notifications = self._read_voice_combo(self.player_leave_voice_combo)
        GUIDetectionSettings.player_leave_logging = self.player_leave_logging_checkbox.isChecked()
        GUIDetectionSettings.player_leave_message_box = self.player_leave_msgbox_checkbox.isChecked()

        # GTA5 Relay (only when the tab is present)
        if hasattr(self, 'gta5_relay_duration_combo'):
            GUIDetectionSettings.gta5_relay_enabled = self.gta5_relay_duration_combo.currentText() != 'Disabled'
            GUIDetectionSettings.gta5_relay_packet_threshold = self.gta5_relay_packet_threshold_spin.value()
            if GUIDetectionSettings.gta5_relay_enabled:
                GUIDetectionSettings.gta5_relay_duration = self._read_duration_widgets(self.gta5_relay_duration_combo, self.gta5_relay_duration_spin)
            GUIDetectionSettings.gta5_relay_voice_notifications = self._read_voice_combo(self.gta5_relay_voice_combo)
            GUIDetectionSettings.gta5_relay_logging = self.gta5_relay_logging_checkbox.isChecked()
            GUIDetectionSettings.gta5_relay_message_box = self.gta5_relay_msgbox_checkbox.isChecked()

    def _read_all_widget_values(self) -> dict[str, object]:
        """Capture a comparable snapshot of all widget values."""
        values: dict[str, object] = {
            'mobile_enabled': self.mobile_duration_combo.currentText() != 'Disabled',
            'mobile_duration': self._read_duration_widgets(self.mobile_duration_combo, self.mobile_duration_spin),
            'mobile_voice': self._read_voice_combo(self.mobile_voice_combo),
            'mobile_logging': self.mobile_logging_checkbox.isChecked(),
            'mobile_msgbox': self.mobile_msgbox_checkbox.isChecked(),
            'vpn_enabled': self.vpn_duration_combo.currentText() != 'Disabled',
            'vpn_duration': self._read_duration_widgets(self.vpn_duration_combo, self.vpn_duration_spin),
            'vpn_voice': self._read_voice_combo(self.vpn_voice_combo),
            'vpn_logging': self.vpn_logging_checkbox.isChecked(),
            'vpn_msgbox': self.vpn_msgbox_checkbox.isChecked(),
            'hosting_enabled': self.hosting_duration_combo.currentText() != 'Disabled',
            'hosting_duration': self._read_duration_widgets(self.hosting_duration_combo, self.hosting_duration_spin),
            'hosting_voice': self._read_voice_combo(self.hosting_voice_combo),
            'hosting_logging': self.hosting_logging_checkbox.isChecked(),
            'hosting_msgbox': self.hosting_msgbox_checkbox.isChecked(),
            'country_enabled': self.country_duration_combo.currentText() != 'Disabled',
            'country_list': tuple(item.data(Qt.ItemDataRole.UserRole) for i in range(self.country_list.count()) if (item := self.country_list.item(i)) is not None),
            'country_duration': self._read_duration_widgets(self.country_duration_combo, self.country_duration_spin),
            'country_voice': self._read_voice_combo(self.country_voice_combo),
            'country_logging': self.country_logging_checkbox.isChecked(),
            'country_msgbox': self.country_msgbox_checkbox.isChecked(),
            'isp_enabled': self.isp_duration_combo.currentText() != 'Disabled',
            'isp_list': tuple(item.text() for i in range(self.isp_list.count()) if (item := self.isp_list.item(i)) is not None),
            'isp_duration': self._read_duration_widgets(self.isp_duration_combo, self.isp_duration_spin),
            'isp_voice': self._read_voice_combo(self.isp_voice_combo),
            'isp_logging': self.isp_logging_checkbox.isChecked(),
            'isp_msgbox': self.isp_msgbox_checkbox.isChecked(),
            'asn_enabled': self.asn_duration_combo.currentText() != 'Disabled',
            'asn_list': tuple(item.text() for i in range(self.asn_list.count()) if (item := self.asn_list.item(i)) is not None),
            'asn_duration': self._read_duration_widgets(self.asn_duration_combo, self.asn_duration_spin),
            'asn_voice': self._read_voice_combo(self.asn_voice_combo),
            'asn_logging': self.asn_logging_checkbox.isChecked(),
            'asn_msgbox': self.asn_msgbox_checkbox.isChecked(),
            'player_join_enabled': self.player_join_duration_combo.currentText() != 'Disabled',
            'player_join_duration': self._read_duration_widgets(self.player_join_duration_combo, self.player_join_duration_spin),
            'player_join_voice': self._read_voice_combo(self.player_join_voice_combo),
            'player_join_logging': self.player_join_logging_checkbox.isChecked(),
            'player_join_msgbox': self.player_join_msgbox_checkbox.isChecked(),
            'player_rejoin_enabled': self.player_rejoin_duration_combo.currentText() != 'Disabled',
            'player_rejoin_duration': self._read_duration_widgets(self.player_rejoin_duration_combo, self.player_rejoin_duration_spin),
            'player_rejoin_voice': self._read_voice_combo(self.player_rejoin_voice_combo),
            'player_rejoin_logging': self.player_rejoin_logging_checkbox.isChecked(),
            'player_rejoin_msgbox': self.player_rejoin_msgbox_checkbox.isChecked(),
            'player_leave_enabled': self.player_leave_duration_combo.currentText() != 'Disabled',
            'player_leave_duration': self._read_duration_widgets(self.player_leave_duration_combo, self.player_leave_duration_spin),
            'player_leave_voice': self._read_voice_combo(self.player_leave_voice_combo),
            'player_leave_logging': self.player_leave_logging_checkbox.isChecked(),
            'player_leave_msgbox': self.player_leave_msgbox_checkbox.isChecked(),
            'combo_rules': [rule.to_dict() for rule in ComboRulesManager.rules],
        }
        if hasattr(self, 'gta5_relay_duration_combo'):
            values['gta5_relay_enabled'] = self.gta5_relay_duration_combo.currentText() != 'Disabled'
            values['gta5_relay_packet_threshold'] = self.gta5_relay_packet_threshold_spin.value()
            values['gta5_relay_duration'] = self._read_duration_widgets(self.gta5_relay_duration_combo, self.gta5_relay_duration_spin)
            values['gta5_relay_voice'] = self._read_voice_combo(self.gta5_relay_voice_combo)
            values['gta5_relay_logging'] = self.gta5_relay_logging_checkbox.isChecked()
            values['gta5_relay_msgbox'] = self.gta5_relay_msgbox_checkbox.isChecked()
        return values

    @override
    def keyPressEvent(self, a0: QKeyEvent | None) -> None:
        """Consume Enter/Return when the combo rules list has focus to prevent triggering the default button."""
        if a0 is not None and a0.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self._combo_rules_list.hasFocus():
            return
        super().keyPressEvent(a0)

    def _has_unsaved_changes(self) -> bool:
        """Return True if any widget value differs from the state when the dialog was opened."""
        return self._read_all_widget_values() != self._snapshot

    @override
    def _has_unsaved_changes_for_close(self) -> bool:
        """Return `True` if there are unsaved changes that should be saved before closing."""
        return self._has_unsaved_changes()

    @override
    def _save_on_close(self) -> bool:
        """Save and apply detection settings; always succeeds."""
        self._save_and_apply()
        return True

    @override
    def showEvent(self, a0: QShowEvent | None) -> None:
        """Handle the window show event and maximize if required."""
        super().showEvent(a0)
        if self.property('_should_maximize_on_show') is True:
            self.setProperty('_should_maximize_on_show', value=False)
            self.showMaximized()


def open_combo_rule_editor_for_player(parent: QWidget, player: Player) -> None:
    """Open the combo rule editor pre-filled with the player's known IP lookup attributes."""
    _placeholder = '...'

    def _safe(value: object) -> str | None:
        return value if isinstance(value, str) and value and value != _placeholder else None

    conditions: dict[str, str | bool | list[str]] = {}
    if country := _safe(player.iplookup.geolite2.country):
        conditions['country'] = country
    if isp := _safe(player.iplookup.ipapi.isp):
        conditions['isp'] = isp
    as_name = _safe(player.iplookup.ipapi.as_name)
    asn_geo = _safe(player.iplookup.geolite2.asn)
    if asn_val := (as_name or asn_geo):
        conditions['as_name' if as_name else 'asn'] = asn_val
    if isinstance(player.iplookup.ipapi.mobile, bool):
        conditions['mobile'] = player.iplookup.ipapi.mobile
    if isinstance(player.iplookup.ipapi.proxy, bool):
        conditions['vpn'] = player.iplookup.ipapi.proxy
    if isinstance(player.iplookup.ipapi.hosting, bool):
        conditions['hosting'] = player.iplookup.ipapi.hosting

    prefilled = ComboRule(name=f'Rule for {player.ip}', conditions=conditions) if conditions else None
    dialog = ComboRuleEditorDialog(parent, prefilled)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        ComboRulesManager.rules.append(dialog.get_rule())
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)


def open_combo_rule_editor(parent: QWidget) -> None:
    """Open a blank combo rule editor and save the new rule on accept."""
    dialog = ComboRuleEditorDialog(parent)
    if dialog.exec() == QDialog.DialogCode.Accepted:
        ComboRulesManager.rules.append(dialog.get_rule())
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
