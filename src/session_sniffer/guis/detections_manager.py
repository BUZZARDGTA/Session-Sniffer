"""Detections Manager dialog for configuring advanced per-detection protection rules."""

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
from session_sniffer.constants.local import COMBO_RULES_PATH, PROTECTIONS_JSON_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._combo_rule_editor import ComboRuleEditorDialog
from session_sniffer.guis._detections_manager_tabs import DetectionsManagerTabsMixin
from session_sniffer.guis._dialog_mixins import UnsavedChangesMixin, setup_tab_dialog_buttons
from session_sniffer.guis.stylesheets import DETECTIONS_MANAGER_HEADER_STYLESHEET, DIALOG_BUTTON_STYLESHEET
from session_sniffer.guis.utils import set_dialog_window_flags
from session_sniffer.player.combo_rules import ComboRule, ComboRulesManager
from session_sniffer.player.protections import GUIProtectionSettings
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings

if TYPE_CHECKING:
    from PyQt6.QtGui import QKeyEvent

    from session_sniffer.models.player import Player


class DetectionsManagerDialog(UnsavedChangesMixin, DetectionsManagerTabsMixin, QDialog):
    """Comprehensive detections manager with VPN, IP range, and advanced threat detection capabilities."""

    def __init__(self, parent: QWidget) -> None:
        """Initialize the Detections Manager dialog."""
        super().__init__(parent)
        self.setWindowTitle(f'{TITLE} - Detections Manager')
        self.setMinimumSize(720, 560)
        self.resize(800, 640)
        set_dialog_window_flags(self)

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
        self.gta5_relay_action_section: QWidget
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
        header = QLabel('\U0001f6e1\ufe0f Advanced Protection & Security Manager')
        header.setStyleSheet(DETECTIONS_MANAGER_HEADER_STYLESHEET)
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        # Tabs
        self._tabs = QTabWidget()
        self._tabs.addTab(self.create_player_events_tab(), '\U0001f464 Player Events')
        self._tabs.addTab(self.create_network_based_tab(), '\U0001f310 Network-Based')
        self._tabs.addTab(self.create_geo_based_tab(), '\U0001f30d Geography-Based')
        self._tabs.addTab(self.create_combo_rules_tab(), '\U0001f517 Combo Rules')
        if Settings.capture_game_preset == 'GTA5':
            self._tabs.addTab(self.create_gta5_relays_tab(), '\U0001f3ae GTA5 Relays')
        layout.addWidget(self._tabs)

        # Bottom buttons
        button_row = QHBoxLayout()

        import_button = QPushButton('\U0001f4e5 Import')
        import_button.setToolTip('Import protection settings from a JSON file')
        import_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        import_button.clicked.connect(self._import_protections)
        button_row.addWidget(import_button)

        export_button = QPushButton('\U0001f4e4 Export')
        export_button.setToolTip('Export protection settings to a JSON file')
        export_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        export_button.clicked.connect(self._export_protections)
        button_row.addWidget(export_button)

        reset_button = QPushButton('\U0001f504 Reset all…')
        reset_button.setToolTip('Reset all protection settings to defaults')
        save_button = setup_tab_dialog_buttons(button_row, reset_button, self._reset_to_defaults, self._reset_current_tab)
        save_button.setToolTip('Save all protection settings')
        save_button.clicked.connect(self._save_and_apply)
        button_row.addWidget(save_button)

        cancel_button = QPushButton('\u274c Cancel')
        cancel_button.setStyleSheet(DIALOG_BUTTON_STYLESHEET)
        cancel_button.clicked.connect(self.reject)
        button_row.addWidget(cancel_button)

        layout.addLayout(button_row)

        self._load_current_settings()
        self.refresh_protection_availability()
        if hasattr(self, 'gta5_relay_duration_combo'):
            self.gta5_relay_duration_combo.currentTextChanged.connect(self._on_gta5_relay_suspend_mode_changed)
        self._snapshot = self._read_all_widget_values()

    # ------------------------------------------------------------------
    # Protection support restrictions
    # ------------------------------------------------------------------

    def refresh_protection_availability(self) -> None:
        """Refresh protection action visibility based on current runtime support."""
        if Settings.capture_game_preset != 'GTA5' or CaptureState.is_neighbour_interface:
            self._apply_protection_restrictions()
        else:
            self._remove_protection_restrictions()

    def _apply_protection_restrictions(self) -> None:
        """Hide all protection action widgets when protection is not supported (non-GTA5 preset or neighbour interface)."""
        for prefix in ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave', 'gta5_relay'):
            if not hasattr(self, f'{prefix}_action_section'):
                continue
            action_section: QWidget = getattr(self, f'{prefix}_action_section')
            action_section.setVisible(False)

    def _remove_protection_restrictions(self) -> None:
        """Show all protection action widgets when protection is supported."""
        for prefix in ('mobile', 'vpn', 'hosting', 'country', 'isp', 'asn', 'player_join', 'player_rejoin', 'player_leave', 'gta5_relay'):
            if not hasattr(self, f'{prefix}_action_section'):
                continue
            action_section: QWidget = getattr(self, f'{prefix}_action_section')
            action_section.setVisible(True)

    # ------------------------------------------------------------------
    # Settings load / save
    # ------------------------------------------------------------------

    def _load_current_settings(self) -> None:
        """Read GUIProtectionSettings and populate all widgets."""
        # Mobile
        self._set_duration_widgets(
            self.mobile_duration_combo, self.mobile_duration_spin,
            GUIProtectionSettings.mobile_suspend_duration if GUIProtectionSettings.mobile_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.mobile_voice_combo, GUIProtectionSettings.mobile_voice_notifications)
        self.mobile_logging_checkbox.setChecked(GUIProtectionSettings.mobile_logging)
        self.mobile_msgbox_checkbox.setChecked(GUIProtectionSettings.mobile_message_box)

        # VPN
        self._set_duration_widgets(
            self.vpn_duration_combo, self.vpn_duration_spin,
            GUIProtectionSettings.vpn_suspend_duration if GUIProtectionSettings.vpn_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.vpn_voice_combo, GUIProtectionSettings.vpn_voice_notifications)
        self.vpn_logging_checkbox.setChecked(GUIProtectionSettings.vpn_logging)
        self.vpn_msgbox_checkbox.setChecked(GUIProtectionSettings.vpn_message_box)

        # Hosting
        self._set_duration_widgets(
            self.hosting_duration_combo, self.hosting_duration_spin,
            GUIProtectionSettings.hosting_suspend_duration if GUIProtectionSettings.hosting_suspend_enabled else 'Disabled',
        )
        self._set_voice_combo(self.hosting_voice_combo, GUIProtectionSettings.hosting_voice_notifications)
        self.hosting_logging_checkbox.setChecked(GUIProtectionSettings.hosting_logging)
        self.hosting_msgbox_checkbox.setChecked(GUIProtectionSettings.hosting_message_box)

        # Country
        self.country_list.clear()
        seen_countries: set[str] = set()
        for c in GUIProtectionSettings.country_block_list:
            if c not in seen_countries:
                seen_countries.add(c)
                self._add_country_item(c)
        self._set_duration_widgets(
            self.country_duration_combo, self.country_duration_spin,
            GUIProtectionSettings.country_block_duration if GUIProtectionSettings.country_block_enabled else 'Disabled',
        )
        self._set_voice_combo(self.country_voice_combo, GUIProtectionSettings.country_voice_notifications)
        self.country_logging_checkbox.setChecked(GUIProtectionSettings.country_logging)
        self.country_msgbox_checkbox.setChecked(GUIProtectionSettings.country_message_box)

        # ISP
        self.isp_list.clear()
        seen_isps: set[str] = set()
        for i in GUIProtectionSettings.isp_block_list:
            if i not in seen_isps:
                seen_isps.add(i)
                self.isp_list.addItem(i)
        self._set_duration_widgets(
            self.isp_duration_combo, self.isp_duration_spin,
            GUIProtectionSettings.isp_block_duration if GUIProtectionSettings.isp_block_enabled else 'Disabled',
        )
        self._set_voice_combo(self.isp_voice_combo, GUIProtectionSettings.isp_voice_notifications)
        self.isp_logging_checkbox.setChecked(GUIProtectionSettings.isp_logging)
        self.isp_msgbox_checkbox.setChecked(GUIProtectionSettings.isp_message_box)

        # ASN
        self.asn_list.clear()
        seen_asns: set[str] = set()
        for a in GUIProtectionSettings.asn_block_list:
            if a not in seen_asns:
                seen_asns.add(a)
                self.asn_list.addItem(a)
        self._set_duration_widgets(
            self.asn_duration_combo, self.asn_duration_spin,
            GUIProtectionSettings.asn_block_duration if GUIProtectionSettings.asn_block_enabled else 'Disabled',
        )
        self._set_voice_combo(self.asn_voice_combo, GUIProtectionSettings.asn_voice_notifications)
        self.asn_logging_checkbox.setChecked(GUIProtectionSettings.asn_logging)
        self.asn_msgbox_checkbox.setChecked(GUIProtectionSettings.asn_message_box)

        # Player Join
        self._set_duration_widgets(
            self.player_join_duration_combo, self.player_join_duration_spin,
            GUIProtectionSettings.player_join_duration if GUIProtectionSettings.player_join_enabled else 'Disabled',
        )
        self._set_voice_combo(self.player_join_voice_combo, GUIProtectionSettings.player_join_voice_notifications)
        self.player_join_logging_checkbox.setChecked(GUIProtectionSettings.player_join_logging)
        self.player_join_msgbox_checkbox.setChecked(GUIProtectionSettings.player_join_message_box)

        # Player Rejoin
        self._set_duration_widgets(
            self.player_rejoin_duration_combo, self.player_rejoin_duration_spin,
            GUIProtectionSettings.player_rejoin_duration if GUIProtectionSettings.player_rejoin_enabled else 'Disabled',
        )
        self._set_voice_combo(self.player_rejoin_voice_combo, GUIProtectionSettings.player_rejoin_voice_notifications)
        self.player_rejoin_logging_checkbox.setChecked(GUIProtectionSettings.player_rejoin_logging)
        self.player_rejoin_msgbox_checkbox.setChecked(GUIProtectionSettings.player_rejoin_message_box)

        # Player Leave
        self._set_duration_widgets(
            self.player_leave_duration_combo, self.player_leave_duration_spin,
            GUIProtectionSettings.player_leave_duration if GUIProtectionSettings.player_leave_enabled else 'Disabled',
        )
        self._set_voice_combo(self.player_leave_voice_combo, GUIProtectionSettings.player_leave_voice_notifications)
        self.player_leave_logging_checkbox.setChecked(GUIProtectionSettings.player_leave_logging)
        self.player_leave_msgbox_checkbox.setChecked(GUIProtectionSettings.player_leave_message_box)

        # GTA5 Relay (only when the tab is present)
        if hasattr(self, 'gta5_relay_duration_combo'):
            self.gta5_relay_packet_threshold_spin.setValue(GUIProtectionSettings.gta5_relay_packet_threshold)
            self._set_duration_widgets(
                self.gta5_relay_duration_combo, self.gta5_relay_duration_spin,
                GUIProtectionSettings.gta5_relay_duration if GUIProtectionSettings.gta5_relay_enabled else 'Disabled',
            )
            self._set_voice_combo(self.gta5_relay_voice_combo, GUIProtectionSettings.gta5_relay_voice_notifications)
            self.gta5_relay_logging_checkbox.setChecked(GUIProtectionSettings.gta5_relay_logging)
            self.gta5_relay_msgbox_checkbox.setChecked(GUIProtectionSettings.gta5_relay_message_box)

        # Combo Rules
        self.refresh_combo_rules_list()

    def _save_and_apply(self) -> None:
        """Read widgets, write GUIProtectionSettings, persist to Settings.ini, and close."""
        # Clear voice queue if any protection was newly disabled
        enabled_fields = [
            'mobile_suspend_enabled', 'vpn_suspend_enabled', 'hosting_suspend_enabled',
            'country_block_enabled', 'isp_block_enabled',
            'asn_block_enabled', 'player_join_enabled', 'player_rejoin_enabled', 'player_leave_enabled',
            'gta5_relay_enabled',
        ]
        checkbox_prefixes = [
            'mobile', 'vpn', 'hosting', 'country', 'isp', 'asn',
            'player_join', 'player_rejoin', 'player_leave',
            'gta5_relay',
        ]
        for field, prefix in zip(enabled_fields, checkbox_prefixes, strict=True):
            if not hasattr(self, f'{prefix}_duration_combo'):
                continue
            if getattr(GUIProtectionSettings, field) and getattr(self, f'{prefix}_duration_combo').currentText() == 'Disabled':
                clear_voice_notification_queue()
                break

        self._save_widgets_to_singleton()

        GUIProtectionSettings.export_to_file(PROTECTIONS_JSON_PATH)
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.accept()

    def _export_protections(self) -> None:
        """Export current protection settings (including combo rules) to a JSON file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            'Export Protection Settings',
            'protections.json',
            'JSON Files (*.json);;All Files (*.*)',
        )
        if file_path:
            # Save current widget state to GUIProtectionSettings first
            self._save_widgets_to_singleton()
            # Build combined export: standard protections + combo rules
            target = Path(file_path)
            GUIProtectionSettings.export_to_file(target)
            data: object = json.loads(target.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                msg = 'Expected a JSON object in the exported file.'
                raise RuntimeError(msg)
            data_dict = cast('dict[str, object]', data)
            data_dict['combo_rules'] = [r.to_dict() for r in ComboRulesManager.rules]
            target.write_text(json.dumps(data_dict, indent=4), encoding='utf-8')
            QMessageBox.information(self, TITLE, 'Protection settings exported successfully.')

    def _import_protections(self) -> None:
        """Import protection settings (including combo rules) from a JSON file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            'Import Protection Settings',
            '',
            'JSON Files (*.json);;All Files (*.*)',
        )
        if file_path:
            try:
                raw: object = json.loads(Path(file_path).read_text(encoding='utf-8'))
                GUIProtectionSettings.import_from_file(Path(file_path))
                # Import combo rules if present
                if isinstance(raw, dict):
                    raw_dict = cast('dict[str, object]', raw)
                    combo_data: object = raw_dict.get('combo_rules')
                    if isinstance(combo_data, list):
                        ComboRulesManager.rules = [
                            ComboRule.from_dict(cast('dict[str, object]', entry))
                            for entry in cast('list[object]', combo_data)
                            if isinstance(entry, dict)
                        ]
            except (ValueError, KeyError, OSError, json.JSONDecodeError) as e:
                QMessageBox.critical(self, 'Import Error', f'Failed to import settings:\n{e}')
                return
            self._load_current_settings()
            QMessageBox.information(self, TITLE, 'Protection settings imported successfully.')

    def _reset_tab_to_defaults(self, prefixes: tuple[str, ...]) -> None:
        """Reset all protection widgets for the given *prefixes* to their default values without saving."""
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
        """Reset the current tab's protection widgets to their default values."""
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
        """Reset all protection widget values to defaults after user confirmation."""
        result = QMessageBox.question(
            self,
            TITLE,
            'Reset all protection settings to defaults?\n\nThis will clear all current values in the editor.',
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
        """Write current widget state to GUIProtectionSettings without persisting to disk."""
        # Mobile
        GUIProtectionSettings.mobile_suspend_enabled = self.mobile_duration_combo.currentText() != 'Disabled'
        if GUIProtectionSettings.mobile_suspend_enabled:
            GUIProtectionSettings.mobile_suspend_duration = self._read_duration_widgets(self.mobile_duration_combo, self.mobile_duration_spin)
        GUIProtectionSettings.mobile_voice_notifications = self._read_voice_combo(self.mobile_voice_combo)
        GUIProtectionSettings.mobile_logging = self.mobile_logging_checkbox.isChecked()
        GUIProtectionSettings.mobile_message_box = self.mobile_msgbox_checkbox.isChecked()

        # VPN
        GUIProtectionSettings.vpn_suspend_enabled = self.vpn_duration_combo.currentText() != 'Disabled'
        if GUIProtectionSettings.vpn_suspend_enabled:
            GUIProtectionSettings.vpn_suspend_duration = self._read_duration_widgets(self.vpn_duration_combo, self.vpn_duration_spin)
        GUIProtectionSettings.vpn_voice_notifications = self._read_voice_combo(self.vpn_voice_combo)
        GUIProtectionSettings.vpn_logging = self.vpn_logging_checkbox.isChecked()
        GUIProtectionSettings.vpn_message_box = self.vpn_msgbox_checkbox.isChecked()

        # Hosting
        GUIProtectionSettings.hosting_suspend_enabled = self.hosting_duration_combo.currentText() != 'Disabled'
        if GUIProtectionSettings.hosting_suspend_enabled:
            GUIProtectionSettings.hosting_suspend_duration = self._read_duration_widgets(self.hosting_duration_combo, self.hosting_duration_spin)
        GUIProtectionSettings.hosting_voice_notifications = self._read_voice_combo(self.hosting_voice_combo)
        GUIProtectionSettings.hosting_logging = self.hosting_logging_checkbox.isChecked()
        GUIProtectionSettings.hosting_message_box = self.hosting_msgbox_checkbox.isChecked()

        # Country
        GUIProtectionSettings.country_block_enabled = self.country_duration_combo.currentText() != 'Disabled'
        GUIProtectionSettings.country_block_list = [
            item.data(Qt.ItemDataRole.UserRole)
            for i in range(self.country_list.count())
            if (item := self.country_list.item(i)) is not None
        ]
        if GUIProtectionSettings.country_block_enabled:
            GUIProtectionSettings.country_block_duration = self._read_duration_widgets(self.country_duration_combo, self.country_duration_spin)
        GUIProtectionSettings.country_voice_notifications = self._read_voice_combo(self.country_voice_combo)
        GUIProtectionSettings.country_logging = self.country_logging_checkbox.isChecked()
        GUIProtectionSettings.country_message_box = self.country_msgbox_checkbox.isChecked()

        # ISP
        GUIProtectionSettings.isp_block_enabled = self.isp_duration_combo.currentText() != 'Disabled'
        GUIProtectionSettings.isp_block_list = [
            item.text()
            for i in range(self.isp_list.count())
            if (item := self.isp_list.item(i)) is not None
        ]
        if GUIProtectionSettings.isp_block_enabled:
            GUIProtectionSettings.isp_block_duration = self._read_duration_widgets(self.isp_duration_combo, self.isp_duration_spin)
        GUIProtectionSettings.isp_voice_notifications = self._read_voice_combo(self.isp_voice_combo)
        GUIProtectionSettings.isp_logging = self.isp_logging_checkbox.isChecked()
        GUIProtectionSettings.isp_message_box = self.isp_msgbox_checkbox.isChecked()

        # ASN
        GUIProtectionSettings.asn_block_enabled = self.asn_duration_combo.currentText() != 'Disabled'
        GUIProtectionSettings.asn_block_list = [
            item.text()
            for i in range(self.asn_list.count())
            if (item := self.asn_list.item(i)) is not None
        ]
        if GUIProtectionSettings.asn_block_enabled:
            GUIProtectionSettings.asn_block_duration = self._read_duration_widgets(self.asn_duration_combo, self.asn_duration_spin)
        GUIProtectionSettings.asn_voice_notifications = self._read_voice_combo(self.asn_voice_combo)
        GUIProtectionSettings.asn_logging = self.asn_logging_checkbox.isChecked()
        GUIProtectionSettings.asn_message_box = self.asn_msgbox_checkbox.isChecked()

        # Player Join
        GUIProtectionSettings.player_join_enabled = self.player_join_duration_combo.currentText() != 'Disabled'
        if GUIProtectionSettings.player_join_enabled:
            GUIProtectionSettings.player_join_duration = self._read_duration_widgets(self.player_join_duration_combo, self.player_join_duration_spin)
        GUIProtectionSettings.player_join_voice_notifications = self._read_voice_combo(self.player_join_voice_combo)
        GUIProtectionSettings.player_join_logging = self.player_join_logging_checkbox.isChecked()
        GUIProtectionSettings.player_join_message_box = self.player_join_msgbox_checkbox.isChecked()

        # Player Rejoin
        GUIProtectionSettings.player_rejoin_enabled = self.player_rejoin_duration_combo.currentText() != 'Disabled'
        if GUIProtectionSettings.player_rejoin_enabled:
            GUIProtectionSettings.player_rejoin_duration = self._read_duration_widgets(self.player_rejoin_duration_combo, self.player_rejoin_duration_spin)
        GUIProtectionSettings.player_rejoin_voice_notifications = self._read_voice_combo(self.player_rejoin_voice_combo)
        GUIProtectionSettings.player_rejoin_logging = self.player_rejoin_logging_checkbox.isChecked()
        GUIProtectionSettings.player_rejoin_message_box = self.player_rejoin_msgbox_checkbox.isChecked()

        # Player Leave
        GUIProtectionSettings.player_leave_enabled = self.player_leave_duration_combo.currentText() != 'Disabled'
        if GUIProtectionSettings.player_leave_enabled:
            GUIProtectionSettings.player_leave_duration = self._read_duration_widgets(self.player_leave_duration_combo, self.player_leave_duration_spin)
        GUIProtectionSettings.player_leave_voice_notifications = self._read_voice_combo(self.player_leave_voice_combo)
        GUIProtectionSettings.player_leave_logging = self.player_leave_logging_checkbox.isChecked()
        GUIProtectionSettings.player_leave_message_box = self.player_leave_msgbox_checkbox.isChecked()

        # GTA5 Relay (only when the tab is present)
        if hasattr(self, 'gta5_relay_duration_combo'):
            GUIProtectionSettings.gta5_relay_enabled = self.gta5_relay_duration_combo.currentText() != 'Disabled'
            GUIProtectionSettings.gta5_relay_packet_threshold = self.gta5_relay_packet_threshold_spin.value()
            if GUIProtectionSettings.gta5_relay_enabled:
                GUIProtectionSettings.gta5_relay_duration = self._read_duration_widgets(self.gta5_relay_duration_combo, self.gta5_relay_duration_spin)
            GUIProtectionSettings.gta5_relay_voice_notifications = self._read_voice_combo(self.gta5_relay_voice_combo)
            GUIProtectionSettings.gta5_relay_logging = self.gta5_relay_logging_checkbox.isChecked()
            GUIProtectionSettings.gta5_relay_message_box = self.gta5_relay_msgbox_checkbox.isChecked()

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
            'country_list': tuple(
                item.data(Qt.ItemDataRole.UserRole)
                for i in range(self.country_list.count())
                if (item := self.country_list.item(i)) is not None
            ),
            'country_duration': self._read_duration_widgets(self.country_duration_combo, self.country_duration_spin),
            'country_voice': self._read_voice_combo(self.country_voice_combo),
            'country_logging': self.country_logging_checkbox.isChecked(),
            'country_msgbox': self.country_msgbox_checkbox.isChecked(),
            'isp_enabled': self.isp_duration_combo.currentText() != 'Disabled',
            'isp_list': tuple(
                item.text()
                for i in range(self.isp_list.count())
                if (item := self.isp_list.item(i)) is not None
            ),
            'isp_duration': self._read_duration_widgets(self.isp_duration_combo, self.isp_duration_spin),
            'isp_voice': self._read_voice_combo(self.isp_voice_combo),
            'isp_logging': self.isp_logging_checkbox.isChecked(),
            'isp_msgbox': self.isp_msgbox_checkbox.isChecked(),
            'asn_enabled': self.asn_duration_combo.currentText() != 'Disabled',
            'asn_list': tuple(
                item.text()
                for i in range(self.asn_list.count())
                if (item := self.asn_list.item(i)) is not None
            ),
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
            'combo_rules': [r.to_dict() for r in ComboRulesManager.rules],
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
        """Save and apply protections; always succeeds."""
        self._save_and_apply()
        return True


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
