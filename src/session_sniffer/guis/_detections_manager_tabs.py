"""Mixin providing tab-building, group-factory, and combo-rule management methods for DetectionsManagerDialog."""

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from pydantic import TypeAdapter, ValidationError
from PySide6.QtCore import QPoint, QSignalBlocker, Qt
from PySide6.QtGui import QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.background import clear_voice_notification_queue, retrigger_detections_scan
from session_sniffer.constants.local import COMBO_RULES_PATH
from session_sniffer.constants.standalone import MAX_SUSPEND_DURATION_SECONDS, TITLE
from session_sniffer.guis._combo_rule_editor import ComboRuleEditorDialog, ContinentSelectionDialog, CountrySelectionDialog
from session_sniffer.guis.country_data import (
    get_continent_code,
    get_country_flag_code,
    normalize_continent_name,
    normalize_country_name,
)
from session_sniffer.guis.delegates import ComboRuleCardDelegate, ElidedTextTooltipDelegate
from session_sniffer.guis.stylesheets import (
    COMBO_RULES_LIST_STYLE,
    DESC_LABEL_STYLESHEET,
    GROUPBOX_STYLE,
    LIST_WIDGET_STYLE,
    RELAY_FILTER_WARNING_STYLESHEET,
    SVG_ICON_CONTEXT_MENU_STYLESHEET,
    WARNING_ICON_LABEL_STYLESHEET,
    WARNING_TEXT_LABEL_STYLESHEET,
)
from session_sniffer.guis.theming import ICONS_DIR_PATH
from session_sniffer.guis.utils import (
    SUSPEND_TOOLTIP_AUTO,
    SUSPEND_TOOLTIP_DISABLED,
    SUSPEND_TOOLTIP_MANUAL,
    create_section_separator,
    load_country_flag_icon,
    render_svg_pixmap_from_resource,
    scale_by_ui,
)
from session_sniffer.models.combo_rules import ComboRule
from session_sniffer.models.detections import DetectionsFile
from session_sniffer.networking.third_party_servers import ThirdPartyServers
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.rendering_core.types import CaptureState
from session_sniffer.settings import Settings
from session_sniffer.text_utils import DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS, pluralize


class DetectionsManagerTabsMixin(QDialog):
    """Mixin that adds tab-building, group-factory, and combo-rule management to DetectionsManagerDialog."""

    if TYPE_CHECKING:
        _loading_settings: bool
        _relay_filter_warning: QWidget
        _combo_rules_list: QListWidget
        _combo_toggle_button: QPushButton
        _combo_edit_button: QPushButton
        _combo_duplicate_button: QPushButton
        _combo_export_button: QPushButton
        _combo_remove_button: QPushButton
        _combo_clear_button: QPushButton
        continent_list: QListWidget
        country_list: QListWidget
        isp_list: QListWidget
        asn_list: QListWidget

        def _auto_save_detections(self) -> None: ...

    # ------------------------------------------------------------------
    # Tab creation
    # ------------------------------------------------------------------

    @staticmethod
    def _add_scrollable_section(parent_layout: QVBoxLayout) -> QVBoxLayout:
        """Create a frameless scroll area inside *parent_layout* and return its inner vertical layout."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)
        scroll.setWidget(scroll_content)
        parent_layout.addWidget(scroll)
        return scroll_layout

    def create_player_events_tab(self) -> QWidget:
        """Create the player events tab with detection groups for join/rejoin/leave."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        scroll_layout = self._add_scrollable_section(layout)

        join_group = self._create_detection_group(
            'Player Join',
            'Triggers when a new player joins your session.',
            'player_join',
        )
        scroll_layout.addWidget(join_group)

        rejoin_group = self._create_detection_group(
            'Player Rejoin',
            'Triggers when a player rejoins your session after disconnecting.',
            'player_rejoin',
        )
        scroll_layout.addWidget(rejoin_group)

        leave_group = self._create_detection_group(
            'Player Leave',
            'Triggers when a player leaves your session.',
            'player_leave',
        )
        scroll_layout.addWidget(leave_group)

        scroll_layout.addStretch()
        return widget

    def create_network_based_tab(self) -> QWidget:
        """Create the network-based detections tab (VPN, Hosting, Mobile, IP Range)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        scroll_layout = self._add_scrollable_section(layout)

        mobile_group = self._create_detection_group(
            'Mobile Connection',
            'Triggers when a player is on a mobile or cellular connection.',
            'mobile',
        )
        scroll_layout.addWidget(mobile_group)

        vpn_group = self._create_detection_group(
            'VPN/Proxy/Tor',
            'Triggers when a player is using a VPN, proxy, or Tor exit node.',
            'vpn',
        )
        scroll_layout.addWidget(vpn_group)

        hosting_group = self._create_detection_group(
            'Hosting/Data Center',
            'Triggers when a player connects from a hosting provider or data center.',
            'hosting',
        )
        scroll_layout.addWidget(hosting_group)

        scroll_layout.addStretch()
        return widget

    def create_geo_based_tab(self) -> QWidget:
        """Create the geography-based detections tab (Continent, Country, ISP, ASN)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        scroll_layout = self._add_scrollable_section(layout)

        continent_group = self._create_list_detection_group(
            'Continent Detection',
            "Triggers when a player's continent is in the detection list.",
            'continent',
            on_add=self._add_continent,
        )
        scroll_layout.addWidget(continent_group)

        country_group = self._create_list_detection_group(
            'Country Detection',
            "Triggers when a player's country is in the detection list.",
            'country',
            on_add=self._add_country,
        )
        scroll_layout.addWidget(country_group)

        isp_group = self._create_list_detection_group(
            'ISP/Company Detection',
            "Triggers when a player's ISP or company is in the detection list (e.g., Vodafone, Orange, Cloudflare).",
            'isp',
            on_add=self._add_isp,
        )
        scroll_layout.addWidget(isp_group)

        asn_group = self._create_list_detection_group(
            'ASN Number Detection',
            "Triggers when a player's ASN is in the detection list (e.g., AS15169, AS13335, or just 15169, 13335).",
            'asn',
            on_add=self._add_asn,
        )
        scroll_layout.addWidget(asn_group)

        scroll_layout.addStretch()
        return widget

    def create_gta5_relays_tab(self) -> QWidget:
        """Create the GTA5 Relays detection tab (only shown with the GTA5 feature set)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        # Warning banner: shown when TAKETWO_INTERACTIVE ranges are in the capture block list,
        # which prevents relay IPs from ever reaching the capture engine.
        filter_warning = QWidget()
        filter_warning.setStyleSheet(RELAY_FILTER_WARNING_STYLESHEET)
        filter_warning_layout = QHBoxLayout(filter_warning)
        filter_warning_layout.setContentsMargins(8, 6, 8, 6)
        filter_warning_layout.setSpacing(10)
        warning_icon_label = QLabel()
        warning_icon_label.setPixmap(render_svg_pixmap_from_resource('triangle-alert.svg', 20, 20, '#f59e0b'))
        warning_icon_label.setStyleSheet(WARNING_ICON_LABEL_STYLESHEET)
        filter_warning_layout.addWidget(warning_icon_label)
        warning_text_label = QLabel(
            '<b>Relay IPs are currently filtered out of the capture.</b><br>'
            "The 'Take-Two Interactive Software, Inc.' and/or 'Microsoft' IP ranges are listed under <i>Block Third-Party Servers</i> in Settings. "
            'These IPs are dropped before the capture engine sees them, so relay detection will not trigger for blocked ranges. '
            'Remove those entries from the blocked servers list to enable full relay detection.',
        )
        warning_text_label.setWordWrap(True)
        warning_text_label.setStyleSheet(WARNING_TEXT_LABEL_STYLESHEET)
        filter_warning_layout.addWidget(warning_text_label, 1)
        fix_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'settings.svg')), ' Fix It')
        fix_button.setToolTip("Remove 'Take-Two Interactive Software, Inc.' and 'Microsoft' from the blocked servers list and save the setting")
        fix_button.setCursor(Qt.CursorShape.PointingHandCursor)
        fix_button.clicked.connect(self._remove_relay_servers_from_blocked_servers)
        filter_warning_layout.addWidget(fix_button)
        self._relay_filter_warning = filter_warning
        filter_warning.setVisible(any(name in Settings.capture_block_third_party_servers for name in ('TAKETWO_INTERACTIVE', 'MICROSOFT')))
        layout.addWidget(filter_warning)

        scroll_layout = self._add_scrollable_section(layout)

        relay_group = self._create_detection_group(
            'GTA5 Relay',
            'Triggers when a Take-Two Interactive or Microsoft relay IP is detected (thresholds are configured under Settings -> GTA V -> Session Relays).',
            'gta5_relay',
        )
        scroll_layout.addWidget(relay_group)

        scroll_layout.addStretch()
        return widget

    def create_combo_rules_tab(self) -> QWidget:
        """Create the combo rules tab with rule list and management buttons."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        desc = QLabel(
            'Combine multiple conditions into a single rule using AND logic. '
            'All conditions in a rule must match for it to trigger. '
            'Rules with an event condition require at least one IP-based condition.',
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(DESC_LABEL_STYLESHEET)
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

        add_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), ' Add Rule')
        add_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_button.clicked.connect(self._add_combo_rule)
        button_layout.addWidget(add_button)

        self._combo_toggle_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'toggle-right.svg')), ' Toggle State')
        self._combo_toggle_button.setEnabled(False)
        self._combo_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_toggle_button.setMinimumWidth(scale_by_ui(125))
        self._combo_toggle_button.clicked.connect(self._toggle_combo_rule)
        button_layout.addWidget(self._combo_toggle_button)

        self._combo_edit_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), ' Edit')
        self._combo_edit_button.setEnabled(False)
        self._combo_edit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_edit_button.clicked.connect(self._edit_combo_rule)
        button_layout.addWidget(self._combo_edit_button)

        self._combo_duplicate_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), ' Duplicate')
        self._combo_duplicate_button.setEnabled(False)
        self._combo_duplicate_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_duplicate_button.clicked.connect(self._duplicate_combo_rule)
        button_layout.addWidget(self._combo_duplicate_button)

        self._combo_export_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), ' Export Rule')
        self._combo_export_button.setEnabled(False)
        self._combo_export_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_export_button.setToolTip('Export the selected combo rule(s) to a JSON file')
        self._combo_export_button.clicked.connect(self._export_selected_combo_rules)
        button_layout.addWidget(self._combo_export_button)

        self._combo_remove_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), ' Remove')
        self._combo_remove_button.setEnabled(False)
        self._combo_remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_remove_button.clicked.connect(self._remove_combo_rule)
        button_layout.addWidget(self._combo_remove_button)

        self._combo_clear_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), ' Clear All')
        self._combo_clear_button.setEnabled(False)
        self._combo_clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_clear_button.clicked.connect(self._clear_combo_rules)
        button_layout.addWidget(self._combo_clear_button)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        self._combo_rules_list.itemSelectionChanged.connect(self._update_combo_rule_buttons)
        self._combo_rules_list.itemActivated.connect(self._on_combo_item_activated)

        return widget

    # ------------------------------------------------------------------
    # GTA5 relay handlers
    # ------------------------------------------------------------------

    def _on_gta5_relay_suspend_mode_changed(self, text: str) -> None:
        """Warn the user when enabling relay detection while relay IPs are still being filtered."""
        if self._loading_settings or text == 'Disabled':
            return
        blocked_relays = [name for name in ('TAKETWO_INTERACTIVE', 'MICROSOFT') if name in Settings.capture_block_third_party_servers]
        if not blocked_relays:
            return
        blocked_names_str = ' and '.join(f"'{ThirdPartyServers[name].display_name}'" for name in blocked_relays)
        result = QMessageBox.question(
            self,
            TITLE,
            f'The {blocked_names_str} relay IP ranges are currently being blocked by the capture filter '
            '(Block Third-Party Servers setting).\n\n'
            'Relay IPs will be dropped before the capture engine sees them, '
            'so this detection will not trigger for blocked ranges while that filter is active.\n\n'
            f'Would you like to automatically remove {blocked_names_str} from the blocked servers list?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if result == QMessageBox.StandardButton.Yes:
            self._remove_relay_servers_from_blocked_servers()

    def _remove_relay_servers_from_blocked_servers(self) -> None:
        """Remove TAKETWO_INTERACTIVE and MICROSOFT from the blocked third-party servers list and persist the setting."""
        blocked_relays = [name for name in ('TAKETWO_INTERACTIVE', 'MICROSOFT') if name in Settings.capture_block_third_party_servers]
        removed_names_str = ' and '.join(f"'{ThirdPartyServers[name].display_name}'" for name in blocked_relays) or 'Relay server ranges'
        Settings.capture_block_third_party_servers = tuple(
            server for server in Settings.capture_block_third_party_servers if server not in ('TAKETWO_INTERACTIVE', 'MICROSOFT')
        )
        Settings.rewrite_settings_file()
        self._relay_filter_warning.setVisible(False)
        verb = 'have' if len(blocked_relays) > 1 else 'has'
        QMessageBox.information(
            self,
            TITLE,
            f'{removed_names_str} {verb} been removed from the blocked servers list and the setting has been saved.\n\n'
            'Please restart the capture for the change to take effect.',
        )

    # ------------------------------------------------------------------
    # Combo rule management
    # ------------------------------------------------------------------

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
        self._combo_duplicate_button.setText(f' Duplicate ({sel_count})' if sel_count > 1 else ' Duplicate')
        self._combo_export_button.setEnabled(has_selection)
        self._combo_export_button.setText(f' Export ({sel_count})' if sel_count > 1 else ' Export Rule')
        self._combo_remove_button.setEnabled(has_selection)
        self._combo_remove_button.setText(f' Remove ({sel_count})' if sel_count > 1 else ' Remove')
        self._combo_toggle_button.setEnabled(has_selection)
        self._combo_clear_button.setEnabled(has_items)

        if sel_count == 1:
            all_enabled = ComboRulesManager.rules[indices[0]].enabled
            self._combo_toggle_button.setText(' Disable Rule' if all_enabled else ' Enable Rule')
            self._combo_toggle_button.setIcon(QIcon(str(ICONS_DIR_PATH / ('toggle-left.svg' if all_enabled else 'toggle-right.svg'))))
        elif sel_count > 1:
            all_enabled = all(ComboRulesManager.rules[i].enabled for i in indices)
            self._combo_toggle_button.setText(f' Disable Rules ({sel_count})' if all_enabled else f' Enable Rules ({sel_count})')
            self._combo_toggle_button.setIcon(QIcon(str(ICONS_DIR_PATH / ('toggle-left.svg' if all_enabled else 'toggle-right.svg'))))
        else:
            self._combo_toggle_button.setText(' Toggle State')
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

        add_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), 'Add Rule…')
        add_act.triggered.connect(self._add_combo_rule)

        edit_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'square-pen.svg')), 'Edit Rule…')
        edit_act.setEnabled(sel_count == 1)
        edit_act.triggered.connect(self._edit_combo_rule)

        all_enabled = has_selection and all(ComboRulesManager.rules[i].enabled for i in indices)
        toggle_label = (
            ('Disable Rule' if all_enabled else 'Enable Rule')
            if sel_count <= 1
            else (f'Disable Rules ({sel_count})' if all_enabled else f'Enable Rules ({sel_count})')
        )
        toggle_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / ('toggle-left.svg' if all_enabled else 'toggle-right.svg'))), toggle_label)
        toggle_act.setEnabled(has_selection)
        toggle_act.triggered.connect(self._toggle_combo_rule)

        dup_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'copy.svg')), f'Duplicate ({sel_count})' if sel_count > 1 else 'Duplicate')
        dup_act.setEnabled(has_selection)
        dup_act.triggered.connect(self._duplicate_combo_rule)

        menu.addSeparator()

        export_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'upload.svg')), f'Export Selected Rules ({sel_count})…' if sel_count > 1 else 'Export Selected Rule…')
        export_act.setEnabled(has_selection)
        export_act.triggered.connect(self._export_selected_combo_rules)

        import_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'download.svg')), 'Import Combo Rules…')
        import_act.triggered.connect(self._import_combo_rules_file)

        menu.addSeparator()

        select_all_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), 'Select All')
        select_all_act.setShortcut('Ctrl+A')
        select_all_act.setEnabled(has_items)
        select_all_act.triggered.connect(self._combo_rules_list.selectAll)

        remove_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f'Remove ({sel_count})' if sel_count > 1 else 'Remove')
        remove_act.setShortcut('Delete')
        remove_act.setEnabled(has_selection)
        remove_act.triggered.connect(self._remove_combo_rule)

        clear_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), 'Clear All')
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
            QMessageBox.information(self, TITLE, 'Select a single rule to edit.')
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
            QMessageBox.information(self, TITLE, 'Select at least one rule to duplicate.')
            return
        start_index = len(ComboRulesManager.rules)
        any_enabled = False
        for index in indices:
            original = ComboRulesManager.rules[index]
            copy = ComboRule(
                name=f'{original.name} (Copy)',
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
            QMessageBox.information(self, TITLE, 'Select at least one rule to export.')
            return
        selected_rules = [ComboRulesManager.rules[i] for i in indices]
        default_name = f'{selected_rules[0].name}.json' if len(selected_rules) == 1 else 'combo_rules.json'
        file_path, _ = QFileDialog.getSaveFileName(self, 'Export Selected Combo Rules', default_name, 'JSON Files (*.json);;All Files (*.*)')
        if not file_path:
            return
        target = Path(file_path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(TypeAdapter(list[ComboRule]).dump_json(selected_rules, indent=4).decode('utf-8'), encoding='utf-8')
        except OSError as e:
            QMessageBox.critical(self, 'Export Error', f'Failed to export combo rules:\n{e}')
            return
        QMessageBox.information(self, TITLE, f'Exported {len(selected_rules)} combo rule{pluralize(len(selected_rules))} successfully.')

    def _import_combo_rules_file(self) -> None:
        """Import combo rules from either a combo-rules list JSON or a detections JSON file and append them."""
        file_path, _ = QFileDialog.getOpenFileName(self, 'Import Combo Rules', '', 'JSON Files (*.json);;All Files (*.*)')
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
            QMessageBox.critical(self, 'Import Error', f'Failed to import combo rules:\n{e}')
            return
        if not imported:
            QMessageBox.information(self, TITLE, 'No combo rules were found in the selected file.')
            return
        start_index = len(ComboRulesManager.rules)
        ComboRulesManager.rules.extend(imported)
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.refresh_combo_rules_list(selected_rows=list(range(start_index, len(ComboRulesManager.rules))))
        if any(rule.enabled for rule in imported):
            retrigger_detections_scan()
        QMessageBox.information(self, TITLE, f'Imported {len(imported)} combo rule{pluralize(len(imported))} successfully.')

    def _remove_combo_rule(self) -> None:
        """Remove the selected combo rule(s)."""
        indices = self._get_selected_combo_rule_indices()
        if not indices:
            return
        prompt = (
            f'Remove rule "{ComboRulesManager.rules[indices[0]].name}"?'
            if len(indices) == 1
            else f'Remove {len(indices)} selected combo rules?'
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
                'Remove all combo rules?',
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

    # ------------------------------------------------------------------
    # Group factories
    # ------------------------------------------------------------------

    @staticmethod
    def _create_base_group(title: str, description: str) -> tuple[QGroupBox, QVBoxLayout]:
        """Create a styled `QGroupBox` with a description label and return `(group, group_layout)`."""
        group = QGroupBox(title)
        group.setStyleSheet(GROUPBOX_STYLE)
        group_layout = QVBoxLayout()

        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet(DESC_LABEL_STYLESHEET)
        group_layout.addWidget(desc_label)
        return group, group_layout

    def _append_detection_and_notification_sections(self, group_layout: QVBoxLayout, detection_type: str) -> None:
        """Append the hideable detection suspend section and notification controls to *group_layout*."""
        detection_section = QWidget()
        detection_section_layout = QVBoxLayout(detection_section)
        detection_section_layout.setContentsMargins(0, 0, 0, 0)
        setattr(self, f'{detection_type}_detection_section', detection_section)

        detection_separator = create_section_separator('Detection Settings')
        detection_section_layout.addWidget(detection_separator)

        duration_layout = QHBoxLayout()
        duration_label = QLabel('Suspend Mode:')
        duration_layout.addWidget(duration_label)

        duration_combo = QComboBox()
        duration_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        duration_combo.addItems(['Disabled', 'Auto', 'Manual'])
        duration_combo.setItemData(0, SUSPEND_TOOLTIP_DISABLED, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(1, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(2, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        setattr(self, f'{detection_type}_duration_combo', duration_combo)
        duration_layout.addWidget(duration_combo)

        duration_spin = QSpinBox()
        duration_spin.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        duration_spin.setRange(1, MAX_SUSPEND_DURATION_SECONDS)
        duration_spin.setValue(DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS)
        duration_spin.setSuffix(' seconds')
        duration_spin.setVisible(False)

        def _on_duration_text_changed(text: str) -> None:
            duration_spin.setVisible(text == 'Manual')

        duration_combo.currentTextChanged.connect(_on_duration_text_changed)
        setattr(self, f'{detection_type}_duration_spin', duration_spin)
        duration_layout.addWidget(duration_spin)

        duration_layout.addStretch()
        detection_section_layout.addLayout(duration_layout)

        self._create_notification_controls(group_layout, detection_type)
        group_layout.addWidget(detection_section)

    def _create_detection_group(self, title: str, description: str, detection_type: str) -> QGroupBox:
        """Create a detection group with duration and notification settings."""
        group, group_layout = self._create_base_group(title, description)
        self._append_detection_and_notification_sections(group_layout, detection_type)
        group.setLayout(group_layout)
        return group

    def _append_managed_list_row(
        self,
        group_layout: QVBoxLayout,
        attr_name: str,
        *,
        on_add: Callable[[], None],
    ) -> QListWidget:
        """Create a styled `QListWidget` with multi-select Add/Remove/Clear All support and attach it to *group_layout*."""
        list_layout = QHBoxLayout()

        list_widget = QListWidget()
        list_widget.setStyleSheet(LIST_WIDGET_STYLE)
        list_widget.setItemDelegate(ElidedTextTooltipDelegate(list_widget))
        list_widget.setWordWrap(False)
        list_widget.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        list_widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        setattr(self, attr_name, list_widget)
        list_layout.addWidget(list_widget)

        buttons_layout = QVBoxLayout()
        add_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), ' Add')
        add_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_button.clicked.connect(on_add)
        buttons_layout.addWidget(add_button)

        remove_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), ' Remove')
        remove_button.setEnabled(False)
        remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
        buttons_layout.addWidget(remove_button)

        clear_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), ' Clear All')
        clear_button.setEnabled(False)
        clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        buttons_layout.addWidget(clear_button)

        def _sync_list_buttons(*_args: object) -> None:
            if not (isValid(list_widget) and isValid(remove_button) and isValid(clear_button)):
                return
            sel_count = len(list_widget.selectedItems())
            remove_button.setEnabled(sel_count > 0)
            remove_button.setText(f' Remove ({sel_count})' if sel_count > 1 else ' Remove')
            clear_button.setEnabled(list_widget.count() > 0)

        def _on_remove_selected() -> None:
            selected_rows = sorted({list_widget.row(item) for item in list_widget.selectedItems()}, reverse=True)
            if not selected_rows:
                return
            for row in selected_rows:
                list_widget.takeItem(row)
            self._auto_save_detections()
            _sync_list_buttons()

        def _on_clear_list() -> None:
            if list_widget.count() > 0:
                list_widget.clear()
                self._auto_save_detections()
            _sync_list_buttons()

        def _on_list_context_menu(pos: QPoint) -> None:
            clicked_item = list_widget.itemAt(pos)
            if clicked_item is not None and not clicked_item.isSelected():
                list_widget.clearSelection()
                list_widget.setCurrentItem(clicked_item)
                clicked_item.setSelected(True)
            sel_count = len(list_widget.selectedItems())
            has_items = list_widget.count() > 0
            menu = QMenu(self)
            menu.setStyleSheet(SVG_ICON_CONTEXT_MENU_STYLESHEET)
            menu.addAction(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), 'Add…').triggered.connect(on_add)
            rm_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f'Remove ({sel_count})' if sel_count > 1 else 'Remove')
            rm_act.setShortcut('Delete')
            rm_act.setEnabled(sel_count > 0)
            rm_act.triggered.connect(_on_remove_selected)
            menu.addSeparator()
            sel_all_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), 'Select All')
            sel_all_act.setShortcut('Ctrl+A')
            sel_all_act.setEnabled(has_items)
            sel_all_act.triggered.connect(list_widget.selectAll)
            clr_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), 'Clear All')
            clr_act.setEnabled(has_items)
            clr_act.triggered.connect(_on_clear_list)
            if viewport := list_widget.viewport():
                menu.exec(viewport.mapToGlobal(pos))

        remove_button.clicked.connect(_on_remove_selected)
        clear_button.clicked.connect(_on_clear_list)
        list_widget.itemSelectionChanged.connect(_sync_list_buttons)
        list_widget.customContextMenuRequested.connect(_on_list_context_menu)
        QShortcut(QKeySequence('Delete'), list_widget, context=Qt.ShortcutContext.WidgetShortcut).activated.connect(_on_remove_selected)
        if list_model := list_widget.model():
            list_model.rowsInserted.connect(_sync_list_buttons)
            list_model.rowsRemoved.connect(_sync_list_buttons)
            list_model.modelReset.connect(_sync_list_buttons)

        buttons_layout.addStretch()
        list_layout.addLayout(buttons_layout)
        group_layout.addLayout(list_layout)
        return list_widget

    def _create_list_detection_group(
        self,
        title: str,
        description: str,
        detection_type: str,
        *,
        on_add: Callable[[], None],
    ) -> QGroupBox:
        """Create a detection group with enable, list, action, process path, and notification settings."""
        group, group_layout = self._create_base_group(title, description)
        self._append_managed_list_row(group_layout, f'{detection_type}_list', on_add=on_add)
        self._append_detection_and_notification_sections(group_layout, detection_type)
        group.setLayout(group_layout)
        return group

    def _create_notification_controls(self, parent_layout: QVBoxLayout, prefix: str) -> None:
        """Add voice notification, logging, and message box controls to a group layout."""
        separator = create_section_separator('Notification Settings')
        parent_layout.addWidget(separator)

        voice_layout = QHBoxLayout()
        voice_label = QLabel('Voice Notifications:')
        voice_layout.addWidget(voice_label)

        voice_combo = QComboBox()
        voice_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        voice_combo.addItems(['Disabled', 'Male', 'Female'])
        voice_combo.setToolTip('Select voice for text-to-speech notifications')
        setattr(self, f'{prefix}_voice_combo', voice_combo)
        voice_layout.addWidget(voice_combo)
        voice_layout.addStretch()
        parent_layout.addLayout(voice_layout)

        msgbox_checkbox = QCheckBox('Show Message Box')
        msgbox_checkbox.setToolTip('Show a message box popup when this detection triggers')
        setattr(self, f'{prefix}_msgbox_checkbox', msgbox_checkbox)
        parent_layout.addWidget(msgbox_checkbox)

        logging_checkbox = QCheckBox('Detection Logging')
        logging_checkbox.setToolTip('Log detection events to the detection logging file')
        setattr(self, f'{prefix}_logging_checkbox', logging_checkbox)
        parent_layout.addWidget(logging_checkbox)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _list_contains(list_widget: QListWidget, value: str) -> bool:
        """Return True if *value* already exists in the QListWidget (case-insensitive)."""
        for i in range(list_widget.count()):
            item = list_widget.item(i)
            if item and item.text().casefold() == value.casefold():
                return True
        return False

    def _add_continent(self) -> None:
        """Add one or more continents via a multi-select dialog."""
        existing_continents: set[str] = set()
        for i in range(self.continent_list.count()):
            item = self.continent_list.item(i)
            if item:
                continent = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(continent, str):
                    existing_continents.add(normalize_continent_name(continent) or continent)

        dialog = ContinentSelectionDialog(self, existing_continents)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            continents = dialog.selected_continents()
            if continents:
                for continent in continents:
                    self._add_continent_item(continent)
                self._auto_save_detections()

    def _add_continent_item(self, continent_name: str) -> None:
        """Add a continent list item with display name and continent code."""
        canonical = normalize_continent_name(continent_name) or continent_name
        code = get_continent_code(canonical)
        display_text = f'{canonical} ({code})' if code is not None and code else canonical
        item = QListWidgetItem(display_text)
        item.setData(Qt.ItemDataRole.UserRole, canonical)
        item.setIcon(QIcon(str(ICONS_DIR_PATH / 'globe.svg')))
        self.continent_list.addItem(item)

    def _add_country(self) -> None:
        """Add one or more countries via a searchable selection dialog."""
        existing_countries: set[str] = set()
        for i in range(self.country_list.count()):
            item = self.country_list.item(i)
            if item:
                country = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(country, str):
                    existing_countries.add(normalize_country_name(country) or country)

        dialog = CountrySelectionDialog(self, existing_countries, title='Select Country / Countries')
        if dialog.exec() == QDialog.DialogCode.Accepted:
            countries = dialog.selected_countries()
            if countries:
                for country in countries:
                    self._add_country_item(country)
                self._auto_save_detections()

    def _add_country_item(self, country_name: str) -> None:
        """Add a country list item with an icon and display name to `self.country_list`."""
        canonical = normalize_country_name(country_name) or country_name
        item = QListWidgetItem(canonical)
        item.setData(Qt.ItemDataRole.UserRole, canonical)
        flag_code = get_country_flag_code(canonical)
        if flag_code is not None and flag_code:
            flag_icon = load_country_flag_icon(flag_code)
            if flag_icon is not None:
                item.setIcon(flag_icon)
        self.country_list.addItem(item)

    def _add_isp(self) -> None:
        """Add an ISP/company name to the list."""
        text, success = QInputDialog.getText(
            self,
            'Add ISP/Company',
            'Enter ISP or company name:\nExamples: Vodafone, Orange, Cloudflare',
        )
        if success and text:
            stripped = text.strip()
            if stripped and not self._list_contains(self.isp_list, stripped):
                self.isp_list.addItem(stripped)
                self._auto_save_detections()

    def _add_asn(self) -> None:
        """Add an ASN to the list."""
        text, success = QInputDialog.getText(
            self,
            'Add ASN',
            'Enter ASN (with or without AS prefix):\nExamples: AS13335, 15169',
        )
        if success and text:
            asn = text.strip().upper()
            if not asn.startswith('AS'):
                asn = f'AS{asn}'
            if not self._list_contains(self.asn_list, asn):
                self.asn_list.addItem(asn)
                self._auto_save_detections()
