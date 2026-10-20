"""Mixin providing tab-building, group-factory, and combo-rule management methods for DetectionsManagerDialog."""

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.background import clear_voice_notification_queue
from session_sniffer.constants.local import COMBO_RULES_PATH, RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import MAX_SUSPEND_DURATION_SECONDS, TITLE
from session_sniffer.guis._combo_rule_editor import ComboRuleEditorDialog, CountrySelectionDialog
from session_sniffer.guis.country_data import get_country_flag_code
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.stylesheets import (
    DESC_LABEL_STYLESHEET,
    GROUPBOX_STYLE,
    LIST_WIDGET_STYLE,
    RELAY_FILTER_WARNING_STYLESHEET,
    WARNING_ICON_LABEL_STYLESHEET,
    WARNING_TEXT_LABEL_STYLESHEET,
)
from session_sniffer.guis.utils import (
    SUSPEND_TOOLTIP_AUTO,
    SUSPEND_TOOLTIP_DISABLED,
    SUSPEND_TOOLTIP_MANUAL,
    create_section_separator,
    load_country_flag_icon,
    render_svg_pixmap_from_resource,
)
from session_sniffer.models.combo_rules import ComboRule
from session_sniffer.player.combo_rules import ComboRulesManager
from session_sniffer.settings import Settings
from session_sniffer.text_utils import DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS


class DetectionsManagerTabsMixin(QDialog):
    """Mixin that adds tab-building, group-factory, and combo-rule management to DetectionsManagerDialog."""

    if TYPE_CHECKING:
        _loading_settings: bool
        _relay_filter_warning: QWidget
        gta5_relay_packet_threshold_spin: QSpinBox
        _combo_rules_list: QListWidget
        _combo_edit_button: QPushButton
        _combo_duplicate_button: QPushButton
        _combo_remove_button: QPushButton
        _combo_clear_button: QPushButton
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
        """Create the geography-based detections tab (Country, ISP, ASN)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        scroll_layout = self._add_scrollable_section(layout)

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
            "The 'Take-Two Interactive Software, Inc.' IP ranges are listed under <i>Block Third-Party Servers</i> in Settings. "
            'These IPs are dropped before the capture engine sees them, so relay detection will never trigger. '
            'Remove that entry from the blocked servers list to enable relay detection.',
        )
        warning_text_label.setWordWrap(True)
        warning_text_label.setStyleSheet(WARNING_TEXT_LABEL_STYLESHEET)
        filter_warning_layout.addWidget(warning_text_label, 1)
        fix_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), ' Fix It')
        fix_button.setToolTip("Remove 'Take-Two Interactive Software, Inc.' from the blocked servers list and save the setting")
        fix_button.setCursor(Qt.CursorShape.PointingHandCursor)
        fix_button.clicked.connect(self._remove_take_two_interactive_from_blocked_servers)
        filter_warning_layout.addWidget(fix_button)
        self._relay_filter_warning = filter_warning
        filter_warning.setVisible('TAKETWO_INTERACTIVE' in Settings.capture_block_third_party_servers)
        layout.addWidget(filter_warning)

        scroll_layout = self._add_scrollable_section(layout)

        relay_group = self._create_detection_group(
            'GTA5 Relay',
            'Triggers when a Take-Two Interactive relay IP exceeds the configured packet threshold.',
            'gta5_relay',
        )
        threshold_row = QWidget()
        threshold_layout = QHBoxLayout(threshold_row)
        threshold_layout.setContentsMargins(0, 0, 0, 0)
        _threshold_tooltip = (
            'How many packets must be exchanged with a relay IP before the detection triggers.\n\n'
            'Take-Two Interactive relay servers act as middlemen between you and other players — '
            'they route traffic through their own infrastructure.\n\n'
            'A lower value triggers faster but may react to brief or coincidental relay contact.\n'
            'A higher value waits for sustained communication, reducing false positives '
            'but delaying the response.'
        )
        threshold_label = QLabel('Packet Threshold:')
        threshold_label.setToolTip(_threshold_tooltip)
        threshold_layout.addWidget(threshold_label)
        threshold_spin = QSpinBox()
        threshold_spin.setRange(10, 10000)
        threshold_spin.setValue(40)
        threshold_spin.setSuffix(' packets')
        threshold_spin.setToolTip(_threshold_tooltip)
        self.gta5_relay_packet_threshold_spin = threshold_spin
        threshold_layout.addWidget(threshold_spin)
        threshold_layout.addStretch()
        cast('QVBoxLayout', relay_group.layout()).insertWidget(1, threshold_row)
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
        self._combo_rules_list.setStyleSheet(LIST_WIDGET_STYLE)
        self._combo_rules_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self._combo_rules_list.setItemDelegate(ElidedTextTooltipDelegate(self._combo_rules_list))
        self._combo_rules_list.setWordWrap(False)
        layout.addWidget(self._combo_rules_list, stretch=1)

        # Buttons row
        button_layout = QHBoxLayout()

        add_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')), ' Add Rule')
        add_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_button.clicked.connect(self._add_combo_rule)
        button_layout.addWidget(add_button)

        self._combo_toggle_button = QPushButton(' Toggle State')
        self._combo_toggle_button.setEnabled(False)
        self._combo_toggle_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_toggle_button.setFixedWidth(110)
        self._combo_toggle_button.clicked.connect(self._toggle_combo_rule)
        button_layout.addWidget(self._combo_toggle_button)

        self._combo_edit_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'square-pen.svg')), ' Edit')
        self._combo_edit_button.setEnabled(False)
        self._combo_edit_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_edit_button.clicked.connect(self._edit_combo_rule)
        button_layout.addWidget(self._combo_edit_button)

        self._combo_duplicate_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'copy.svg')), ' Duplicate')
        self._combo_duplicate_button.setEnabled(False)
        self._combo_duplicate_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_duplicate_button.clicked.connect(self._duplicate_combo_rule)
        button_layout.addWidget(self._combo_duplicate_button)

        self._combo_remove_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Remove')
        self._combo_remove_button.setEnabled(False)
        self._combo_remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_remove_button.clicked.connect(self._remove_combo_rule)
        button_layout.addWidget(self._combo_remove_button)

        self._combo_clear_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Clear All')
        self._combo_clear_button.setEnabled(False)
        self._combo_clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self._combo_clear_button.clicked.connect(self._clear_combo_rules)
        button_layout.addWidget(self._combo_clear_button)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        self._combo_rules_list.currentRowChanged.connect(self._update_combo_rule_buttons)
        self._combo_rules_list.itemActivated.connect(self._on_combo_item_activated)

        return widget

    # ------------------------------------------------------------------
    # GTA5 relay handlers
    # ------------------------------------------------------------------

    def _on_gta5_relay_suspend_mode_changed(self, text: str) -> None:
        """Warn the user when enabling relay detection while relay IPs are still being filtered."""
        if self._loading_settings or text == 'Disabled':
            return
        if 'TAKETWO_INTERACTIVE' not in Settings.capture_block_third_party_servers:
            return
        result = QMessageBox.question(
            self,
            TITLE,
            'The Take-Two Interactive Software, Inc. relay IP ranges are currently being blocked by the capture filter '
            '(<i>Block Third-Party Servers</i> setting).\n\n'
            'Relay IPs will be dropped before the capture engine sees them, '
            'so this detection will never trigger while that filter is active.\n\n'
            "Would you like to automatically remove 'Take-Two Interactive Software, Inc.' from the blocked servers list?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if result == QMessageBox.StandardButton.Yes:
            self._remove_take_two_interactive_from_blocked_servers()

    def _remove_take_two_interactive_from_blocked_servers(self) -> None:
        """Remove TAKETWO_INTERACTIVE from the blocked third-party servers list and persist the setting."""
        Settings.capture_block_third_party_servers = tuple(server for server in Settings.capture_block_third_party_servers if server != 'TAKETWO_INTERACTIVE')
        Settings.rewrite_settings_file()
        self._relay_filter_warning.setVisible(False)
        QMessageBox.information(
            self,
            TITLE,
            "'Take-Two Interactive Software, Inc.' has been removed from the blocked servers list and the setting has been saved.\n\n"
            'Please restart the capture for the change to take effect.',
        )

    # ------------------------------------------------------------------
    # Combo rule management
    # ------------------------------------------------------------------

    def _update_combo_rule_buttons(self) -> None:
        """Synchronize the enabled/disabled state of combo rule management buttons."""
        has_selection = self._combo_rules_list.currentRow() >= 0
        has_items = self._combo_rules_list.count() > 0
        self._combo_edit_button.setEnabled(has_selection)
        self._combo_duplicate_button.setEnabled(has_selection)
        self._combo_remove_button.setEnabled(has_selection)
        self._combo_toggle_button.setEnabled(has_selection)
        self._combo_clear_button.setEnabled(has_items)

        if has_selection:
            index = self._get_selected_combo_rule_index()
            if index is not None:
                rule = ComboRulesManager.rules[index]
                self._combo_toggle_button.setText(' Disable Rule' if rule.enabled else ' Enable Rule')
        else:
            self._combo_toggle_button.setText(' Toggle State')

    def refresh_combo_rules_list(self) -> None:
        """Reload the combo rules QListWidget from ComboRulesManager."""
        current_row = self._combo_rules_list.currentRow()
        self._combo_rules_list.clear()
        for rule in ComboRulesManager.rules:
            conditions_summary = ', '.join(f'{key}={value}' if not isinstance(value, bool) else key for key, value in rule.conditions.items())
            item = QListWidgetItem(f'{rule.name}  [{conditions_summary}]')
            item.setIcon(QIcon(str(RESOURCES_DIR_PATH / 'icons' / ('check.svg' if rule.enabled else 'x.svg'))))
            item.setData(Qt.ItemDataRole.UserRole, id(rule))
            self._combo_rules_list.addItem(item)

        if 0 <= current_row < self._combo_rules_list.count():
            self._combo_rules_list.setCurrentRow(current_row)

        self._update_combo_rule_buttons()

    def _get_selected_combo_rule_index(self) -> int | None:
        """Return the index of the selected combo rule, or None."""
        current = self._combo_rules_list.currentRow()
        if current < 0 or current >= len(ComboRulesManager.rules):
            return None
        return current

    def _add_combo_rule(self) -> None:
        """Open editor dialog to create a new combo rule."""
        dialog = ComboRuleEditorDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ComboRulesManager.rules.append(dialog.get_rule())
            ComboRulesManager.save_to_file(COMBO_RULES_PATH)
            self.refresh_combo_rules_list()

    def _on_combo_item_activated(self, _item: QListWidgetItem) -> None:
        """Handle double-click/activation on a combo rule list item."""
        self._edit_combo_rule()

    def _edit_combo_rule(self) -> None:
        """Open editor dialog to edit the selected combo rule."""
        index = self._get_selected_combo_rule_index()
        if index is None:
            QMessageBox.information(self, TITLE, 'Select a rule to edit.')
            return
        existing_rule = ComboRulesManager.rules[index]
        dialog = ComboRuleEditorDialog(self, rule=existing_rule)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_rule = dialog.get_rule()
            if existing_rule.enabled and existing_rule.voice_notifications and (not new_rule.enabled or not new_rule.voice_notifications):
                clear_voice_notification_queue()
            ComboRulesManager.rules[index] = new_rule
            ComboRulesManager.save_to_file(COMBO_RULES_PATH)
            self.refresh_combo_rules_list()

    def _toggle_combo_rule(self) -> None:
        """Toggle the enabled state of the selected combo rule."""
        index = self._get_selected_combo_rule_index()
        if index is None:
            return
        rule = ComboRulesManager.rules[index]
        rule.enabled = not rule.enabled
        if not rule.enabled and rule.voice_notifications:
            clear_voice_notification_queue()
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.refresh_combo_rules_list()

    def _duplicate_combo_rule(self) -> None:
        """Duplicate the selected combo rule."""
        index = self._get_selected_combo_rule_index()
        if index is None:
            QMessageBox.information(self, TITLE, 'Select a rule to duplicate.')
            return
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
        ComboRulesManager.save_to_file(COMBO_RULES_PATH)
        self.refresh_combo_rules_list()

    def _remove_combo_rule(self) -> None:
        """Remove the selected combo rule."""
        index = self._get_selected_combo_rule_index()
        if index is None:
            QMessageBox.information(self, TITLE, 'Select a rule to remove.')
            return
        rule = ComboRulesManager.rules[index]
        reply = QMessageBox.question(
            self,
            TITLE,
            f'Remove rule "{rule.name}"?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            if rule.enabled and rule.voice_notifications:
                clear_voice_notification_queue()
            del ComboRulesManager.rules[index]
            ComboRulesManager.save_to_file(COMBO_RULES_PATH)
            self.refresh_combo_rules_list()

    def _clear_combo_rules(self) -> None:
        """Remove all combo rules."""
        if not ComboRulesManager.rules:
            return
        reply = QMessageBox.question(
            self,
            TITLE,
            'Remove all combo rules?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            if any(rule.enabled and rule.voice_notifications for rule in ComboRulesManager.rules):
                clear_voice_notification_queue()
            ComboRulesManager.rules.clear()
            ComboRulesManager.save_to_file(COMBO_RULES_PATH)
            self.refresh_combo_rules_list()

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
        duration_combo.addItems(['Disabled', 'Auto', 'Manual'])
        duration_combo.setItemData(0, SUSPEND_TOOLTIP_DISABLED, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(1, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(2, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        setattr(self, f'{detection_type}_duration_combo', duration_combo)
        duration_layout.addWidget(duration_combo)

        duration_spin = QSpinBox()
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

        # List widget
        list_layout = QHBoxLayout()

        list_widget = QListWidget()
        list_widget.setStyleSheet(LIST_WIDGET_STYLE)
        list_widget.setItemDelegate(ElidedTextTooltipDelegate(list_widget))
        list_widget.setWordWrap(False)
        setattr(self, f'{detection_type}_list', list_widget)
        list_layout.addWidget(list_widget)

        buttons_layout = QVBoxLayout()
        add_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'plus.svg')), ' Add')
        add_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_button.clicked.connect(on_add)
        buttons_layout.addWidget(add_button)

        def _on_remove_selected() -> None:
            current_item = list_widget.currentItem()
            if current_item:
                list_widget.takeItem(list_widget.row(current_item))
                self._auto_save_detections()

        remove_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Remove')
        remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
        remove_button.clicked.connect(_on_remove_selected)
        buttons_layout.addWidget(remove_button)

        def _on_clear_list() -> None:
            if list_widget.count() > 0:
                list_widget.clear()
                self._auto_save_detections()

        clear_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'remove.svg')), ' Clear All')
        clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        clear_button.clicked.connect(_on_clear_list)
        buttons_layout.addWidget(clear_button)

        buttons_layout.addStretch()
        list_layout.addLayout(buttons_layout)
        group_layout.addLayout(list_layout)

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

    def _add_country(self) -> None:
        """Add a country via a searchable selection dialog."""
        existing_countries: set[str] = set()
        for i in range(self.country_list.count()):
            item = self.country_list.item(i)
            if item:
                country = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(country, str):
                    existing_countries.add(country)

        dialog = CountrySelectionDialog(self, existing_countries)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            country = dialog.selected_country()
            if country is not None and country:
                self._add_country_item(country)
                self._auto_save_detections()

    def _add_country_item(self, country_name: str) -> None:
        """Add a country list item with an icon and display name."""
        item = QListWidgetItem(country_name)
        item.setData(Qt.ItemDataRole.UserRole, country_name)
        flag_code = get_country_flag_code(country_name)
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
