"""Mixin providing tab-building, group-factory, and combo-rule management methods for DetectionsManagerDialog."""

from typing import TYPE_CHECKING, Literal, cast

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QPixmap
from PyQt6.QtWidgets import (
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

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis._combo_rule_editor import (
    AVAILABLE_FLAG_CODES,
    COUNTRY_FLAGS_DIR,
    ComboRuleEditorDialog,
    CountrySelectionDialog,
    read_duration_widgets_helper,
    read_voice_combo_helper,
    set_duration_widgets_helper,
    set_voice_combo_helper,
)
from session_sniffer.guis.country_data import get_country_flag_code
from session_sniffer.guis.stylesheets import (
    BOLD_LABEL_STYLESHEET,
    DESC_LABEL_STYLESHEET,
    GROUPBOX_STYLE,
    LIST_WIDGET_STYLE,
    RELAY_FILTER_WARNING_STYLESHEET,
    SECTION_SEPARATOR_LABEL_STYLESHEET,
    WARNING_ICON_LABEL_STYLESHEET,
    WARNING_TEXT_LABEL_STYLESHEET,
)
from session_sniffer.guis.utils import SUSPEND_TOOLTIP_AUTO, SUSPEND_TOOLTIP_DISABLED, SUSPEND_TOOLTIP_MANUAL
from session_sniffer.player.combo_rules import ComboRule, ComboRulesManager
from session_sniffer.settings import Settings


class DetectionsManagerTabsMixin(QDialog):
    """Mixin that adds tab-building, group-factory, and combo-rule management to DetectionsManagerDialog."""

    if TYPE_CHECKING:
        _relay_filter_warning: QWidget
        gta5_relay_packet_threshold_spin: QSpinBox
        _combo_rules_list: QListWidget
        _combo_edit_btn: QPushButton
        _combo_duplicate_btn: QPushButton
        _combo_remove_btn: QPushButton
        _combo_clear_btn: QPushButton
        country_list: QListWidget
        isp_list: QListWidget
        asn_list: QListWidget

    # ------------------------------------------------------------------
    # Tab creation
    # ------------------------------------------------------------------

    def create_player_events_tab(self) -> QWidget:
        """Create the player events tab with full protection groups for join/rejoin/leave."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)

        join_group = self._create_protection_group(
            '\u2795 Player Join',
            'Configure actions and notifications when a player joins your session',
            'player_join',
        )
        scroll_layout.addWidget(join_group)

        rejoin_group = self._create_protection_group(
            '\U0001f504 Player Rejoin',
            'Configure actions and notifications when a player rejoins your session after disconnecting',
            'player_rejoin',
        )
        scroll_layout.addWidget(rejoin_group)

        leave_group = self._create_protection_group(
            '\u274c Player Leave',
            'Configure actions and notifications when a player leaves your session',
            'player_leave',
        )
        scroll_layout.addWidget(leave_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return widget

    def create_network_based_tab(self) -> QWidget:
        """Create the network-based protections tab (VPN, Hosting, Mobile, IP Range)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)

        mobile_group = self._create_protection_group(
            '\U0001f4f1 Mobile Connection',
            'Protect against mobile/cellular connections',
            'mobile',
        )
        scroll_layout.addWidget(mobile_group)

        vpn_group = self._create_protection_group(
            '\U0001f512 VPN/Proxy/Tor',
            'Protect against connections from VPN, proxy, or Tor exit nodes',
            'vpn',
        )
        scroll_layout.addWidget(vpn_group)

        hosting_group = self._create_protection_group(
            '\U0001f3e2 Hosting/Data Center',
            'Protect against connections from hosting providers and data centers',
            'hosting',
        )
        scroll_layout.addWidget(hosting_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return widget

    def create_geo_based_tab(self) -> QWidget:
        """Create the geography-based protections tab (Country, ISP, ASN)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)

        country_group = self._create_blocklist_group(
            '\U0001f30d Country Blocklist',
            'Block or restrict players from specific countries',
            'country',
        )
        scroll_layout.addWidget(country_group)

        isp_group = self._create_blocklist_group(
            '\U0001f310 ISP/Company Blocklist',
            'Block specific ISPs or companies by name (e.g., Vodafone, Orange, Cloudflare)',
            'isp',
        )
        scroll_layout.addWidget(isp_group)

        asn_group = self._create_blocklist_group(
            '\U0001f522 ASN Number Blocklist',
            'Block specific ASN numbers (e.g., AS15169, AS13335, or just 15169, 13335)',
            'asn',
        )
        scroll_layout.addWidget(asn_group)

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        return widget

    def create_gta5_relays_tab(self) -> QWidget:
        """Create the GTA5 Relays protection tab (only shown with the GTA5 preset)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        # Warning banner: shown when GTAV_TAKETWO ranges are in the capture block list,
        # which prevents relay IPs from ever reaching the capture engine.
        filter_warning = QWidget()
        filter_warning.setStyleSheet(RELAY_FILTER_WARNING_STYLESHEET)
        filter_warning_layout = QHBoxLayout(filter_warning)
        filter_warning_layout.setContentsMargins(8, 6, 8, 6)
        filter_warning_layout.setSpacing(10)
        warning_icon_label = QLabel('\u26a0\ufe0f')
        warning_icon_label.setStyleSheet(WARNING_ICON_LABEL_STYLESHEET)
        filter_warning_layout.addWidget(warning_icon_label)
        warning_text_label = QLabel(
            '<b>Relay IPs are currently filtered out of the capture.</b><br>'
            "The 'Take-Two (GTA V)' IP ranges (<code>104.255.104.0/22</code>, <code>185.56.64.0/22</code>, "
            '<code>192.81.240.0/21</code>) are listed under <i>Block Third-Party Servers</i> in Settings. '
            'These IPs are dropped before the capture engine sees them, so relay detection will never trigger. '
            'Remove that entry from the blocked servers list to enable relay detection.',
        )
        warning_text_label.setWordWrap(True)
        warning_text_label.setStyleSheet(WARNING_TEXT_LABEL_STYLESHEET)
        filter_warning_layout.addWidget(warning_text_label, 1)
        fix_button = QPushButton('Fix It')
        fix_button.setToolTip("Remove 'Take-Two (GTA V)' from the blocked servers list and save the setting")
        fix_button.setCursor(Qt.CursorShape.PointingHandCursor)
        fix_button.clicked.connect(self._remove_gtav_taketwo_from_blocked_servers)
        filter_warning_layout.addWidget(fix_button)
        self._relay_filter_warning = filter_warning
        filter_warning.setVisible('GTAV_TAKETWO' in Settings.capture_block_third_party_servers)
        layout.addWidget(filter_warning)

        desc = QLabel(
            'Configure actions and notifications when a Take-Two relay IP exceeds the '
            'packet threshold while still connected.',
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(DESC_LABEL_STYLESHEET)
        layout.addWidget(desc)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(20)

        relay_group = self._create_protection_group(
            '\U0001f6e1 GTA5 Relay',
            'Suspend GTA5 when a relay IP exceeds the packet threshold and is still connected',
            'gta5_relay',
        )
        threshold_row = QWidget()
        threshold_layout = QHBoxLayout(threshold_row)
        threshold_layout.setContentsMargins(0, 0, 0, 0)
        _threshold_tooltip = (
            'How many packets must be exchanged with a relay IP before the protection triggers.\n\n'
            'Take-Two relay servers act as middlemen between you and other players — '
            'they route traffic through their own infrastructure.\n\n'
            'A lower value triggers faster but may react to brief or coincidental relay contact.\n'
            'A higher value waits for sustained communication, reducing false positives '
            'but delaying the response.'
        )
        threshold_label = QLabel('Packet Threshold:')
        threshold_label.setStyleSheet(BOLD_LABEL_STYLESHEET)
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
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

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
        layout.addWidget(self._combo_rules_list, stretch=1)

        # Buttons row
        btn_layout = QHBoxLayout()

        add_btn = QPushButton('\u2795 Add Rule')
        add_btn.clicked.connect(self._add_combo_rule)
        btn_layout.addWidget(add_btn)

        self._combo_edit_btn = QPushButton('\u270f\ufe0f Edit')
        self._combo_edit_btn.setEnabled(False)
        self._combo_edit_btn.clicked.connect(self._edit_combo_rule)
        btn_layout.addWidget(self._combo_edit_btn)

        self._combo_duplicate_btn = QPushButton('\U0001f4cb Duplicate')
        self._combo_duplicate_btn.setEnabled(False)
        self._combo_duplicate_btn.clicked.connect(self._duplicate_combo_rule)
        btn_layout.addWidget(self._combo_duplicate_btn)

        self._combo_remove_btn = QPushButton('\u2796 Remove')
        self._combo_remove_btn.setEnabled(False)
        self._combo_remove_btn.clicked.connect(self._remove_combo_rule)
        btn_layout.addWidget(self._combo_remove_btn)

        self._combo_clear_btn = QPushButton('\U0001f5d1\ufe0f Clear All')
        self._combo_clear_btn.setEnabled(False)
        self._combo_clear_btn.clicked.connect(self._clear_combo_rules)
        btn_layout.addWidget(self._combo_clear_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self._combo_rules_list.currentRowChanged.connect(self._update_combo_rule_buttons)
        self._combo_rules_list.itemActivated.connect(self._on_combo_item_activated)

        return widget

    # ------------------------------------------------------------------
    # GTA5 relay handlers
    # ------------------------------------------------------------------

    def _on_gta5_relay_suspend_mode_changed(self, text: str) -> None:
        """Warn the user when enabling relay detection while relay IPs are still being filtered."""
        if text == 'Disabled':
            return
        if 'GTAV_TAKETWO' not in Settings.capture_block_third_party_servers:
            return
        result = QMessageBox.question(
            self,
            TITLE,
            '\u26a0\ufe0f The Take-Two / GTA V relay IP ranges are currently being blocked by the capture filter '
            '(<i>Block Third-Party Servers</i> setting).\n\n'
            'Relay IPs will be dropped before the capture engine sees them, '
            'so this protection will never trigger while that filter is active.\n\n'
            "Would you like to automatically remove 'Take-Two (GTA V)' from the blocked servers list?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if result == QMessageBox.StandardButton.Yes:
            self._remove_gtav_taketwo_from_blocked_servers()

    def _remove_gtav_taketwo_from_blocked_servers(self) -> None:
        """Remove GTAV_TAKETWO from the blocked third-party servers list and persist the setting."""
        Settings.capture_block_third_party_servers = tuple(
            s for s in Settings.capture_block_third_party_servers if s != 'GTAV_TAKETWO'
        )
        Settings.rewrite_settings_file()
        self._relay_filter_warning.setVisible(False)
        QMessageBox.information(
            self,
            TITLE,
            "'Take-Two (GTA V)' has been removed from the blocked servers list and the setting has been saved.\n\n"
            'Please restart the capture for the change to take effect.',
        )

    # ------------------------------------------------------------------
    # Combo rule management
    # ------------------------------------------------------------------

    def _update_combo_rule_buttons(self) -> None:
        """Enable or disable combo rule action buttons based on list state."""
        has_selection = self._combo_rules_list.currentRow() >= 0
        has_items = self._combo_rules_list.count() > 0
        self._combo_edit_btn.setEnabled(has_selection)
        self._combo_duplicate_btn.setEnabled(has_selection)
        self._combo_remove_btn.setEnabled(has_selection)
        self._combo_clear_btn.setEnabled(has_items)

    def refresh_combo_rules_list(self) -> None:
        """Reload the combo rules QListWidget from ComboRulesManager."""
        self._combo_rules_list.clear()
        for rule in ComboRulesManager.rules:
            conditions_summary = ', '.join(
                f'{k}={v}' if not isinstance(v, bool) else k for k, v in rule.conditions.items()
            )
            status = '\u2705' if rule.enabled else '\u274c'
            item = QListWidgetItem(f'{status} {rule.name}  [{conditions_summary}]')
            item.setData(Qt.ItemDataRole.UserRole, id(rule))
            self._combo_rules_list.addItem(item)
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
            self.refresh_combo_rules_list()

    def _on_combo_item_activated(self, _item: QListWidgetItem) -> None:
        """Handle double-click/activation on a combo rule list item."""
        self._edit_combo_rule()

    def _edit_combo_rule(self) -> None:
        """Open editor dialog to edit the selected combo rule."""
        idx = self._get_selected_combo_rule_index()
        if idx is None:
            QMessageBox.information(self, TITLE, 'Select a rule to edit.')
            return
        existing_rule = ComboRulesManager.rules[idx]
        dialog = ComboRuleEditorDialog(self, rule=existing_rule)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ComboRulesManager.rules[idx] = dialog.get_rule()
            self.refresh_combo_rules_list()

    def _duplicate_combo_rule(self) -> None:
        """Duplicate the selected combo rule."""
        idx = self._get_selected_combo_rule_index()
        if idx is None:
            QMessageBox.information(self, TITLE, 'Select a rule to duplicate.')
            return
        original = ComboRulesManager.rules[idx]
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
        self.refresh_combo_rules_list()

    def _remove_combo_rule(self) -> None:
        """Remove the selected combo rule."""
        idx = self._get_selected_combo_rule_index()
        if idx is None:
            QMessageBox.information(self, TITLE, 'Select a rule to remove.')
            return
        rule = ComboRulesManager.rules[idx]
        reply = QMessageBox.question(
            self, TITLE, f'Remove rule "{rule.name}"?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            del ComboRulesManager.rules[idx]
            self.refresh_combo_rules_list()

    def _clear_combo_rules(self) -> None:
        """Remove all combo rules."""
        if not ComboRulesManager.rules:
            return
        reply = QMessageBox.question(
            self, TITLE, 'Remove all combo rules?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            ComboRulesManager.rules.clear()
            self.refresh_combo_rules_list()

    # ------------------------------------------------------------------
    # Group factories
    # ------------------------------------------------------------------

    def _create_protection_group(self, title: str, description: str, protection_type: str) -> QGroupBox:
        """Create a standard protection group with enable, action, process path, duration, and notification settings."""
        group = QGroupBox(title)
        group.setStyleSheet(GROUPBOX_STYLE)
        group_layout = QVBoxLayout()

        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet(DESC_LABEL_STYLESHEET)
        group_layout.addWidget(desc_label)

        # -- Protection section container (hideable when protection is not supported) --
        protection_section = QWidget()
        protection_section_layout = QVBoxLayout(protection_section)
        protection_section_layout.setContentsMargins(0, 0, 0, 0)
        setattr(self, f'{protection_type}_protection_section', protection_section)

        protection_separator = QLabel('\u2500\u2500\u2500 Protection Settings \u2500\u2500\u2500')
        protection_separator.setStyleSheet(SECTION_SEPARATOR_LABEL_STYLESHEET)
        protection_separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        protection_section_layout.addWidget(protection_separator)

        # Suspend duration
        duration_layout = QHBoxLayout()
        duration_label = QLabel('Suspend Mode:')
        duration_layout.addWidget(duration_label)

        duration_combo = QComboBox()
        duration_combo.addItems(['Disabled', 'Auto', 'Manual'])
        duration_combo.setItemData(0, SUSPEND_TOOLTIP_DISABLED, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(1, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(2, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        setattr(self, f'{protection_type}_duration_combo', duration_combo)
        duration_layout.addWidget(duration_combo)

        duration_spin = QSpinBox()
        duration_spin.setRange(1, 3600)
        duration_spin.setValue(60)
        duration_spin.setSuffix(' seconds')
        duration_spin.setVisible(False)

        def _on_duration_text_changed(text: str) -> None:
            duration_spin.setVisible(text == 'Manual')

        duration_combo.currentTextChanged.connect(_on_duration_text_changed)
        setattr(self, f'{protection_type}_duration_spin', duration_spin)
        duration_layout.addWidget(duration_spin)

        duration_layout.addStretch()
        protection_section_layout.addLayout(duration_layout)

        # Notification controls
        self._create_notification_controls(group_layout, protection_type)

        group_layout.addWidget(protection_section)

        group.setLayout(group_layout)
        return group

    def _create_blocklist_group(self, title: str, description: str, blocklist_type: str) -> QGroupBox:
        """Create a blocklist group with enable, list, action, process path, and notification settings."""
        group = QGroupBox(title)
        group.setStyleSheet(GROUPBOX_STYLE)
        group_layout = QVBoxLayout()

        desc_label = QLabel(description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet(DESC_LABEL_STYLESHEET)
        group_layout.addWidget(desc_label)

        # List widget
        list_layout = QHBoxLayout()

        list_widget = QListWidget()
        list_widget.setStyleSheet(LIST_WIDGET_STYLE)
        setattr(self, f'{blocklist_type}_list', list_widget)
        list_layout.addWidget(list_widget)

        buttons_layout = QVBoxLayout()
        add_button = QPushButton('\u2795 Add')
        add_callback = getattr(self, f'_add_{blocklist_type}')
        add_button.clicked.connect(add_callback)
        buttons_layout.addWidget(add_button)

        remove_button = QPushButton('\u2796 Remove')
        remove_callback = getattr(self, f'_remove_{blocklist_type}')
        remove_button.clicked.connect(remove_callback)
        buttons_layout.addWidget(remove_button)

        clear_button = QPushButton('\U0001f5d1\ufe0f Clear All')
        clear_button.clicked.connect(list_widget.clear)
        buttons_layout.addWidget(clear_button)

        buttons_layout.addStretch()
        list_layout.addLayout(buttons_layout)
        group_layout.addLayout(list_layout)

        # -- Protection section container (hideable when protection is not supported) --
        protection_section = QWidget()
        protection_section_layout = QVBoxLayout(protection_section)
        protection_section_layout.setContentsMargins(0, 0, 0, 0)
        setattr(self, f'{blocklist_type}_protection_section', protection_section)

        protection_separator = QLabel('\u2500\u2500\u2500 Protection Settings \u2500\u2500\u2500')
        protection_separator.setStyleSheet(SECTION_SEPARATOR_LABEL_STYLESHEET)
        protection_separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        protection_section_layout.addWidget(protection_separator)

        # Suspend duration
        duration_layout = QHBoxLayout()
        duration_label = QLabel('Suspend Mode:')
        duration_layout.addWidget(duration_label)

        duration_combo = QComboBox()
        duration_combo.addItems(['Disabled', 'Auto', 'Manual'])
        duration_combo.setItemData(0, SUSPEND_TOOLTIP_DISABLED, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(1, SUSPEND_TOOLTIP_AUTO, Qt.ItemDataRole.ToolTipRole)
        duration_combo.setItemData(2, SUSPEND_TOOLTIP_MANUAL, Qt.ItemDataRole.ToolTipRole)
        setattr(self, f'{blocklist_type}_duration_combo', duration_combo)
        duration_layout.addWidget(duration_combo)

        duration_spin = QSpinBox()
        duration_spin.setRange(1, 3600)
        duration_spin.setValue(60)
        duration_spin.setSuffix(' seconds')
        duration_spin.setVisible(False)

        def _on_duration_text_changed(text: str) -> None:
            duration_spin.setVisible(text == 'Manual')

        duration_combo.currentTextChanged.connect(_on_duration_text_changed)
        setattr(self, f'{blocklist_type}_duration_spin', duration_spin)
        duration_layout.addWidget(duration_spin)

        duration_layout.addStretch()
        protection_section_layout.addLayout(duration_layout)

        # Notification controls
        self._create_notification_controls(group_layout, blocklist_type)

        group_layout.addWidget(protection_section)

        group.setLayout(group_layout)
        return group

    def _create_notification_controls(self, parent_layout: QVBoxLayout, prefix: str) -> None:
        """Add voice notification, logging, and message box controls to a group layout."""
        separator = QLabel('\u2500\u2500\u2500 Notification Settings \u2500\u2500\u2500')
        separator.setStyleSheet(SECTION_SEPARATOR_LABEL_STYLESHEET)
        separator.setAlignment(Qt.AlignmentFlag.AlignCenter)
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
        msgbox_checkbox.setToolTip('Show a message box popup when this protection triggers')
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
            if item is not None and item.text().casefold() == value.casefold():
                return True
        return False

    def _add_country(self) -> None:
        """Add a country via a searchable selection dialog."""
        existing_countries: set[str] = set()
        for i in range(self.country_list.count()):
            item = self.country_list.item(i)
            if item is not None:
                country = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(country, str):
                    existing_countries.add(country)

        dialog = CountrySelectionDialog(self, existing_countries)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            country = dialog.selected_country()
            if country:
                self._add_country_item(country)

    def _add_country_item(self, country_name: str) -> None:
        """Add a country list item with an icon and display name."""
        item = QListWidgetItem(country_name)
        item.setData(Qt.ItemDataRole.UserRole, country_name)
        flag_code = get_country_flag_code(country_name)
        if flag_code and flag_code in AVAILABLE_FLAG_CODES:
            item.setIcon(QIcon(QPixmap(str(COUNTRY_FLAGS_DIR / f'{flag_code}.png'))))
        self.country_list.addItem(item)

    def _remove_country(self) -> None:
        """Remove selected country from the list."""
        current_item = self.country_list.currentItem()
        if current_item:
            self.country_list.takeItem(self.country_list.row(current_item))

    def _add_isp(self) -> None:
        """Add an ISP/company name to the list."""
        text, ok = QInputDialog.getText(
            self,
            'Add ISP/Company',
            'Enter ISP or company name:\nExamples: Vodafone, Orange, Cloudflare',
        )
        if ok and text:
            stripped = text.strip()
            if stripped and not self._list_contains(self.isp_list, stripped):
                self.isp_list.addItem(stripped)

    def _remove_isp(self) -> None:
        """Remove selected ISP from the list."""
        current_item = self.isp_list.currentItem()
        if current_item:
            self.isp_list.takeItem(self.isp_list.row(current_item))

    def _add_asn(self) -> None:
        """Add an ASN to the list."""
        text, ok = QInputDialog.getText(
            self,
            'Add ASN',
            'Enter ASN (with or without AS prefix):\nExamples: AS13335, 15169',
        )
        if ok and text:
            asn = text.strip().upper()
            if not asn.startswith('AS'):
                asn = f'AS{asn}'
            if not self._list_contains(self.asn_list, asn):
                self.asn_list.addItem(asn)

    def _remove_asn(self) -> None:
        """Remove selected ASN from the list."""
        current_item = self.asn_list.currentItem()
        if current_item:
            self.asn_list.takeItem(self.asn_list.row(current_item))

    # ------------------------------------------------------------------
    # Duration & voice helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _set_duration_widgets(combo: QComboBox, spin: QSpinBox, duration: int | str) -> None:
        """Set duration combo and spin box from a stored duration value."""
        set_duration_widgets_helper(combo, spin, duration)

    @staticmethod
    def _read_duration_widgets(combo: QComboBox, spin: QSpinBox) -> int | Literal['Auto']:
        """Read duration value from combo and spin box widgets."""
        return read_duration_widgets_helper(combo, spin)

    @staticmethod
    def _set_voice_combo(combo: QComboBox, value: Literal['Male', 'Female'] | bool) -> None:  # noqa: FBT001
        """Set voice combo from a stored voice notification value."""
        set_voice_combo_helper(combo, value)

    @staticmethod
    def _read_voice_combo(combo: QComboBox) -> Literal['Male', 'Female'] | bool:
        """Read voice notification value from a combo widget."""
        return read_voice_combo_helper(combo)
