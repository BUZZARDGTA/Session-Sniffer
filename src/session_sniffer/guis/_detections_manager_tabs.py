"""Mixin providing tab-building and group-factory methods for DetectionsManagerDialog."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QIcon, QKeySequence, QShortcut
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
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.constants.standalone import MAX_SUSPEND_DURATION_SECONDS, TITLE
from session_sniffer.guis._combo_rule_editor import (
    ContinentSelectionDialog,
    CountrySelectionDialog,
    populate_suspend_mode_combo,
    populate_voice_combo,
    retranslate_suspend_mode_combo,
    retranslate_voice_combo,
)
from session_sniffer.guis.country_data import (
    get_continent_code,
    get_country_flag_code,
    normalize_continent_name,
    normalize_country_name,
)
from session_sniffer.guis.delegates import ElidedTextTooltipDelegate
from session_sniffer.guis.live_language import set_i18n_colon_label
from session_sniffer.guis.stylesheets import (
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
    create_section_separator,
    load_country_flag_icon,
    render_svg_pixmap_from_resource,
    scale_by_ui,
)
from session_sniffer.i18n import tr
from session_sniffer.networking.third_party_servers import ThirdPartyServers
from session_sniffer.settings import Settings
from session_sniffer.text_utils import DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS


class DetectionsManagerTabsMixin(QDialog):
    """Mixin that adds tab-building and group-factory helpers to DetectionsManagerDialog."""

    if TYPE_CHECKING:
        _loading_settings: bool
        _relay_filter_warning: QWidget
        _relay_warning_text_label: QLabel
        _relay_fix_button: QPushButton
        gta5_relay_duration_combo: QComboBox
        continent_list: QListWidget
        country_list: QListWidget
        isp_list: QListWidget
        asn_list: QListWidget

        def _auto_save_detections(self) -> None: ...

    _translatable_groups: list[tuple[QGroupBox, str, QLabel, str]]
    _translatable_separators: list[tuple[QWidget, str]]
    _suspend_combos: list[QComboBox]
    _duration_spins: list[QSpinBox]
    _voice_combos: list[QComboBox]
    _translatable_checkboxes: list[tuple[QCheckBox, str, str]]
    _managed_list_controls: list[tuple[QPushButton, QPushButton, Callable[[], None]]]

    def _init_tab_i18n_tracking(self) -> None:
        """Initialize widget lists tracked for live language retranslation across tabs."""
        self._translatable_groups = []
        self._translatable_separators = []
        self._suspend_combos = []
        self._duration_spins = []
        self._voice_combos = []
        self._translatable_checkboxes = []
        self._managed_list_controls = []

    def _retranslate_tabs(self) -> None:
        """Update all localized text across Detections Manager tab widgets."""
        for group, title_key, desc_label, desc_key in self._translatable_groups:
            group.setTitle(tr(title_key).replace('&', '&&'))
            desc_label.setText(tr(desc_key))

        for separator, label_key in self._translatable_separators:
            sep_label = separator.findChild(QLabel)
            if sep_label is not None:
                sep_label.setText(tr(label_key))

        for combo in self._suspend_combos:
            retranslate_suspend_mode_combo(combo)

        for spin in self._duration_spins:
            spin.setSuffix(f" {tr('seconds')}")

        for combo in self._voice_combos:
            retranslate_voice_combo(combo)
            combo.setToolTip(tr('Select voice for text-to-speech notifications'))

        for checkbox, label_key, tooltip_key in self._translatable_checkboxes:
            checkbox.setText(tr(label_key))
            checkbox.setToolTip(tr(tooltip_key))

        for add_btn, clear_btn, sync_cb in self._managed_list_controls:
            add_btn.setText(f" {tr('Add')}")
            clear_btn.setText(f" {tr('Clear All')}")
            sync_cb()

        if hasattr(self, '_relay_warning_text_label'):
            self._relay_warning_text_label.setText(
                tr(
                    '<b>Relay IPs are currently filtered out of the capture.</b><br>'
                    "The 'Take-Two Interactive Software, Inc.' and/or 'Microsoft' IP ranges are listed under <i>Block Third-Party Servers</i> in Settings. "
                    'These IPs are dropped before the capture engine sees them, so relay detection will not trigger for blocked ranges. '
                    'Remove those entries from the blocked servers list to enable full relay detection.',
                ),
            )
            self._relay_fix_button.setText(f" {tr('Fix It')}")
            self._relay_fix_button.setToolTip(tr("Remove 'Take-Two Interactive Software, Inc.' and 'Microsoft' from the blocked servers list and save the setting"))

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
        warning_icon_px = scale_by_ui(20)
        warning_icon_label.setPixmap(render_svg_pixmap_from_resource('triangle-alert.svg', warning_icon_px, warning_icon_px, '#f59e0b'))
        warning_icon_label.setStyleSheet(WARNING_ICON_LABEL_STYLESHEET)
        filter_warning_layout.addWidget(warning_icon_label)
        warning_text_label = QLabel(
            tr(
                '<b>Relay IPs are currently filtered out of the capture.</b><br>'
                "The 'Take-Two Interactive Software, Inc.' and/or 'Microsoft' IP ranges are listed under <i>Block Third-Party Servers</i> in Settings. "
                'These IPs are dropped before the capture engine sees them, so relay detection will not trigger for blocked ranges. '
                'Remove those entries from the blocked servers list to enable full relay detection.',
            ),
        )
        warning_text_label.setWordWrap(True)
        warning_text_label.setStyleSheet(WARNING_TEXT_LABEL_STYLESHEET)
        self._relay_warning_text_label = warning_text_label
        filter_warning_layout.addWidget(warning_text_label, 1)
        fix_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'settings.svg')), f" {tr('Fix It')}")
        fix_button.setToolTip(tr("Remove 'Take-Two Interactive Software, Inc.' and 'Microsoft' from the blocked servers list and save the setting"))
        fix_button.setCursor(Qt.CursorShape.PointingHandCursor)
        fix_button.clicked.connect(self._remove_relay_servers_from_blocked_servers)
        self._relay_fix_button = fix_button
        filter_warning_layout.addWidget(fix_button)
        self._relay_filter_warning = filter_warning
        filter_warning.setVisible(any(name in Settings.capture_block_third_party_servers for name in ('TAKETWO_INTERACTIVE', 'MICROSOFT')))
        layout.addWidget(filter_warning)

        scroll_layout = self._add_scrollable_section(layout)

        relay_group = self._create_detection_group(
            'GTA5 Relay',
            'Triggers when a Take-Two Interactive or Microsoft relay IP is detected (thresholds are configured under Settings → Open Settings → GTA V → Session Relays).',
            'gta5_relay',
        )
        scroll_layout.addWidget(relay_group)

        scroll_layout.addStretch()
        return widget

    # ------------------------------------------------------------------
    # GTA5 relay handlers
    # ------------------------------------------------------------------

    def _on_gta5_relay_suspend_mode_changed(self, _index: int | None = None) -> None:
        """Warn the user when enabling relay detection while relay IPs are still being filtered."""
        if self._loading_settings or self.gta5_relay_duration_combo.currentData() in ('Disabled', None):
            return
        blocked_relays = [name for name in ('TAKETWO_INTERACTIVE', 'MICROSOFT') if name in Settings.capture_block_third_party_servers]
        if not blocked_relays:
            return
        blocked_names = [ThirdPartyServers[name].display_name for name in blocked_relays]
        if len(blocked_names) == 1:
            prompt = tr(
                "The '{first}' relay IP ranges are currently being blocked by the capture filter "
                '(Block Third-Party Servers setting).\n\n'
                'Relay IPs will be dropped before the capture engine sees them, '
                'so this detection will not trigger for blocked ranges while that filter is active.\n\n'
                "Would you like to automatically remove '{first}' from the blocked servers list?",
                first=blocked_names[0],
            )
        else:
            prompt = tr(
                "The '{first}' and '{second}' relay IP ranges are currently being blocked by the capture filter "
                '(Block Third-Party Servers setting).\n\n'
                'Relay IPs will be dropped before the capture engine sees them, '
                'so this detection will not trigger for blocked ranges while that filter is active.\n\n'
                "Would you like to automatically remove '{first}' and '{second}' from the blocked servers list?",
                first=blocked_names[0],
                second=blocked_names[1],
            )
        result = QMessageBox.question(
            self,
            TITLE,
            prompt,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if result == QMessageBox.StandardButton.Yes:
            self._remove_relay_servers_from_blocked_servers()

    def _remove_relay_servers_from_blocked_servers(self) -> None:
        """Remove TAKETWO_INTERACTIVE and MICROSOFT from the blocked third-party servers list and persist the setting."""
        blocked_relays = [name for name in ('TAKETWO_INTERACTIVE', 'MICROSOFT') if name in Settings.capture_block_third_party_servers]
        removed_names = [ThirdPartyServers[name].display_name for name in blocked_relays]
        Settings.capture_block_third_party_servers = tuple(
            server for server in Settings.capture_block_third_party_servers if server not in ('TAKETWO_INTERACTIVE', 'MICROSOFT')
        )
        Settings.rewrite_settings_file()
        self._relay_filter_warning.setVisible(False)
        if not removed_names:
            info_text = tr(
                'Relay server ranges have been removed from the blocked servers list and the setting has been saved.\n\n'
                'Please restart the capture for the change to take effect.',
            )
        elif len(removed_names) == 1:
            info_text = tr(
                "'{first}' has been removed from the blocked servers list and the setting has been saved.\n\nPlease restart the capture for the change to take effect.",
                first=removed_names[0],
            )
        else:
            info_text = tr(
                "'{first}' and '{second}' have been removed from the blocked servers list and the setting has been saved.\n\n"
                'Please restart the capture for the change to take effect.',
                first=removed_names[0],
                second=removed_names[1],
            )
        QMessageBox.information(self, TITLE, info_text)

    # ------------------------------------------------------------------
    # Group factories
    # ------------------------------------------------------------------

    def _create_base_group(self, title: str, description: str) -> tuple[QGroupBox, QVBoxLayout]:
        """Create a styled `QGroupBox` with a description label and return `(group, group_layout)`."""
        group = QGroupBox(tr(title).replace('&', '&&'))
        group.setStyleSheet(GROUPBOX_STYLE)
        group_layout = QVBoxLayout()

        desc_label = QLabel(tr(description))
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet(DESC_LABEL_STYLESHEET)
        group_layout.addWidget(desc_label)
        self._translatable_groups.append((group, title, desc_label, description))
        return group, group_layout

    def _append_detection_and_notification_sections(self, group_layout: QVBoxLayout, detection_type: str) -> None:
        """Append the hideable detection suspend section and notification controls to *group_layout*."""
        detection_section = QWidget()
        detection_section_layout = QVBoxLayout(detection_section)
        detection_section_layout.setContentsMargins(0, 0, 0, 0)
        setattr(self, f'{detection_type}_detection_section', detection_section)

        detection_separator = create_section_separator(tr('Detection Settings'))
        self._translatable_separators.append((detection_separator, 'Detection Settings'))
        detection_section_layout.addWidget(detection_separator)

        duration_layout = QHBoxLayout()
        duration_label = QLabel()
        set_i18n_colon_label(duration_label, 'Suspend Mode')
        duration_layout.addWidget(duration_label)

        duration_combo = QComboBox()
        duration_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        populate_suspend_mode_combo(duration_combo)
        self._suspend_combos.append(duration_combo)
        setattr(self, f'{detection_type}_duration_combo', duration_combo)
        duration_layout.addWidget(duration_combo)

        duration_spin = QSpinBox()
        duration_spin.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        duration_spin.setRange(1, MAX_SUSPEND_DURATION_SECONDS)
        duration_spin.setValue(DEFAULT_MANUAL_SUSPEND_DURATION_SECONDS)
        duration_spin.setSuffix(f" {tr('seconds')}")
        duration_spin.setVisible(False)
        self._duration_spins.append(duration_spin)

        def _on_duration_index_changed(_index: int) -> None:
            duration_spin.setVisible(duration_combo.currentData() == 'Manual')

        duration_combo.currentIndexChanged.connect(_on_duration_index_changed)
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
        add_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), f" {tr('Add')}")
        add_button.setCursor(Qt.CursorShape.PointingHandCursor)
        add_button.clicked.connect(on_add)
        buttons_layout.addWidget(add_button)

        remove_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f" {tr('Remove')}")
        remove_button.setEnabled(False)
        remove_button.setCursor(Qt.CursorShape.PointingHandCursor)
        buttons_layout.addWidget(remove_button)

        clear_button = QPushButton(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), f" {tr('Clear All')}")
        clear_button.setEnabled(False)
        clear_button.setCursor(Qt.CursorShape.PointingHandCursor)
        buttons_layout.addWidget(clear_button)

        def _sync_list_buttons(*_args: object) -> None:
            if not (isValid(list_widget) and isValid(remove_button) and isValid(clear_button)):
                return
            sel_count = len(list_widget.selectedItems())
            remove_button.setEnabled(sel_count > 0)
            remove_button.setText(f" {tr('Remove ({count})', count=sel_count)}" if sel_count > 1 else f" {tr('Remove')}")
            clear_button.setEnabled(list_widget.count() > 0)

        self._managed_list_controls.append((add_button, clear_button, _sync_list_buttons))

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
            menu.addAction(QIcon(str(ICONS_DIR_PATH / 'plus.svg')), tr('Add…')).triggered.connect(on_add)
            remove_label = tr('Remove ({count})', count=sel_count) if sel_count > 1 else tr('Remove')
            rm_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), remove_label)
            rm_act.setShortcut('Delete')
            rm_act.setEnabled(sel_count > 0)
            rm_act.triggered.connect(_on_remove_selected)
            menu.addSeparator()
            sel_all_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'square-check.svg')), tr('Select All'))
            sel_all_act.setShortcut('Ctrl+A')
            sel_all_act.setEnabled(has_items)
            sel_all_act.triggered.connect(list_widget.selectAll)
            clr_act = menu.addAction(QIcon(str(ICONS_DIR_PATH / 'remove.svg')), tr('Clear All'))
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
        separator = create_section_separator(tr('Notification Settings'))
        self._translatable_separators.append((separator, 'Notification Settings'))
        parent_layout.addWidget(separator)

        voice_layout = QHBoxLayout()
        voice_label = QLabel()
        set_i18n_colon_label(voice_label, 'Voice Notifications')
        voice_layout.addWidget(voice_label)

        voice_combo = QComboBox()
        voice_combo.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        populate_voice_combo(voice_combo)
        voice_tooltip = 'Select voice for text-to-speech notifications'
        voice_combo.setToolTip(tr(voice_tooltip))
        self._voice_combos.append(voice_combo)
        setattr(self, f'{prefix}_voice_combo', voice_combo)
        voice_layout.addWidget(voice_combo)
        voice_layout.addStretch()
        parent_layout.addLayout(voice_layout)

        msgbox_label = 'Show Message Box'
        msgbox_tooltip = 'Show a message box popup when this detection triggers'
        msgbox_checkbox = QCheckBox(tr(msgbox_label))
        msgbox_checkbox.setToolTip(tr(msgbox_tooltip))
        self._translatable_checkboxes.append((msgbox_checkbox, msgbox_label, msgbox_tooltip))
        setattr(self, f'{prefix}_msgbox_checkbox', msgbox_checkbox)
        parent_layout.addWidget(msgbox_checkbox)

        logging_label = 'Detection Logging'
        logging_tooltip = 'Log detection events to the detection logging file'
        logging_checkbox = QCheckBox(tr(logging_label))
        logging_checkbox.setToolTip(tr(logging_tooltip))
        self._translatable_checkboxes.append((logging_checkbox, logging_label, logging_tooltip))
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

        dialog = CountrySelectionDialog(self, existing_countries, title=tr('Select Country / Countries'))
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
            tr('Add ISP/Company'),
            tr('Enter ISP or company name:\nExamples: Vodafone, Orange, Cloudflare'),
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
            tr('Add ASN'),
            tr('Enter ASN (with or without AS prefix):\nExamples: AS13335, 15169'),
        )
        if success and text:
            asn = text.strip().upper()
            if not asn.startswith('AS'):
                asn = f'AS{asn}'
            if not self._list_contains(self.asn_list, asn):
                self.asn_list.addItem(asn)
                self._auto_save_detections()
