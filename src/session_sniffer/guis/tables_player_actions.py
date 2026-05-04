"""Player action helpers for session table context menus (info dialogs, ping)."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QClipboard, QCloseEvent, QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QInputDialog,
    QLabel,
    QMessageBox,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import BIN_DIR_PATH, SESSIONS_LOGGING_DIR_PATH, USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import MAX_PORT, MIN_PORT, TITLE
from session_sniffer.error_messages import ensure_instance
from session_sniffer.guis.app import app
from session_sniffer.guis.userip_manager_helpers import IPRangeBuilderDialog
from session_sniffer.guis.utils import format_player_display, get_screen_size, resize_window_for_screen, set_dialog_window_flags
from session_sniffer.player.seen_stats import SEEN_STATS_LABELS, SeenStats, analyze_sessions_logging
from session_sniffer.settings.settings import Settings
from session_sniffer.utils import run_cmd_command, run_cmd_script

if TYPE_CHECKING:
    from collections.abc import Callable

    from session_sniffer.models.player import Player

PAPING_PATH = BIN_DIR_PATH / 'paping.exe'

_UNSET_SENTINEL = '...'


def _is_unset(value: object) -> bool:
    """Return True if a player lookup field has not yet been populated."""
    return value is None or value == _UNSET_SENTINEL


def _fmt_text(value: object) -> str:
    """Format a generic lookup field, showing 'N/A' for unset values."""
    if _is_unset(value):
        return 'N/A'
    return str(value)


def _fmt_bool(value: object) -> str:
    """Format a boolean-ish lookup field as Yes / No / N/A."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {'true', 'yes', '1'}:
            return 'Yes'
        if lowered in {'false', 'no', '0'}:
            return 'No'
    return str(value)


def _fmt_ms(value: object) -> str:
    """Format a millisecond RTT value with one decimal."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{value:.1f} ms'
    return str(value)


def _fmt_int(value: object) -> str:
    """Format an integer count, falling back to N/A for unset values."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{int(value)}'
    return str(value)


def _fmt_loss_pct(value: object) -> str:
    """Format a packet-loss percentage with one decimal place."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{value:.1f} %'
    return str(value)


def _fmt_packet_summary(transmitted: object, received: object) -> str:
    """Format a 'sent / received' summary line."""
    if _is_unset(transmitted) and _is_unset(received):
        return 'N/A'
    return f'{_fmt_int(transmitted)} sent · {_fmt_int(received)} received'


def _fmt_ping_times(value: object, *, max_samples: int = 10) -> str:
    """Format the recent ping time samples as a compact ms list."""
    if _is_unset(value):
        return 'N/A'
    if not isinstance(value, list):
        return str(value)
    times = cast('list[object]', value)
    if not times:
        return 'No samples yet'
    samples = times[-max_samples:]
    formatted = ', '.join(f'{t:.1f}' for t in samples if isinstance(t, (int, float)))
    if not formatted:
        return 'N/A'
    suffix = '' if len(times) <= max_samples else f' (last {max_samples} of {len(times)})'
    return f'[{formatted}] ms{suffix}'


def _fmt_ping_status(value: object) -> str:
    """Format the is_pinging status field."""
    if _is_unset(value):
        return 'Pending…'
    if isinstance(value, bool):
        return 'Active' if value else 'Idle'
    return str(value)


def _userip_database_text(player: Player) -> str:
    """Return the relative UserIP database path or 'No' when not present."""
    if player.userip_detection is None or player.userip is None:
        return 'No'
    relative = player.userip.database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix('')
    return str(relative)


class SeenStatsDialog(QDialog):
    """A dialog showing historical encounter statistics for a player IP."""

    def __init__(self, parent: QWidget, player: Player) -> None:
        """Compute seen stats and build the dialog UI."""
        super().__init__(parent)
        set_dialog_window_flags(self)
        stats = analyze_sessions_logging(SESSIONS_LOGGING_DIR_PATH, player.ip)

        self.setWindowTitle(f'{TITLE} - Seen Stats ({format_player_display(player.ip, player.usernames)})')
        self.setMinimumSize(400, 300)

        screen_width, screen_height = get_screen_size()

        if (screen_width, screen_height) >= (1920, 1080):
            self.resize(500, 360)
        elif (screen_width, screen_height) >= (1280, 720):
            self.resize(460, 340)
        else:
            resize_window_for_screen(self, screen_width, screen_height)
            self.resize(min(self.width(), max(400, screen_width - 80)), min(self.height(), max(300, screen_height - 80)))

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        header = QLabel(f'\U0001f4c5  Seen Stats \u2014 {format_player_display(player.ip, player.usernames)}')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
            'color: #ffffff; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
            ' stop:0 #6b46c1, stop:1 #9f7aea); border-radius: 6px;',
        )
        header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        outer_layout.addWidget(header)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer_layout.addWidget(scroll, stretch=1)

        scroll_content = QWidget()
        scroll.setWidget(scroll_content)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(2, 2, 2, 2)
        scroll_layout.setSpacing(10)

        self._build_encounter_group(scroll_layout, stats)
        scroll_layout.addStretch(1)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        button_box.rejected.connect(self.reject)
        button_box.accepted.connect(self.accept)
        outer_layout.addWidget(button_box)

    def _build_encounter_group(self, parent_layout: QVBoxLayout, stats: SeenStats) -> None:
        """Add the 'Session Encounters' section to the scroll layout."""
        group, form = self._make_group('\U0001f4c5  Session Encounters', accent='#6b46c1')
        for key, label in SEEN_STATS_LABELS.items():
            self._add_row(form, label, str(getattr(stats, key)))
        parent_layout.addWidget(group)

    @staticmethod
    def _make_group(title: str, *, accent: str) -> tuple[QGroupBox, QFormLayout]:
        """Create a styled group box with an attached QFormLayout and return both."""
        group = QGroupBox(title)
        group.setStyleSheet(
            'QGroupBox {'
            f' border: 1px solid {accent};'
            ' border-radius: 6px;'
            ' margin-top: 14px;'
            ' padding-top: 10px;'
            ' background: rgba(255, 255, 255, 8);'
            ' font-weight: bold;'
            '}'
            'QGroupBox::title {'
            ' subcontrol-origin: margin;'
            ' subcontrol-position: top left;'
            ' left: 10px; padding: 2px 8px;'
            f' background: {accent};'
            ' color: #ffffff;'
            ' border-radius: 4px;'
            '}',
        )
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(5)
        form.setContentsMargins(10, 8, 10, 10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        return group, form

    @staticmethod
    def _add_row(form: QFormLayout, label_text: str, value: str) -> None:
        """Append a copyable label/value row to *form*."""
        label_widget = QLabel(f'{label_text}:')
        label_widget.setStyleSheet('color: #cbd5e0; font-weight: 600; background: transparent;')

        value_widget = QLabel(value)
        value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        value_widget.setCursor(Qt.CursorShape.IBeamCursor)
        value_widget.setWordWrap(True)
        value_widget.setFont(QFont('Consolas'))
        value_widget.setStyleSheet('color: #ffffff; font-weight: bold; padding: 3px 6px; border-radius: 3px; background: rgba(255, 255, 255, 12);')
        value_widget.setToolTip('Click and drag to select; Ctrl+C to copy.')

        form.addRow(label_widget, value_widget)

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802  # Qt override name
        """Handle the close event."""
        super().closeEvent(a0)


class IPLookupDetailsDialog(QDialog):
    """A non-modal dialog showing live, copyable IP lookup details for a player.

    The dialog refreshes its values periodically so reverse-DNS, IP-API,
    GeoLite2 and ping data appear as they are resolved.
    """

    _REFRESH_INTERVAL_MS = 500

    def __init__(self, parent: QWidget, player: Player) -> None:
        """Build the dialog, install the periodic refresh timer, and show initial values."""
        super().__init__(parent)
        set_dialog_window_flags(self)
        self._player = player
        self._rows: list[tuple[QLabel, Callable[[Player], str]]] = []

        self.setWindowTitle(f'{TITLE} - IP Lookup Details ({format_player_display(player.ip, player.usernames)})')
        self.setMinimumSize(560, 460)

        screen_width, screen_height = get_screen_size()

        if (screen_width, screen_height) >= (1920, 1080):
            self.resize(820, 720)
        elif (screen_width, screen_height) >= (1280, 720):
            self.resize(720, 640)
        else:
            resize_window_for_screen(self, screen_width, screen_height)
            self.resize(min(self.width(), max(560, screen_width - 80)), min(self.height(), max(460, screen_height - 80)))

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._header_label = QLabel(f'\U0001f50e  IP Lookup Details \u2014 {format_player_display(player.ip, player.usernames)}')
        self._header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._header_label.setStyleSheet(
            'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
            'color: #ffffff; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
            ' stop:0 #2b6cb0, stop:1 #4c51bf); border-radius: 6px;',
        )
        self._header_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        outer_layout.addWidget(self._header_label)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer_layout.addWidget(scroll, stretch=1)

        scroll_content = QWidget()
        scroll.setWidget(scroll_content)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(2, 2, 2, 2)
        scroll_layout.setSpacing(10)

        self._build_player_info_group(scroll_layout)
        self._build_iplookup_group(scroll_layout)
        self._build_ping_group(scroll_layout)
        scroll_layout.addStretch(1)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        button_box.rejected.connect(self.reject)
        button_box.accepted.connect(self.accept)
        outer_layout.addWidget(button_box)

        self._timer = QTimer(self)
        self._timer.setInterval(self._REFRESH_INTERVAL_MS)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

        self._refresh()

    def _build_player_info_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'Player Info' section to the scroll layout."""
        group, form = self._make_group('\U0001f464  Player Info', accent='#2b6cb0')
        self._add_row(form, 'IP Address', lambda p: p.ip)
        self._add_row(form, 'Hostname', lambda p: _fmt_text(p.reverse_dns.hostname))
        self._add_row(form, 'Username(s)', lambda p: ', '.join(p.usernames) or 'N/A')
        self._add_row(form, 'In UserIP database', _userip_database_text)
        self._add_row(form, 'First Port', lambda p: str(p.ports.first))
        self._add_row(form, 'Middle Port(s)', lambda p: ', '.join(map(str, p.ports.middle)) or 'N/A')
        self._add_row(form, 'Last Port', lambda p: str(p.ports.last))
        parent_layout.addWidget(group)

    def _build_iplookup_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'IP Lookup Details' section to the scroll layout."""
        group, form = self._make_group('\U0001f30d  IP Lookup Details', accent='#38a169')
        self._add_row(form, 'Continent', lambda p: _fmt_text(p.iplookup.ipapi.continent))
        self._add_row(form, 'Continent Code', lambda p: _fmt_text(p.iplookup.ipapi.continent_code))
        self._add_row(form, 'Country', lambda p: _fmt_text(p.iplookup.geolite2.country))
        self._add_row(form, 'Country Code', lambda p: _fmt_text(p.iplookup.geolite2.country_code))
        self._add_row(form, 'Region', lambda p: _fmt_text(p.iplookup.ipapi.region))
        self._add_row(form, 'Region Code', lambda p: _fmt_text(p.iplookup.ipapi.region_code))
        self._add_row(form, 'City', lambda p: _fmt_text(p.iplookup.geolite2.city))
        self._add_row(form, 'District', lambda p: _fmt_text(p.iplookup.ipapi.district))
        self._add_row(form, 'ZIP Code', lambda p: _fmt_text(p.iplookup.ipapi.zip_code))
        self._add_row(form, 'Latitude', lambda p: _fmt_text(p.iplookup.ipapi.lat))
        self._add_row(form, 'Longitude', lambda p: _fmt_text(p.iplookup.ipapi.lon))
        self._add_row(form, 'Time Zone', lambda p: _fmt_text(p.iplookup.ipapi.time_zone))
        self._add_row(form, 'UTC Offset', lambda p: _fmt_text(p.iplookup.ipapi.offset))
        self._add_row(form, 'Currency', lambda p: _fmt_text(p.iplookup.ipapi.currency))
        self._add_row(form, 'Organization', lambda p: _fmt_text(p.iplookup.ipapi.org))
        self._add_row(form, 'ISP', lambda p: _fmt_text(p.iplookup.ipapi.isp))
        self._add_row(form, 'GeoLite2 ASN / ISP', lambda p: _fmt_text(p.iplookup.geolite2.asn))
        self._add_row(form, 'AS Number', lambda p: _fmt_text(p.iplookup.ipapi.asn))
        self._add_row(form, 'AS Name', lambda p: _fmt_text(p.iplookup.ipapi.as_name))
        self._add_row(form, 'Mobile (cellular)', lambda p: _fmt_bool(p.iplookup.ipapi.mobile))
        self._add_row(form, 'Proxy / VPN / Tor', lambda p: _fmt_bool(p.iplookup.ipapi.proxy))
        self._add_row(form, 'Hosting / Datacenter', lambda p: _fmt_bool(p.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)

    def _build_ping_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'Ping Response' section to the scroll layout, with cleaner formatting."""
        group, form = self._make_group('\U0001f4e1  Ping Response', accent='#d69e2e')
        self._add_row(form, 'Status', lambda p: _fmt_ping_status(p.ping.is_pinging))
        self._add_row(form, 'Packets', lambda p: _fmt_packet_summary(p.ping.packets_transmitted, p.ping.packets_received))
        self._add_row(form, 'Packets Transmitted', lambda p: _fmt_int(p.ping.packets_transmitted))
        self._add_row(form, 'Packets Received', lambda p: _fmt_int(p.ping.packets_received))
        self._add_row(form, 'Packet Loss', lambda p: _fmt_loss_pct(p.ping.packet_loss))
        self._add_row(form, 'Packet Errors', lambda p: _fmt_int(p.ping.packet_errors))
        self._add_row(form, 'Packet Duplicates', lambda p: _fmt_int(p.ping.packet_duplicates))
        self._add_row(form, 'RTT Minimum', lambda p: _fmt_ms(p.ping.rtt_min))
        self._add_row(form, 'RTT Average', lambda p: _fmt_ms(p.ping.rtt_avg))
        self._add_row(form, 'RTT Maximum', lambda p: _fmt_ms(p.ping.rtt_max))
        self._add_row(form, 'RTT Mean Deviation', lambda p: _fmt_ms(p.ping.rtt_mdev))
        self._add_row(form, 'Recent Ping Times', lambda p: _fmt_ping_times(p.ping.ping_times))
        parent_layout.addWidget(group)

    @staticmethod
    def _make_group(title: str, *, accent: str) -> tuple[QGroupBox, QFormLayout]:
        """Create a styled group box with an attached `QFormLayout` and return both."""
        group = QGroupBox(title)
        group.setStyleSheet(
            'QGroupBox {'
            f' border: 1px solid {accent};'
            ' border-radius: 6px;'
            ' margin-top: 14px;'
            ' padding-top: 10px;'
            ' background: rgba(255, 255, 255, 8);'
            ' font-weight: bold;'
            '}'
            'QGroupBox::title {'
            ' subcontrol-origin: margin;'
            ' subcontrol-position: top left;'
            ' left: 10px; padding: 2px 8px;'
            f' background: {accent};'
            ' color: #ffffff;'
            ' border-radius: 4px;'
            '}',
        )
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(5)
        form.setContentsMargins(10, 8, 10, 10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        return group, form

    def _add_row(self, form: QFormLayout, label_text: str, provider: Callable[[Player], str]) -> None:
        """Append a label / copyable-value row to *form* and register it for refresh."""
        label_widget = QLabel(f'{label_text}:')
        label_widget.setStyleSheet('color: #cbd5e0; font-weight: 600; background: transparent;')

        value_widget = QLabel()
        value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        value_widget.setCursor(Qt.CursorShape.IBeamCursor)
        value_widget.setWordWrap(True)
        value_widget.setFont(QFont('Consolas'))
        value_widget.setStyleSheet('color: #ffffff; font-weight: bold; padding: 3px 6px; border-radius: 3px; background: rgba(255, 255, 255, 12);')
        value_widget.setToolTip('Click and drag to select; Ctrl+C to copy.')

        form.addRow(label_widget, value_widget)
        self._rows.append((value_widget, provider))

    def _refresh(self) -> None:
        """Re-evaluate every row provider and update the value widget text."""
        player = self._player
        display = format_player_display(player.ip, player.usernames)
        new_title = f'{TITLE} - IP Lookup Details ({display})'
        if self.windowTitle() != new_title:
            self.setWindowTitle(new_title)
            self._header_label.setText(f'\U0001f50e  IP Lookup Details \u2014 {display}')
        for value_widget, provider in self._rows:
            text = provider(player)
            if value_widget.text() != text:
                value_widget.setText(text)

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802  # Qt override name
        """Stop the refresh timer when the dialog is closed."""
        self._timer.stop()
        super().closeEvent(a0)


def show_detailed_ip_lookup(parent: QWidget, player: Player) -> None:
    """Open the brand-new live IP Lookup Details dialog for *player*."""
    dialog = IPLookupDetailsDialog(parent, player)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()


def show_seen_stats(parent: QWidget, player: Player) -> None:
    """Open the Seen Stats dialog for *player*."""
    dialog = SeenStatsDialog(parent, player)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()


class UserIPDetectedDialog(QDialog):
    """A non-modal dialog showing a snapshot of UserIP detection data for a player."""

    def __init__(self, parent: QWidget | None, player: Player) -> None:
        """Snapshot player data at detection time and build the dialog UI."""
        super().__init__(parent)
        set_dialog_window_flags(self)

        self.setWindowTitle(f'{TITLE} - UserIP Detected ({format_player_display(player.ip, player.usernames)})')
        self.setMinimumSize(560, 460)

        screen_width, screen_height = get_screen_size()

        if (screen_width, screen_height) >= (1920, 1080):
            self.resize(700, 580)
        elif (screen_width, screen_height) >= (1280, 720):
            self.resize(620, 520)
        else:
            resize_window_for_screen(self, screen_width, screen_height)
            self.resize(min(self.width(), max(560, screen_width - 80)), min(self.height(), max(460, screen_height - 80)))

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        header = QLabel(f'\U0001f514  UserIP Detected \u2014 {format_player_display(player.ip, player.usernames)}')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
            'color: #ffffff; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
            ' stop:0 #c53030, stop:1 #dd6b20); border-radius: 6px;',
        )
        header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        outer_layout.addWidget(header)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer_layout.addWidget(scroll, stretch=1)

        scroll_content = QWidget()
        scroll.setWidget(scroll_content)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(2, 2, 2, 2)
        scroll_layout.setSpacing(10)

        self._build_detection_group(scroll_layout, player)
        self._build_iplookup_group(scroll_layout, player)
        scroll_layout.addStretch(1)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        button_box.rejected.connect(self.reject)
        button_box.accepted.connect(self.accept)
        outer_layout.addWidget(button_box)

    def _build_detection_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Detection Details' section to the scroll layout."""
        group, form = self._make_group('\U0001f534  Detection Details', accent='#c53030')
        detection = player.userip_detection
        userip = player.userip
        detection_time = detection.time if detection is not None else 'N/A'
        usernames = ', '.join(userip.usernames) if userip is not None and userip.usernames else 'N/A'
        ports_str = ', '.join(map(str, reversed(player.ports.all))) if player.ports.all else 'N/A'
        if userip is not None:
            try:
                relative_db = str(userip.database_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))
            except ValueError:
                relative_db = str(userip.database_path)
        else:
            relative_db = 'N/A'
        detection_type = detection.type if detection is not None else 'N/A'
        self._add_row(form, 'Detection Time', detection_time)
        self._add_row(form, 'Username(s)', usernames)
        self._add_row(form, 'IP Address', player.ip)
        self._add_row(form, 'Hostname', _fmt_text(player.reverse_dns.hostname))
        self._add_row(form, 'Port(s)', ports_str)
        self._add_row(form, 'Country Code', _fmt_text(player.iplookup.geolite2.country_code))
        self._add_row(form, 'Detection Type', detection_type)
        self._add_row(form, 'Database', relative_db)
        parent_layout.addWidget(group)

    def _build_iplookup_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'IP Lookup' section to the scroll layout."""
        group, form = self._make_group('\U0001f30d  IP Lookup', accent='#38a169')
        self._add_row(form, 'Continent', _fmt_text(player.iplookup.ipapi.continent))
        self._add_row(form, 'Country', _fmt_text(player.iplookup.geolite2.country))
        self._add_row(form, 'Region', _fmt_text(player.iplookup.ipapi.region))
        self._add_row(form, 'City', _fmt_text(player.iplookup.geolite2.city))
        self._add_row(form, 'Organization', _fmt_text(player.iplookup.ipapi.org))
        self._add_row(form, 'ISP', _fmt_text(player.iplookup.ipapi.isp))
        self._add_row(form, 'GeoLite2 ASN / ISP', _fmt_text(player.iplookup.geolite2.asn))
        self._add_row(form, 'AS Name', _fmt_text(player.iplookup.ipapi.as_name))
        self._add_row(form, 'Mobile (cellular)', _fmt_bool(player.iplookup.ipapi.mobile))
        self._add_row(form, 'Proxy / VPN / Tor', _fmt_bool(player.iplookup.ipapi.proxy))
        self._add_row(form, 'Hosting / Datacenter', _fmt_bool(player.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)

    @staticmethod
    def _make_group(title: str, *, accent: str) -> tuple[QGroupBox, QFormLayout]:
        """Create a styled group box with an attached QFormLayout and return both."""
        group = QGroupBox(title)
        group.setStyleSheet(
            'QGroupBox {'
            f' border: 1px solid {accent};'
            ' border-radius: 6px;'
            ' margin-top: 14px;'
            ' padding-top: 10px;'
            ' background: rgba(255, 255, 255, 8);'
            ' font-weight: bold;'
            '}'
            'QGroupBox::title {'
            ' subcontrol-origin: margin;'
            ' subcontrol-position: top left;'
            ' left: 10px; padding: 2px 8px;'
            f' background: {accent};'
            ' color: #ffffff;'
            ' border-radius: 4px;'
            '}',
        )
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(5)
        form.setContentsMargins(10, 8, 10, 10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        return group, form

    @staticmethod
    def _add_row(form: QFormLayout, label_text: str, value: str) -> None:
        """Append a copyable label/value row to *form*."""
        label_widget = QLabel(f'{label_text}:')
        label_widget.setStyleSheet('color: #cbd5e0; font-weight: 600; background: transparent;')

        value_widget = QLabel(value)
        value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        value_widget.setCursor(Qt.CursorShape.IBeamCursor)
        value_widget.setWordWrap(True)
        value_widget.setFont(QFont('Consolas'))
        value_widget.setStyleSheet('color: #ffffff; font-weight: bold; padding: 3px 6px; border-radius: 3px; background: rgba(255, 255, 255, 12);')
        value_widget.setToolTip('Click and drag to select; Ctrl+C to copy.')

        form.addRow(label_widget, value_widget)

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802  # Qt override name
        """Handle the close event."""
        super().closeEvent(a0)


def show_userip_detected_dialog(parent: QWidget | None, player: Player) -> None:
    """Open the UserIP Detected dialog for *player*."""
    dialog = UserIPDetectedDialog(parent, player)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()


@dataclass(slots=True, kw_only=True)
class PlayerDetectionInfo:
    """Bundled metadata for a player detection event notification."""

    emoji: str
    title: str
    description: str
    event_time: str
    data_ready: bool


_DETECTION_EMOJI_HEADER_COLORS: dict[str, tuple[str, str]] = {
    '\U0001f7e2': ('#276749', '#38a169'),   # 🟢 joined  → green
    '\U0001f504': ('#2b6cb0', '#4c51bf'),   # 🔄 rejoined → blue
    '\U0001f534': ('#9b2c2c', '#c53030'),   # 🔴 left     → red
}
_DETECTION_DEFAULT_HEADER_COLORS = ('#2d3748', '#4a5568')


class PlayerDetectionDialog(QDialog):
    """A non-modal dialog showing a snapshot of player detection event data."""

    def __init__(
        self,
        parent: QWidget | None,
        player: Player,
        info: PlayerDetectionInfo,
    ) -> None:
        """Snapshot player data at event time and build the dialog UI."""
        super().__init__(parent)
        set_dialog_window_flags(self)

        self.setWindowTitle(f'{TITLE} - {info.title} ({format_player_display(player.ip, player.usernames)})')
        self.setMinimumSize(560, 460)

        screen_width, screen_height = get_screen_size()

        if (screen_width, screen_height) >= (1920, 1080):
            self.resize(700, 580)
        elif (screen_width, screen_height) >= (1280, 720):
            self.resize(620, 520)
        else:
            resize_window_for_screen(self, screen_width, screen_height)
            self.resize(min(self.width(), max(560, screen_width - 80)), min(self.height(), max(460, screen_height - 80)))

        color_start, color_stop = _DETECTION_EMOJI_HEADER_COLORS.get(info.emoji, _DETECTION_DEFAULT_HEADER_COLORS)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        header = QLabel(f'{info.emoji}  {info.title} \u2014 {format_player_display(player.ip, player.usernames)}')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
            'color: #ffffff; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
            f' stop:0 {color_start}, stop:1 {color_stop}); border-radius: 6px;',
        )
        header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        outer_layout.addWidget(header)

        if not info.data_ready:
            warn_label = QLabel('\u26a0\ufe0f  Some data may still be loading and missing from this notification')
            warn_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            warn_label.setWordWrap(True)
            warn_label.setStyleSheet(
                'color: #f6e05e; font-weight: bold; padding: 4px 8px;'
                'background: rgba(214, 158, 46, 20); border: 1px solid rgba(214, 158, 46, 80);'
                'border-radius: 4px;',
            )
            outer_layout.addWidget(warn_label)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer_layout.addWidget(scroll, stretch=1)

        scroll_content = QWidget()
        scroll.setWidget(scroll_content)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(2, 2, 2, 2)
        scroll_layout.setSpacing(10)

        self._build_player_group(scroll_layout, player, info, color_start)
        self._build_connection_group(scroll_layout, player)
        self._build_location_group(scroll_layout, player)
        self._build_network_group(scroll_layout, player)
        self._build_flags_group(scroll_layout, player)
        scroll_layout.addStretch(1)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close, parent=self)
        button_box.rejected.connect(self.reject)
        button_box.accepted.connect(self.accept)
        outer_layout.addWidget(button_box)

    def _build_player_group(self, parent_layout: QVBoxLayout, player: Player, info: PlayerDetectionInfo, accent: str) -> None:
        """Add the 'Player Details' section."""
        group, form = self._make_group('\U0001f464  Player Details', accent=accent)
        self._add_row(form, 'Event', info.description)
        self._add_row(form, 'Event Time', info.event_time)
        self._add_row(form, 'Username(s)', ', '.join(player.usernames) or 'N/A')
        parent_layout.addWidget(group)

    def _build_connection_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Connection Details' section."""
        group, form = self._make_group('\U0001f517  Connection Details', accent='#2b6cb0')
        self._add_row(form, 'IP Address', player.ip)
        self._add_row(form, 'Hostname', _fmt_text(player.reverse_dns.hostname))
        self._add_row(form, 'First Port', str(player.ports.first))
        self._add_row(form, 'Middle Port(s)', ', '.join(map(str, reversed(player.ports.middle))) or 'N/A')
        self._add_row(form, 'Last Port', str(player.ports.last))
        self._add_row(form, 'Total Packets Exchanged', str(player.packets.total_exchanged))
        self._add_row(form, 'Session Packets', str(player.packets.exchanged))
        self._add_row(form, 'Rejoins', str(player.rejoins))
        parent_layout.addWidget(group)

    def _build_location_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Location Details' section."""
        group, form = self._make_group('\U0001f30d  Location Details', accent='#38a169')
        continent = _fmt_text(player.iplookup.ipapi.continent)
        continent_code = _fmt_text(player.iplookup.ipapi.continent_code)
        continent_display = f'{continent} ({continent_code})' if continent != 'N/A' and continent_code != 'N/A' else continent
        country = _fmt_text(player.iplookup.ipapi.country)
        country_code = _fmt_text(player.iplookup.ipapi.country_code)
        country_display = f'{country} ({country_code})' if country != 'N/A' and country_code != 'N/A' else country
        region = _fmt_text(player.iplookup.ipapi.region)
        region_code = _fmt_text(player.iplookup.ipapi.region_code)
        region_display = f'{region} ({region_code})' if region != 'N/A' and region_code != 'N/A' else region
        self._add_row(form, 'Continent', continent_display)
        self._add_row(form, 'Country', country_display)
        self._add_row(form, 'Region', region_display)
        parent_layout.addWidget(group)

    def _build_network_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Network Details' section."""
        group, form = self._make_group('\U0001f310  Network Details', accent='#d69e2e')
        self._add_row(form, 'ISP', _fmt_text(player.iplookup.ipapi.isp))
        self._add_row(form, 'Organization', _fmt_text(player.iplookup.ipapi.org))
        asn = _fmt_text(player.iplookup.ipapi.asn)
        as_name = _fmt_text(player.iplookup.ipapi.as_name)
        asn_display = f'{asn} ({as_name})' if asn != 'N/A' and as_name != 'N/A' else asn
        self._add_row(form, 'ASN', asn_display)
        parent_layout.addWidget(group)

    def _build_flags_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Detection Flags' section."""
        group, form = self._make_group('\U0001f6a9  Detection Flags', accent='#805ad5')
        self._add_row(form, 'Mobile (cellular)', _fmt_bool(player.iplookup.ipapi.mobile))
        self._add_row(form, 'Proxy / VPN / Tor', _fmt_bool(player.iplookup.ipapi.proxy))
        self._add_row(form, 'Hosting / Datacenter', _fmt_bool(player.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)

    @staticmethod
    def _make_group(title: str, *, accent: str) -> tuple[QGroupBox, QFormLayout]:
        """Create a styled group box with an attached QFormLayout and return both."""
        group = QGroupBox(title)
        group.setStyleSheet(
            'QGroupBox {'
            f' border: 1px solid {accent};'
            ' border-radius: 6px;'
            ' margin-top: 14px;'
            ' padding-top: 10px;'
            ' background: rgba(255, 255, 255, 8);'
            ' font-weight: bold;'
            '}'
            'QGroupBox::title {'
            ' subcontrol-origin: margin;'
            ' subcontrol-position: top left;'
            ' left: 10px; padding: 2px 8px;'
            f' background: {accent};'
            ' color: #ffffff;'
            ' border-radius: 4px;'
            '}',
        )
        form = QFormLayout(group)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(5)
        form.setContentsMargins(10, 8, 10, 10)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        return group, form

    @staticmethod
    def _add_row(form: QFormLayout, label_text: str, value: str) -> None:
        """Append a copyable label/value row to *form*."""
        label_widget = QLabel(f'{label_text}:')
        label_widget.setStyleSheet('color: #cbd5e0; font-weight: 600; background: transparent;')

        value_widget = QLabel(value)
        value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        value_widget.setCursor(Qt.CursorShape.IBeamCursor)
        value_widget.setWordWrap(True)
        value_widget.setFont(QFont('Consolas'))
        value_widget.setStyleSheet('color: #ffffff; font-weight: bold; padding: 3px 6px; border-radius: 3px; background: rgba(255, 255, 255, 12);')
        value_widget.setToolTip('Click and drag to select; Ctrl+C to copy.')

        form.addRow(label_widget, value_widget)

    def closeEvent(self, a0: QCloseEvent | None) -> None:  # noqa: N802  # Qt override name
        """Handle the close event."""
        super().closeEvent(a0)


def show_player_detection_dialog(
    parent: QWidget | None,
    player: Player,
    info: PlayerDetectionInfo,
) -> None:
    """Open the Player Detection dialog for *player*."""
    dialog = PlayerDetectionDialog(parent, player, info)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()


def build_discord_player_report(player: Player) -> str:
    """Build a Discord-formatted player info report string."""
    lines: list[str] = []
    lines.append(f'## \U0001f4ca Player Report \u2014 `{player.ip}`')
    lines.append('')

    # Player Info
    lines.append('**\U0001f464 Player Info**')
    lines.append(f'> **IP Address:** `{player.ip}`')
    hostname = _fmt_text(player.reverse_dns.hostname)
    lines.append(f'> **Hostname:** `{hostname}`')
    usernames = ', '.join(player.usernames) if player.usernames else 'N/A'
    lines.append(f'> **Username(s):** {usernames}')
    lines.append(f'> **First Port:** {player.ports.first}  |  **Last Port:** {player.ports.last}')
    middle_ports = ', '.join(map(str, player.ports.middle))
    if middle_ports:
        lines.append(f'> **Middle Port(s):** {middle_ports}')
    db_text = _userip_database_text(player)
    if db_text != 'No':
        lines.append(f'> **UserIP Database:** {db_text}')
    first_seen = player.datetime.first_seen.strftime('%Y-%m-%d %H:%M:%S')
    last_seen = player.datetime.last_seen.strftime('%Y-%m-%d %H:%M:%S')
    lines.append(f'> **First Seen:** {first_seen}  |  **Last Seen:** {last_seen}')
    lines.append('')

    # Location
    country = _fmt_text(player.iplookup.geolite2.country)
    country_code = _fmt_text(player.iplookup.geolite2.country_code)
    continent = _fmt_text(player.iplookup.ipapi.continent)
    region = _fmt_text(player.iplookup.ipapi.region)
    city = _fmt_text(player.iplookup.geolite2.city)
    timezone = _fmt_text(player.iplookup.ipapi.time_zone)
    lines.append('**\U0001f30d Location**')
    country_display = f'{country} ({country_code})' if country != 'N/A' and country_code != 'N/A' else country
    lines.append(f'> **Country:** {country_display}')
    if continent != 'N/A':
        lines.append(f'> **Continent:** {continent}')
    if region != 'N/A':
        lines.append(f'> **Region:** {region}')
    if city != 'N/A':
        lines.append(f'> **City:** {city}')
    if timezone != 'N/A':
        lines.append(f'> **Timezone:** {timezone}')
    lines.append('')

    # Network
    isp = _fmt_text(player.iplookup.ipapi.isp)
    org = _fmt_text(player.iplookup.ipapi.org)
    asn = _fmt_text(player.iplookup.ipapi.asn)
    as_name = _fmt_text(player.iplookup.ipapi.as_name)
    mobile = _fmt_bool(player.iplookup.ipapi.mobile)
    proxy = _fmt_bool(player.iplookup.ipapi.proxy)
    hosting = _fmt_bool(player.iplookup.ipapi.hosting)
    lines.append('**\U0001f310 Network**')
    if isp != 'N/A':
        lines.append(f'> **ISP:** {isp}')
    if org not in {'N/A', isp}:
        lines.append(f'> **Organization:** {org}')
    if asn != 'N/A':
        as_display = f'{asn} ({as_name})' if as_name != 'N/A' else asn
        lines.append(f'> **AS:** {as_display}')
    lines.append(f'> **Mobile:** {mobile}  |  **Proxy/VPN/Tor:** {proxy}  |  **Hosting:** {hosting}')
    lines.append('')

    # Ping
    avg_rtt = _fmt_ms(player.ping.rtt_avg)
    packet_loss = _fmt_loss_pct(player.ping.packet_loss)
    lines.append('**\U0001f4e1 Ping**')
    lines.append(f'> **Avg RTT:** {avg_rtt}  |  **Packet Loss:** {packet_loss}')

    return '\n'.join(lines)


def copy_player_info_for_discord(player: Player) -> None:
    """Copy a Discord-formatted player info report to the system clipboard."""
    clipboard = ensure_instance(app.clipboard(), QClipboard)
    clipboard.setText(build_discord_player_report(player))


def copy_players_info_for_discord(players: list[Player]) -> None:
    """Copy Discord-formatted reports for multiple players, separated by a divider."""
    clipboard = ensure_instance(app.clipboard(), QClipboard)
    separator = '\n\n---\n\n'
    clipboard.setText(separator.join(build_discord_player_report(p) for p in players))


def ping_ip(ip: str) -> None:
    """Run a continuous ping to a specified IP address in a new terminal window."""
    run_cmd_command('ping', [ip, '-t'])


def tcp_port_ping(parent: QWidget, ip: str) -> None:
    """Run paping to check TCP connectivity to a host on a user-specified port indefinitely."""
    port_str, ok = QInputDialog.getText(parent, 'Input Port', 'Enter the port number to check TCP connectivity:')

    if not ok:
        return

    port_str = port_str.strip()

    if not port_str.isdigit():
        QMessageBox.warning(parent, 'Error', 'No valid port number provided.')
        return

    port = int(port_str)

    if not MIN_PORT <= port <= MAX_PORT:
        QMessageBox.warning(parent, 'Error', 'Please enter a valid port number between 1 and 65535.')
        return

    run_cmd_script(PAPING_PATH, [ip, '-p', str(port)])


def tcp_port_ping_multi(parent: QWidget, ips: list[str]) -> None:
    """Ask for a port once, then run paping for each IP on that same port."""
    port_str, ok = QInputDialog.getText(parent, 'Input Port', 'Enter the port number to check TCP connectivity:')

    if not ok:
        return

    port_str = port_str.strip()

    if not port_str.isdigit():
        QMessageBox.warning(parent, 'Error', 'No valid port number provided.')
        return

    port = int(port_str)

    if not MIN_PORT <= port <= MAX_PORT:
        QMessageBox.warning(parent, 'Error', 'Please enter a valid port number between 1 and 65535.')
        return

    for ip in ips:
        run_cmd_script(PAPING_PATH, [ip, '-p', str(port)])


def block_ip_as_range(parent: QWidget, ip_address: str) -> str | None:
    """Open the IP Range Builder dialog pre-filled with *ip_address* and add the result to the blocked IPs setting.

    Returns the raw range string that was added, or `None` if the user cancelled or the entry already exists.
    """
    dialog = IPRangeBuilderDialog(parent, initial_ip=ip_address)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None

    entry = dialog.result_entry()
    if not entry:
        return None

    if entry not in Settings.capture_blocked_ips:
        Settings.capture_blocked_ips = (*Settings.capture_blocked_ips, entry)
        Settings.rewrite_settings_file()
        Settings.rebuild_blocked_ip_ranges()

    return entry
