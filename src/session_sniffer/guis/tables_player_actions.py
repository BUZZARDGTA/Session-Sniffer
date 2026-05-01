"""Player action helpers for session table context menus (info dialogs, ping)."""

from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QCloseEvent, QFont
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
from session_sniffer.guis.utils import get_screen_size, resize_window_for_screen
from session_sniffer.player.seen_stats import SEEN_STATS_LABELS, analyze_sessions_logging
from session_sniffer.text_utils import format_triple_quoted_text
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
    """Format a millisecond RTT value with two decimals."""
    if _is_unset(value):
        return 'N/A'
    if isinstance(value, (int, float)):
        return f'{value:.2f} ms'
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


def _fmt_packet_summary(transmitted: object, received: object, loss: object) -> str:
    """Format a 'sent / received (loss%)' summary line."""
    if _is_unset(transmitted) and _is_unset(received) and _is_unset(loss):
        return 'N/A'
    return f'{_fmt_int(transmitted)} sent · {_fmt_int(received)} received · {_fmt_loss_pct(loss)} loss'


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
    formatted = ', '.join(f'{t:.2f}' for t in samples if isinstance(t, (int, float)))
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


class IPLookupDetailsDialog(QDialog):
    """A non-modal dialog showing live, copyable IP lookup details for a player.

    The dialog refreshes its values periodically so reverse-DNS, IP-API,
    GeoLite2 and ping data appear as they are resolved.
    """

    _REFRESH_INTERVAL_MS = 500

    def __init__(self, parent: QWidget, player: Player) -> None:
        """Build the dialog, install the periodic refresh timer, and show initial values."""
        super().__init__(parent)
        self._player = player
        self._rows: list[tuple[QLabel, Callable[[Player], str]]] = []

        self.setWindowTitle(f'{TITLE} - IP Lookup Details ({player.ip})')
        self.setMinimumSize(560, 460)

        try:
            screen_width, screen_height = get_screen_size()
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            screen_width, screen_height = 800, 600

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

        header = QLabel(f'\U0001f50e  IP Lookup Details \u2014 {player.ip}')
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(
            'font-size: 14pt; font-weight: bold; padding: 8px 6px;'
            'color: #ffffff; background: qlineargradient(x1:0, y1:0, x2:1, y2:0,'
            ' stop:0 #2b6cb0, stop:1 #4c51bf); border-radius: 6px;',
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
        self._add_row(form, 'Packets', lambda p: _fmt_packet_summary(p.ping.packets_transmitted, p.ping.packets_received, p.ping.packet_loss))
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
        for value_widget, provider in self._rows:
            try:
                text = provider(player)
            except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
                text = 'N/A'
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
    """Show historical encounter statistics for the given player IP."""
    stats = analyze_sessions_logging(SESSIONS_LOGGING_DIR_PATH, player.ip)
    lines = '\n'.join(f'{label}: {getattr(stats, key)}' for key, label in SEEN_STATS_LABELS.items())
    QMessageBox.information(parent, TITLE, format_triple_quoted_text(f"""
        ########## Seen Stats ##########
        IP Address: {player.ip}

        {lines}
    """))


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
