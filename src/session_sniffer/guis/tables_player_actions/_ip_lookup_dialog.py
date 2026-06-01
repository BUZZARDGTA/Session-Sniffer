"""IPLookupDetailsDialog and show_detailed_ip_lookup helper."""

from typing import TYPE_CHECKING, override

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QFormLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import PLAYER_INFO_FORM_LABEL_STYLESHEET
from session_sniffer.guis.tables_player_actions._fmt import (
    fmt_bool,
    fmt_packets_and_stats,
    fmt_ping_status,
    fmt_ping_times,
    fmt_rtt_summary,
    fmt_text,
    userip_database_text,
)
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import format_player_display, get_screen_size, resize_window_for_screen, set_dialog_window_flags

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtGui import QCloseEvent

    from session_sniffer.models.player import Player


class IPLookupDetailsDialog(PlayerInfoDialogMixin):
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

        screen_size = get_screen_size()

        if screen_size >= (1920, 1080):
            self.resize(820, 720)
        elif screen_size >= (1280, 720):
            self.resize(720, 640)
        else:
            resize_window_for_screen(self, screen_size)
            self.resize(min(self.width(), max(560, screen_size[0] - 80)), min(self.height(), max(460, screen_size[1] - 80)))

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._header_label = self._add_header_label(
            outer_layout,
            f'\U0001f50e  IP Lookup Details \u2014 {format_player_display(player.ip, player.usernames)}',
            '#2b6cb0',
            '#4c51bf',
        )

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_player_info_group(scroll_layout)
        self._build_iplookup_group(scroll_layout)
        self._build_ping_group(scroll_layout)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

        self._timer = QTimer(self)
        self._timer.setInterval(self._REFRESH_INTERVAL_MS)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

        self._refresh()

    def _build_player_info_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'Player Info' section to the scroll layout."""
        group, form = self._make_group('\U0001f464  Player Info', accent='#2b6cb0')
        self._add_live_row(form, 'IP Address', lambda p: p.ip)
        self._add_live_row(form, 'Hostname', lambda p: fmt_text(p.reverse_dns.hostname))
        self._add_live_row(form, 'Usernames', lambda p: ', '.join(p.usernames) or 'N/A')
        self._add_live_row(form, 'In UserIP database', userip_database_text)
        self._add_live_row(form, 'First Port', lambda p: str(p.ports.first))
        self._add_live_row(form, 'Middle Port(s)', lambda p: ', '.join(map(str, p.ports.middle)) or '')
        self._add_live_row(form, 'Last Port', lambda p: str(p.ports.last))
        parent_layout.addWidget(group)

    def _build_iplookup_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'IP Lookup Details' section to the scroll layout."""
        group, form = self._make_group('\U0001f30d  IP Lookup Details', accent='#38a169')
        self._add_live_row(form, 'Continent', lambda p: fmt_text(p.iplookup.ipapi.continent))
        self._add_live_row(form, 'Continent Code', lambda p: fmt_text(p.iplookup.ipapi.continent_code))
        self._add_live_row(form, 'Country', lambda p: fmt_text(p.iplookup.geolite2.country))
        self._add_live_row(form, 'Country Code', lambda p: fmt_text(p.iplookup.geolite2.country_code))
        self._add_live_row(form, 'Region', lambda p: fmt_text(p.iplookup.ipapi.region))
        self._add_live_row(form, 'Region Code', lambda p: fmt_text(p.iplookup.ipapi.region_code))
        self._add_live_row(form, 'City', lambda p: fmt_text(p.iplookup.geolite2.city))
        self._add_live_row(form, 'District', lambda p: fmt_text(p.iplookup.ipapi.district))
        self._add_live_row(form, 'ZIP Code', lambda p: fmt_text(p.iplookup.ipapi.zip_code))
        self._add_live_row(form, 'Latitude', lambda p: fmt_text(p.iplookup.ipapi.lat))
        self._add_live_row(form, 'Longitude', lambda p: fmt_text(p.iplookup.ipapi.lon))
        self._add_live_row(form, 'Time Zone', lambda p: fmt_text(p.iplookup.ipapi.time_zone))
        self._add_live_row(form, 'UTC Offset', lambda p: fmt_text(p.iplookup.ipapi.offset))
        self._add_live_row(form, 'Currency', lambda p: fmt_text(p.iplookup.ipapi.currency))
        self._add_live_row(form, 'Organization', lambda p: fmt_text(p.iplookup.ipapi.org))
        self._add_live_row(form, 'ISP', lambda p: fmt_text(p.iplookup.ipapi.isp))
        self._add_live_row(form, 'GeoLite2 ASN / ISP', lambda p: fmt_text(p.iplookup.geolite2.asn))
        self._add_live_row(form, 'AS Number', lambda p: fmt_text(p.iplookup.ipapi.asn))
        self._add_live_row(form, 'AS Name', lambda p: fmt_text(p.iplookup.ipapi.as_name))
        self._add_live_row(form, 'Mobile (cellular)', lambda p: fmt_bool(p.iplookup.ipapi.mobile))
        self._add_live_row(form, 'Proxy / VPN / Tor', lambda p: fmt_bool(p.iplookup.ipapi.proxy))
        self._add_live_row(form, 'Hosting / Datacenter', lambda p: fmt_bool(p.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)

    def _build_ping_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'Ping Response' section to the scroll layout, with cleaner formatting."""
        group, form = self._make_group('\U0001f4e1  Ping Response', accent='#d69e2e')
        self._add_live_row(form, 'Status', lambda p: fmt_ping_status(p.ping.is_pinging))
        self._add_live_row(form, 'Packets', lambda p: fmt_packets_and_stats(
            p.ping.packets_transmitted, p.ping.packets_received,
            p.ping.packet_loss, p.ping.packet_errors, p.ping.packet_duplicates,
        ))
        self._add_live_row(form, 'RTT Min/Avg/Max', lambda p: fmt_rtt_summary(p.ping.rtt_min, p.ping.rtt_avg, p.ping.rtt_max, p.ping.rtt_mdev))
        self._add_live_row(form, 'Per-Packet RTT', lambda p: fmt_ping_times(p.ping.ping_times))
        parent_layout.addWidget(group)

    def _add_live_row(self, form: QFormLayout, label_text: str, provider: Callable[[Player], str]) -> None:
        """Append a label / copyable-value row to *form* and register it for refresh."""
        label_widget = QLabel(f'{label_text}:')
        label_widget.setStyleSheet(PLAYER_INFO_FORM_LABEL_STYLESHEET)
        value_widget = self._make_value_label()
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

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Stop the refresh timer when the dialog is closed."""
        self._timer.stop()
        super().closeEvent(a0)


def show_detailed_ip_lookup(parent: QWidget, player: Player) -> None:
    """Open the brand-new live IP Lookup Details dialog for *player*."""
    dialog = IPLookupDetailsDialog(parent, player)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
