"""IPLookupDetailsDialog and show_detailed_ip_lookup helper."""

import dataclasses
import time
from dataclasses import dataclass
from threading import Thread
from typing import TYPE_CHECKING, override

import dns.exception
import requests
from pydantic import ValidationError
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import PLAYER_INFO_FORM_LABEL_STYLESHEET
from session_sniffer.guis.tables_player_actions._actions import ping_ip, tcp_port_ping
from session_sniffer.guis.tables_player_actions._format import (
    format_bool,
    format_packets_and_stats,
    format_ping_status,
    format_ping_times,
    format_rtt_summary,
    format_text,
    format_userip_database,
)
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import format_player_display, get_screen_size, resize_window_for_screen, scale_by_ui, set_dialog_window_flags
from session_sniffer.models import IpApiResponse
from session_sniffer.models.player_lookup import (
    PlayerIPLookup,
    PlayerPing,
    PlayerReverseDNS,
)
from session_sniffer.networking.exceptions import AllEndpointsExhaustedError
from session_sniffer.networking.geolite2 import (
    query_geolite2_asn,
    query_geolite2_city,
    query_geolite2_country,
)
from session_sniffer.networking.http_session import session
from session_sniffer.networking.ping import ping_player
from session_sniffer.networking.reverse_dns import reverse_dns_lookup
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIP, UserIPDatabases

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QCloseEvent

    from session_sniffer.models.player import Player


@dataclass(slots=True)
class _StandalonePorts:
    """Placeholder port information for standalone IP lookups."""

    first: str = 'N/A'
    middle: list[str] = dataclasses.field(default_factory=list[str])
    last: str = 'N/A'


@dataclass(slots=True)
class StandaloneIPLookup:
    """Holds lookup information for an IP address without requiring a Player session."""

    ip: str
    usernames: list[str] = dataclasses.field(default_factory=list[str])
    reverse_dns: PlayerReverseDNS = dataclasses.field(default_factory=PlayerReverseDNS)
    iplookup: PlayerIPLookup = dataclasses.field(default_factory=PlayerIPLookup)
    ping: PlayerPing = dataclasses.field(default_factory=PlayerPing)
    ports: _StandalonePorts = dataclasses.field(default_factory=_StandalonePorts)
    userip: UserIP | None = None
    userip_detection: object = None


type IPLookupTarget = Player | StandaloneIPLookup


_IPAPI_FIELDS = (
    'status,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query'
)


def _resolve_standalone_lookup(lookup: StandaloneIPLookup) -> None:
    """Background worker to resolve Reverse DNS, GeoLite2, IP-API, and Ping for a standalone IP."""
    # 1. UserIP resolution
    if not lookup.usernames:
        resolved_userip = UserIPDatabases.resolve_userip(lookup.ip)
        if resolved_userip is not None:
            lookup.userip = resolved_userip
            for username in resolved_userip.usernames:
                if username not in lookup.usernames:
                    lookup.usernames.append(username)

    # 2. Reverse DNS
    if not lookup.reverse_dns.is_initialized:
        try:
            lookup.reverse_dns.hostname = reverse_dns_lookup(lookup.ip)
        except (dns.exception.DNSException, OSError):
            lookup.reverse_dns.hostname = 'N/A'
        lookup.reverse_dns.is_initialized = True

    # 3. GeoLite2
    if not lookup.iplookup.geolite2.is_initialized:
        country_name, country_code = query_geolite2_country(lookup.ip)
        lookup.iplookup.geolite2.country = country_name
        lookup.iplookup.geolite2.country_code = country_code
        lookup.iplookup.geolite2.city = query_geolite2_city(lookup.ip)
        lookup.iplookup.geolite2.asn = query_geolite2_asn(lookup.ip)
        lookup.iplookup.geolite2.is_initialized = True

    # 4. IP-API single query
    if not lookup.iplookup.ipapi.is_initialized:
        try:
            response = session.get(
                f'http://ip-api.com/json/{lookup.ip}',
                params={'fields': _IPAPI_FIELDS},
                timeout=3,
            )
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                parsed = IpApiResponse.model_validate(data)
                lookup.iplookup.ipapi.update_fields(parsed.model_dump(exclude={'status', 'query'}))
                lookup.iplookup.ipapi.is_initialized = True
        except (requests.exceptions.RequestException, ValidationError):
            lookup.iplookup.ipapi.is_initialized = True

    # 5. Ping
    if not lookup.ping.is_initialized:
        try:
            ping_result = ping_player(lookup.ip)
            lookup.ping.update_fields(ping_result._asdict())
            lookup.ping.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
            lookup.ping.is_initialized = True
        except (AllEndpointsExhaustedError, requests.exceptions.RequestException, OSError):
            lookup.ping.is_pinging = False
            lookup.ping.is_initialized = True


def _start_standalone_lookup(lookup: StandaloneIPLookup) -> None:
    """Launch background resolution thread for a standalone IP lookup."""
    thread = Thread(target=_resolve_standalone_lookup, args=(lookup,), daemon=True)
    thread.start()


class IPLookupDetailsDialog(PlayerInfoDialogMixin):
    """A non-modal dialog showing live, copyable IP lookup details for a player or IP address.

    The dialog refreshes its values periodically so reverse-DNS, IP-API,
    GeoLite2 and ping data appear as they are resolved.
    """

    _REFRESH_INTERVAL_MS = 500

    def __init__(self, parent: QWidget, target: IPLookupTarget) -> None:
        """Build the dialog, install the periodic refresh timer, and show initial values."""
        super().__init__(parent)
        set_dialog_window_flags(self)
        self._target: IPLookupTarget = target
        self._rows: list[tuple[QLabel, Callable[[IPLookupTarget], str]]] = []
        self._is_closed = False

        self.setWindowTitle(f'{TITLE} - IP Lookup Details ({format_player_display(self._target.ip, self._target.usernames)})')
        self.setMinimumSize(scale_by_ui(560), scale_by_ui(420))

        screen_size = get_screen_size()

        if screen_size >= (1920, 1080):
            self.resize(scale_by_ui(820), scale_by_ui(680))
        elif screen_size >= (1280, 720):
            self.resize(scale_by_ui(720), scale_by_ui(600))
        else:
            resize_window_for_screen(self, screen_size)
            self.resize(min(self.width(), max(scale_by_ui(560), screen_size[0] - 80)), min(self.height(), max(scale_by_ui(420), screen_size[1] - 80)))

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._header_label = self._add_header_label(
            outer_layout,
            f'🔎  IP Lookup Details — {format_player_display(self._target.ip, self._target.usernames)}',
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

        self._ping_thread = Thread(target=self._live_ping_loop, daemon=True)
        self._ping_thread.start()

        self._refresh()

    def _live_ping_loop(self) -> None:
        """Continuously perform background pings to update ping stats live while dialog is open."""
        while not self._is_closed:
            try:
                ping_result = ping_player(self._target.ip)
                self._target.ping.update_fields(ping_result._asdict())
                self._target.ping.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
                self._target.ping.is_initialized = True
            except (AllEndpointsExhaustedError, requests.exceptions.RequestException, OSError):
                if not self._target.ping.is_initialized:
                    self._target.ping.is_pinging = False
                    self._target.ping.is_initialized = True

            # Cooldown between ping checks (interruptible upon dialog close)
            for _ in range(30):
                if self._is_closed:
                    return
                time.sleep(0.1)

    def _build_player_info_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'Player Info' section to the scroll layout."""
        group, form = self._make_group('👤  Player Info', accent='#2b6cb0')
        self._add_live_row(form, 'IP Address', lambda target: target.ip)
        self._add_live_row(form, 'Hostname', lambda target: format_text(target.reverse_dns.hostname))
        self._add_live_row(form, 'Usernames', lambda target: ', '.join(target.usernames) or 'N/A')
        self._add_live_row(form, 'In UserIP database', lambda target: format_userip_database(target.userip))
        self._add_live_row(form, 'First Port', lambda target: str(target.ports.first))
        self._add_live_row(form, 'Middle Port(s)', lambda target: ', '.join(map(str, target.ports.middle)) or '')
        self._add_live_row(form, 'Last Port', lambda target: str(target.ports.last))
        parent_layout.addWidget(group)

    def _build_iplookup_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'IP Lookup Details' section to the scroll layout."""
        group, form = self._make_group('🌍  IP Lookup Details', accent='#38a169')
        self._add_live_row(form, 'Continent', lambda target: format_text(target.iplookup.ipapi.continent))
        self._add_live_row(form, 'Continent Code', lambda target: format_text(target.iplookup.ipapi.continent_code))
        self._add_live_row(form, 'Country', lambda target: format_text(target.iplookup.geolite2.country))
        self._add_live_row(form, 'Country Code', lambda target: format_text(target.iplookup.geolite2.country_code))
        self._add_live_row(form, 'Region', lambda target: format_text(target.iplookup.ipapi.region))
        self._add_live_row(form, 'Region Code', lambda target: format_text(target.iplookup.ipapi.region_code))
        self._add_live_row(form, 'City', lambda target: format_text(target.iplookup.geolite2.city))
        self._add_live_row(form, 'District', lambda target: format_text(target.iplookup.ipapi.district))
        self._add_live_row(form, 'ZIP Code', lambda target: format_text(target.iplookup.ipapi.zip_code))
        self._add_live_row(form, 'Latitude', lambda target: format_text(target.iplookup.ipapi.lat))
        self._add_live_row(form, 'Longitude', lambda target: format_text(target.iplookup.ipapi.lon))
        self._add_live_row(form, 'Time Zone', lambda target: format_text(target.iplookup.ipapi.time_zone))
        self._add_live_row(form, 'UTC Offset', lambda target: format_text(target.iplookup.ipapi.offset))
        self._add_live_row(form, 'Currency', lambda target: format_text(target.iplookup.ipapi.currency))
        self._add_live_row(form, 'Organization', lambda target: format_text(target.iplookup.ipapi.org))
        self._add_live_row(form, 'ISP', lambda target: format_text(target.iplookup.ipapi.isp))
        self._add_live_row(form, 'GeoLite2 ASN / ISP', lambda target: format_text(target.iplookup.geolite2.asn))
        self._add_live_row(form, 'AS Number', lambda target: format_text(target.iplookup.ipapi.asn))
        self._add_live_row(form, 'AS Name', lambda target: format_text(target.iplookup.ipapi.as_name))
        self._add_live_row(form, 'Mobile (cellular)', lambda target: format_bool(target.iplookup.ipapi.mobile))
        self._add_live_row(form, 'Proxy / VPN / Tor', lambda target: format_bool(target.iplookup.ipapi.proxy))
        self._add_live_row(form, 'Hosting / Datacenter', lambda target: format_bool(target.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)

    def _build_ping_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'Ping Response' section to the scroll layout, with cleaner formatting."""
        group, form = self._make_group('📡  Ping Response', accent='#d69e2e')
        self._add_live_row(form, 'Status', lambda target: format_ping_status(target.ping.is_pinging))
        self._add_live_row(
            form,
            'Packets',
            lambda target: format_packets_and_stats(
                target.ping.packets_transmitted,
                target.ping.packets_received,
                target.ping.packet_loss,
                target.ping.packet_errors,
                target.ping.packet_duplicates,
            ),
        )
        self._add_live_row(form, 'RTT Min/Avg/Max', lambda target: format_rtt_summary(target.ping.rtt_min, target.ping.rtt_avg, target.ping.rtt_max, target.ping.rtt_mdev))
        self._add_live_row(form, 'Per-Packet RTT', lambda target: format_ping_times(target.ping.ping_times))

        buttons_layout = QHBoxLayout()
        buttons_layout.setContentsMargins(0, 6, 0, 0)
        buttons_layout.setSpacing(10)

        icmp_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'play.svg')), ' ICMP Ping')
        icmp_button.setToolTip('Launch continuous ICMP ping diagnostics window for this IP.')
        icmp_button.clicked.connect(lambda: ping_ip(self._target.ip))
        buttons_layout.addWidget(icmp_button)

        tcp_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'settings.svg')), ' TCP Port Ping…')
        tcp_button.setToolTip('Launch TCP port ping diagnostics window for this IP.')
        tcp_button.clicked.connect(lambda: tcp_port_ping(self, self._target.ip))
        buttons_layout.addWidget(tcp_button)

        form.addRow('', buttons_layout)
        parent_layout.addWidget(group)

    def _add_live_row(self, form: QFormLayout, label_text: str, provider: Callable[[IPLookupTarget], str]) -> None:
        """Append a label / copyable-value row to *form* and register it for refresh."""
        label_widget = QLabel(f'{label_text}:')
        label_widget.setStyleSheet(PLAYER_INFO_FORM_LABEL_STYLESHEET)
        value_widget = self._make_value_label()
        form.addRow(label_widget, value_widget)
        self._rows.append((value_widget, provider))

    def _refresh(self) -> None:
        """Re-evaluate every row provider and update the value widget text."""
        display = format_player_display(self._target.ip, self._target.usernames)
        new_title = f'{TITLE} - IP Lookup Details ({display})'
        if self.windowTitle() != new_title:
            self.setWindowTitle(new_title)
            self._header_label.setText(f'🔎  IP Lookup Details — {display}')
        for value_widget, provider in self._rows:
            text = provider(self._target)
            if value_widget.text() != text:
                value_widget.setText(text)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop the refresh timer and live ping worker when the dialog is closed."""
        self._is_closed = True
        self._timer.stop()
        super().closeEvent(event)


def show_detailed_ip_lookup(parent: QWidget, target: Player | StandaloneIPLookup | str) -> None:
    """Open the live IP Lookup Details dialog for a player or IP address."""
    if isinstance(target, str):
        matched_player = PlayersRegistry.get_player_by_ip(target)
        if matched_player is not None:
            dialog = IPLookupDetailsDialog(parent, matched_player)
        else:
            standalone_lookup = StandaloneIPLookup(ip=target)
            _start_standalone_lookup(standalone_lookup)
            dialog = IPLookupDetailsDialog(parent, standalone_lookup)
    else:
        dialog = IPLookupDetailsDialog(parent, target)

    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
