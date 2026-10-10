"""IPLookupDetailsDialog and show_detailed_ip_lookup helper."""

import dataclasses
import logging
import time
from dataclasses import dataclass
from http import HTTPStatus
from threading import Event, Thread
from typing import TYPE_CHECKING, override

import requests
from pydantic import ValidationError
from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.constants.local import RESOURCES_DIR_PATH
from session_sniffer.constants.standalone import LOOKY_BASE_HOST, TITLE
from session_sniffer.guis.looky_text import configure_looky_action, is_looky_gta5_restricted
from session_sniffer.guis.stylesheets import PLAYER_INFO_FORM_LABEL_STYLESHEET
from session_sniffer.guis.tables_player_actions._actions import ping_ip, tcp_port_ping, web_ping
from session_sniffer.guis.tables_player_actions._format import (
    format_bool,
    format_looky_last_seens,
    format_looky_rockstarids,
    format_looky_usernames,
    format_packets_and_stats,
    format_ping_status,
    format_ping_times,
    format_rtt_summary,
    format_text,
    format_userip_database,
)
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.tables_player_actions.looky_system._looky_lookup_dialog import show_looky_lookup
from session_sniffer.guis.utils import (
    ActiveDialogRegistry,
    apply_adaptive_window_size,
    format_player_display,
    set_dialog_window_flags,
)
from session_sniffer.models import IpApiResponse
from session_sniffer.models.player_lookup import (
    PlayerIPLookup,
    PlayerLooky,
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
from session_sniffer.networking.looky_system import get_looky_user_url, lookup_ip
from session_sniffer.networking.ping import ping_player
from session_sniffer.networking.reverse_dns import reverse_dns_lookup
from session_sniffer.player.registry import PlayersRegistry
from session_sniffer.player.userip import UserIP, UserIPDatabases
from session_sniffer.settings.settings import Settings
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QCloseEvent

    from session_sniffer.models.looky_system import LookyPlayer
    from session_sniffer.models.player import Player

logger = logging.getLogger(__name__)


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
    looky_system: PlayerLooky = dataclasses.field(default_factory=PlayerLooky)
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
        except OSError:
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
        except (requests.exceptions.RequestException, ValidationError) as e:
            logger.warning('IP-API lookup failed: %s', e)
            lookup.iplookup.ipapi.is_initialized = True

    # 5. Ping
    if not lookup.ping.is_initialized:
        try:
            ping_result = ping_player(lookup.ip)
            lookup.ping.update_fields(ping_result._asdict())
            lookup.ping.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
            lookup.ping.is_initialized = True
        except (AllEndpointsExhaustedError, requests.exceptions.RequestException, OSError) as e:
            logger.debug('Ping failed: %s', e)
            lookup.ping.is_pinging = False
            lookup.ping.is_initialized = True

    # 6. Looky System
    api_key = Settings.looky_api_key or ''
    if bool(api_key) and not lookup.looky_system.is_initialized and Settings.looky_enabled and Settings.is_gta5_feature_set() and not is_looky_gta5_restricted():
        try:
            looky_players = lookup_ip(lookup.ip, api_key, Settings.looky_game_version.lower())
            unique_results: list[LookyPlayer] = []
            seen_pairs: set[tuple[str, int]] = set()
            for entry in looky_players:
                pair = (entry.name, entry.rockstarid)
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    unique_results.append(entry)
            with lookup.looky_system.lock:
                lookup.looky_system.usernames = [entry.name for entry in unique_results]
                lookup.looky_system.rockstarids = [entry.rockstarid for entry in unique_results]
                lookup.looky_system.last_seens = [entry.last_seen for entry in unique_results]
                lookup.looky_system.needs_refresh = False
                lookup.looky_system.last_fetched_at = time.monotonic()
                lookup.looky_system.is_initialized = True
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == HTTPStatus.NOT_FOUND:
                with lookup.looky_system.lock:
                    lookup.looky_system.needs_refresh = False
                    lookup.looky_system.last_fetched_at = time.monotonic()
                    lookup.looky_system.is_initialized = True
            else:
                logger.debug('Looky lookup HTTP error for standalone IP %s: %s', lookup.ip, e)
                with lookup.looky_system.lock:
                    lookup.looky_system.is_initialized = True
        except (requests.exceptions.RequestException, ValidationError) as e:
            logger.debug('Looky lookup failed for standalone IP %s: %s', lookup.ip, e)
            with lookup.looky_system.lock:
                lookup.looky_system.is_initialized = True


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

    def __init__(self, parent: QWidget | None, target: IPLookupTarget) -> None:
        """Build the dialog, install the periodic refresh timer, and show initial values."""
        super().__init__(parent)
        set_dialog_window_flags(self)
        self._target: IPLookupTarget = target
        self._rows: list[tuple[QLabel, Callable[[IPLookupTarget], str], QLabel, Callable[[IPLookupTarget], str] | None]] = []
        self._closed_event = Event()

        self.setWindowTitle(f'{TITLE} - IP Lookup Details ({format_player_display(self._target.ip, self._target.usernames)})')
        apply_adaptive_window_size(self, min_size=(560, 420), size_1080p=(820, 680), size_720p=(720, 600))

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._header_label = self._add_header_label(
            outer_layout,
            f'IP Lookup Details — {format_player_display(self._target.ip, self._target.usernames)}',
            '#2b6cb0',
            '#4c51bf',
        )

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_player_info_group(scroll_layout)
        self._build_looky_group(scroll_layout)
        self._build_iplookup_group(scroll_layout)
        self._build_ping_group(scroll_layout)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

        self._timer = self._init_refresh_timer(self._REFRESH_INTERVAL_MS, self._refresh)

        self._ping_thread = Thread(target=self._live_ping_loop, daemon=True)
        self._ping_thread.start()

        self._refresh()

    def _live_ping_loop(self) -> None:
        """Continuously perform background pings to update ping stats live while dialog is open."""
        while not self._closed_event.is_set():
            try:
                ping_result = ping_player(self._target.ip)
                self._target.ping.update_fields(ping_result._asdict())
                self._target.ping.is_pinging = ping_result.packets_received is not None and ping_result.packets_received > 0
                self._target.ping.is_initialized = True
            except (AllEndpointsExhaustedError, requests.exceptions.RequestException, OSError) as e:
                logger.debug('Continuous ping failed: %s', e)
                if not self._target.ping.is_initialized:
                    self._target.ping.is_pinging = False
                    self._target.ping.is_initialized = True

            # Cooldown between ping checks (interruptible upon dialog close)
            for _ in range(30):
                if self._closed_event.is_set():
                    return
                time.sleep(0.1)

    def _build_player_info_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'Player Info' section to the scroll layout."""
        group, form = self._make_group('Player Info', accent='#2b6cb0')
        self._add_live_row(form, 'IP Address', lambda target: target.ip)
        self._add_live_row(form, 'Hostname', lambda target: format_text(target.reverse_dns.hostname))
        self._add_live_row(form, lambda target: f'Username{pluralize(len(target.usernames))}', lambda target: ', '.join(target.usernames) or 'N/A')
        self._add_live_row(form, 'In UserIP database', lambda target: format_userip_database(target.userip))
        self._add_live_row(form, 'First Port', lambda target: str(target.ports.first))
        self._add_live_row(
            form,
            lambda target: f'Middle Port{pluralize(len(target.ports.middle))}',
            lambda target: ', '.join(map(str, reversed(target.ports.middle))) or '',
        )
        self._add_live_row(form, 'Last Port', lambda target: str(target.ports.last))
        parent_layout.addWidget(group)

    def _build_looky_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'Looky System' section to the scroll layout."""
        group, form = self._make_group('Looky System', accent='#4c1d95')

        def _looky_usernames_label(target: IPLookupTarget) -> str:
            with target.looky_system.lock:
                return f'Username{pluralize(len(target.looky_system.usernames))}'

        def _looky_rockstarids_label(target: IPLookupTarget) -> str:
            with target.looky_system.lock:
                return f'Rockstar ID{pluralize(len(target.looky_system.rockstarids))}'

        self._add_live_row(form, _looky_usernames_label, lambda target: format_looky_usernames(target.looky_system))
        self._add_live_row(form, _looky_rockstarids_label, lambda target: format_looky_rockstarids(target.looky_system))
        self._add_live_row(form, 'Last Seen', lambda target: format_looky_last_seens(target.looky_system))

        buttons_layout = QHBoxLayout()
        buttons_layout.setContentsMargins(0, 6, 0, 0)
        buttons_layout.setSpacing(10)

        lookup_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'search.svg')), ' Looky Lookup…')
        lookup_button.clicked.connect(lambda: show_looky_lookup(self, self._target))
        configure_looky_action(
            lookup_button,
            default_tooltip='Query the Looky System API to view full player details for this IP.',
            check_gta5_restriction=isinstance(self._target, StandaloneIPLookup) or not getattr(self._target, 'is_gta5_process', False),
        )
        buttons_layout.addWidget(lookup_button)

        website_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'website.svg')), ' Looky Website')
        website_button.setToolTip('Open the Looky System website in your default browser.')

        def _on_website_clicked() -> None:
            with self._target.looky_system.lock:
                rids = list(self._target.looky_system.rockstarids)
            if len(rids) == 1:
                QDesktopServices.openUrl(QUrl(get_looky_user_url(rids[0])))
            else:
                QDesktopServices.openUrl(QUrl(LOOKY_BASE_HOST))

        website_button.clicked.connect(_on_website_clicked)
        buttons_layout.addWidget(website_button)

        form.addRow('', buttons_layout)
        parent_layout.addWidget(group)

    def _build_iplookup_group(self, parent_layout: QVBoxLayout) -> None:
        """Add the 'IP Lookup Details' section to the scroll layout."""
        group, form = self._make_group('IP Lookup Details', accent='#38a169')
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
        group, form = self._make_group('Ping Response', accent='#d69e2e')
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

        icmp_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), ' ICMP Ping')
        icmp_button.setToolTip('Launch continuous ICMP ping diagnostics window for this IP.')
        icmp_button.clicked.connect(lambda: ping_ip(self._target.ip))
        buttons_layout.addWidget(icmp_button)

        tcp_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), ' TCP Port Ping…')
        tcp_button.setToolTip('Launch TCP port ping diagnostics window for this IP.')
        tcp_button.clicked.connect(lambda: tcp_port_ping(self, self._target.ip))
        buttons_layout.addWidget(tcp_button)

        web_button = QPushButton(QIcon(str(RESOURCES_DIR_PATH / 'icons' / 'ping.svg')), ' Web (Check-Host)…')
        web_button.setToolTip('Launch multi-vantage Check-Host.net ping diagnostics window for this IP.')
        web_button.clicked.connect(lambda: web_ping(self._target.ip))
        buttons_layout.addWidget(web_button)

        form.addRow('', buttons_layout)
        parent_layout.addWidget(group)

    def _add_live_row(
        self,
        form: QFormLayout,
        label: str | Callable[[IPLookupTarget], str],
        provider: Callable[[IPLookupTarget], str],
    ) -> None:
        """Append a label / copyable-value row to *form* and register it for refresh."""
        if isinstance(label, str):
            initial_label = label
            label_provider = None
        else:
            initial_label = label(self._target)
            label_provider = label
        label_widget = QLabel(f'{initial_label}:')
        label_widget.setStyleSheet(PLAYER_INFO_FORM_LABEL_STYLESHEET)
        value_widget = self._make_value_label()
        form.addRow(label_widget, value_widget)
        self._rows.append((value_widget, provider, label_widget, label_provider))

    def _refresh(self) -> None:
        """Re-evaluate every row provider and update the value widget text."""
        if not isValid(self):
            return
        display = format_player_display(self._target.ip, self._target.usernames)
        new_title = f'{TITLE} - IP Lookup Details ({display})'
        if self.windowTitle() != new_title:
            self.setWindowTitle(new_title)
            self._header_label.setText(f'IP Lookup Details — {display}')
        for value_widget, provider, label_widget, label_provider in self._rows:
            text = provider(self._target)
            if value_widget.text() != text:
                value_widget.setText(text)
            if label_provider is not None:
                new_label = f'{label_provider(self._target)}:'
                if label_widget.text() != new_label:
                    label_widget.setText(new_label)

    @override
    def done(self, r: int) -> None:
        """Stop the refresh timer and live ping worker when the dialog is finalized."""
        self._closed_event.set()
        self._timer.stop()
        super().done(r)

    @override
    def reject(self) -> None:
        """Stop the refresh timer and live ping worker and reject the dialog."""
        self._closed_event.set()
        self._timer.stop()
        super().reject()

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop the refresh timer and live ping worker when the dialog is closed."""
        self._closed_event.set()
        self._timer.stop()
        super().closeEvent(event)


_active_dialogs: ActiveDialogRegistry[str, IPLookupDetailsDialog] = ActiveDialogRegistry()


def show_detailed_ip_lookup(_parent: QWidget | None, target: Player | StandaloneIPLookup | str) -> None:
    """Open the live IP Lookup Details dialog for a player or IP address."""
    ip = target if isinstance(target, str) else target.ip

    def _factory() -> IPLookupDetailsDialog:
        if isinstance(target, str):
            matched_player = PlayersRegistry.get_player_by_ip(target)
            if matched_player is not None:
                return IPLookupDetailsDialog(None, matched_player)
            standalone_lookup = StandaloneIPLookup(ip=target)
            _start_standalone_lookup(standalone_lookup)
            return IPLookupDetailsDialog(None, standalone_lookup)
        return IPLookupDetailsDialog(None, target)

    _active_dialogs.show_or_focus(ip, _factory)
