"""DetectionNotificationDialog, PlayerDetectionDialog, and related helpers."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QLabel,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import DETECTION_WARN_LABEL_STYLESHEET
from session_sniffer.guis.tables_player_actions._fmt import fmt_bool, fmt_text
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import format_player_display, set_dialog_window_flags
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from session_sniffer.models.player import Player


@dataclass(slots=True, kw_only=True)
class DetectionNotificationInfo:
    """Bundled metadata for a detection manager notification dialog."""

    emoji: str
    display_title: str
    extra_detection_fields: list[tuple[str, str]]
    event_time: str


class DetectionNotificationDialog(PlayerInfoDialogMixin):
    """A non-modal dialog showing a detection manager notification for a player."""

    def __init__(
        self,
        parent: QWidget | None,
        player: Player,
        info: DetectionNotificationInfo,
    ) -> None:
        """Snapshot player data at detection time and build the dialog UI."""
        super().__init__(parent)
        set_dialog_window_flags(self, keep_on_top=True)

        self.setWindowTitle(f'{TITLE} - {info.display_title} ({format_player_display(player.ip, player.usernames)})')
        self._apply_standard_dialog_size()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._add_header_label(outer_layout, f'{info.emoji}  {info.display_title} — {format_player_display(player.ip, player.usernames)}', '#744210', '#975a16')

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_detection_group(scroll_layout, player, info.extra_detection_fields, info.event_time)
        self._build_connection_group(scroll_layout, player)
        self._build_location_group(scroll_layout, player)
        self._build_network_group(scroll_layout, player)
        self._build_flags_group(scroll_layout, player)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

    def _build_detection_group(self, parent_layout: QVBoxLayout, player: Player, extra_detection_fields: list[tuple[str, str]], event_time: str) -> None:
        """Add the 'Detection Details' section."""
        group, form = self._make_group('\U0001f6a8  Detection Details', accent='#c53030')
        self._add_row(form, 'Time', event_time)
        for label, value in extra_detection_fields:
            self._add_row(form, label, value)
        self._add_row(form, f'Username{pluralize(len(player.usernames))}', ', '.join(player.usernames) or 'N/A')
        parent_layout.addWidget(group)

    def _build_connection_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Connection Details' section."""
        group, form = self._make_group('\U0001f517  Connection Details', accent='#2b6cb0')
        self._add_row(form, 'IP Address', player.ip)
        self._add_row(form, 'Hostname', fmt_text(player.reverse_dns.hostname))
        parent_layout.addWidget(group)

    def _build_location_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Location Details' section."""
        group, form = self._make_group('\U0001f30d  Location Details', accent='#38a169')
        self._add_row(form, 'Country', fmt_text(player.iplookup.geolite2.country))
        self._add_row(form, 'City', fmt_text(player.iplookup.geolite2.city))
        parent_layout.addWidget(group)

    def _build_network_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Network Details' section."""
        group, form = self._make_group('\U0001f310  Network Details', accent='#d69e2e')
        self._add_row(form, 'ISP', fmt_text(player.iplookup.ipapi.isp))
        self._add_row(form, 'Organization', fmt_text(player.iplookup.ipapi.org))
        asn = fmt_text(player.iplookup.ipapi.asn)
        as_name = fmt_text(player.iplookup.ipapi.as_name)
        asn_display = f'{asn} ({as_name})' if asn != 'N/A' and as_name != 'N/A' else asn
        self._add_row(form, 'ASN', asn_display)
        parent_layout.addWidget(group)

    def _build_flags_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Detection Flags' section."""
        group, form = self._make_group('\U0001f6a9  Detection Flags', accent='#805ad5')
        self._add_row(form, 'Mobile (cellular)', fmt_bool(player.iplookup.ipapi.mobile))
        self._add_row(form, 'Proxy / VPN / Tor', fmt_bool(player.iplookup.ipapi.proxy))
        self._add_row(form, 'Hosting / Datacenter', fmt_bool(player.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)


def show_detection_notification_dialog(
    parent: QWidget | None,
    player: Player,
    info: DetectionNotificationInfo,
) -> None:
    """Open the Detection Notification dialog for *player*."""
    dialog = DetectionNotificationDialog(parent, player, info)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()


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


class PlayerDetectionDialog(PlayerInfoDialogMixin):
    """A non-modal dialog showing a snapshot of player detection event data."""

    def __init__(
        self,
        parent: QWidget | None,
        player: Player,
        info: PlayerDetectionInfo,
    ) -> None:
        """Snapshot player data at event time and build the dialog UI."""
        super().__init__(parent)
        set_dialog_window_flags(self, keep_on_top=True)

        self.setWindowTitle(f'{TITLE} - {info.title} ({format_player_display(player.ip, player.usernames)})')
        self._apply_standard_dialog_size()

        color_start, color_stop = _DETECTION_EMOJI_HEADER_COLORS.get(info.emoji, _DETECTION_DEFAULT_HEADER_COLORS)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._add_header_label(outer_layout, f'{info.emoji}  {info.title} — {format_player_display(player.ip, player.usernames)}', color_start, color_stop)

        if not info.data_ready:
            warn_label = QLabel('\u26a0\ufe0f  Some data may still be loading and missing from this notification')
            warn_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            warn_label.setWordWrap(True)
            warn_label.setStyleSheet(DETECTION_WARN_LABEL_STYLESHEET)
            outer_layout.addWidget(warn_label)

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_player_group(scroll_layout, player, info, color_start)
        self._build_connection_group(scroll_layout, player)
        self._build_location_group(scroll_layout, player)
        self._build_network_group(scroll_layout, player)
        self._build_flags_group(scroll_layout, player)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

    def _build_player_group(self, parent_layout: QVBoxLayout, player: Player, info: PlayerDetectionInfo, accent: str) -> None:
        """Add the 'Player Details' section."""
        group, form = self._make_group('\U0001f464  Player Details', accent=accent)
        self._add_row(form, 'Event', info.description)
        self._add_row(form, 'Event Time', info.event_time)
        self._add_row(form, f'Username{pluralize(len(player.usernames))}', ', '.join(player.usernames) or 'N/A')
        parent_layout.addWidget(group)

    def _build_connection_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Connection Details' section."""
        group, form = self._make_group('\U0001f517  Connection Details', accent='#2b6cb0')
        self._add_row(form, 'IP Address', player.ip)
        self._add_row(form, 'Hostname', fmt_text(player.reverse_dns.hostname))
        self._add_row(form, 'First Port', str(player.ports.first))
        self._add_row(form, 'Middle Port(s)', ', '.join(map(str, reversed(player.ports.middle))) or '')
        self._add_row(form, 'Last Port', str(player.ports.last))
        self._add_row(form, 'Total Packets Exchanged', str(player.packets.total_exchanged))
        self._add_row(form, 'Session Packets', str(player.packets.exchanged))
        self._add_row(form, 'Rejoins', str(player.rejoins))
        parent_layout.addWidget(group)

    def _build_location_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Location Details' section."""
        group, form = self._make_group('\U0001f30d  Location Details', accent='#38a169')
        continent = fmt_text(player.iplookup.ipapi.continent)
        continent_code = fmt_text(player.iplookup.ipapi.continent_code)
        continent_display = f'{continent} ({continent_code})' if continent != 'N/A' and continent_code != 'N/A' else continent
        country = fmt_text(player.iplookup.ipapi.country)
        country_code = fmt_text(player.iplookup.ipapi.country_code)
        country_display = f'{country} ({country_code})' if country != 'N/A' and country_code != 'N/A' else country
        region = fmt_text(player.iplookup.ipapi.region)
        region_code = fmt_text(player.iplookup.ipapi.region_code)
        region_display = f'{region} ({region_code})' if region != 'N/A' and region_code != 'N/A' else region
        self._add_row(form, 'Continent', continent_display)
        self._add_row(form, 'Country', country_display)
        self._add_row(form, 'Region', region_display)
        parent_layout.addWidget(group)

    def _build_network_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Network Details' section."""
        group, form = self._make_group('\U0001f310  Network Details', accent='#d69e2e')
        self._add_row(form, 'ISP', fmt_text(player.iplookup.ipapi.isp))
        self._add_row(form, 'Organization', fmt_text(player.iplookup.ipapi.org))
        asn = fmt_text(player.iplookup.ipapi.asn)
        as_name = fmt_text(player.iplookup.ipapi.as_name)
        asn_display = f'{asn} ({as_name})' if asn != 'N/A' and as_name != 'N/A' else asn
        self._add_row(form, 'ASN', asn_display)
        parent_layout.addWidget(group)

    def _build_flags_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Detection Flags' section."""
        group, form = self._make_group('\U0001f6a9  Detection Flags', accent='#805ad5')
        self._add_row(form, 'Mobile (cellular)', fmt_bool(player.iplookup.ipapi.mobile))
        self._add_row(form, 'Proxy / VPN / Tor', fmt_bool(player.iplookup.ipapi.proxy))
        self._add_row(form, 'Hosting / Datacenter', fmt_bool(player.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)


def show_player_detection_dialog(
    parent: QWidget | None,
    player: Player,
    info: PlayerDetectionInfo,
) -> None:
    """Open the Player Detection dialog for *player*."""
    dialog = PlayerDetectionDialog(parent, player, info)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
