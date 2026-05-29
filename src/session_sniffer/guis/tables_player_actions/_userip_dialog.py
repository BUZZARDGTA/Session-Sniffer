"""UserIPDetectedDialog and show_userip_detected_dialog helper."""

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.tables_player_actions._fmt import fmt_bool, fmt_text
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import format_player_display, set_dialog_window_flags
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from session_sniffer.models.player import Player


class UserIPDetectedDialog(PlayerInfoDialogMixin):
    """A non-modal dialog showing a snapshot of UserIP detection data for a player."""

    def __init__(self, parent: QWidget | None, player: Player) -> None:
        """Snapshot player data at detection time and build the dialog UI."""
        super().__init__(parent)
        set_dialog_window_flags(self)

        self.setWindowTitle(f'{TITLE} - UserIP Detected ({format_player_display(player.ip, player.usernames)})')
        self._apply_standard_dialog_size()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)

        self._add_header_label(outer_layout, f'\U0001f514  UserIP Detected \u2014 {format_player_display(player.ip, player.usernames)}', '#c53030', '#dd6b20')

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_detection_group(scroll_layout, player)
        self._build_iplookup_group(scroll_layout, player)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

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
        self._add_row(form, f'Username{pluralize(len(userip.usernames) if userip is not None else 0)}', usernames)
        self._add_row(form, 'IP Address', player.ip)
        self._add_row(form, 'Hostname', fmt_text(player.reverse_dns.hostname))
        self._add_row(form, 'Port(s)', ports_str)
        self._add_row(form, 'Country Code', fmt_text(player.iplookup.geolite2.country_code))
        self._add_row(form, 'Detection Type', detection_type)
        self._add_row(form, 'Database', relative_db)
        parent_layout.addWidget(group)

    def _build_iplookup_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'IP Lookup' section to the scroll layout."""
        group, form = self._make_group('\U0001f30d  IP Lookup', accent='#38a169')
        self._add_row(form, 'Continent', fmt_text(player.iplookup.ipapi.continent))
        self._add_row(form, 'Country', fmt_text(player.iplookup.geolite2.country))
        self._add_row(form, 'Region', fmt_text(player.iplookup.ipapi.region))
        self._add_row(form, 'City', fmt_text(player.iplookup.geolite2.city))
        self._add_row(form, 'Organization', fmt_text(player.iplookup.ipapi.org))
        self._add_row(form, 'ISP', fmt_text(player.iplookup.ipapi.isp))
        self._add_row(form, 'GeoLite2 ASN / ISP', fmt_text(player.iplookup.geolite2.asn))
        self._add_row(form, 'AS Name', fmt_text(player.iplookup.ipapi.as_name))
        self._add_row(form, 'Mobile (cellular)', fmt_bool(player.iplookup.ipapi.mobile))
        self._add_row(form, 'Proxy / VPN / Tor', fmt_bool(player.iplookup.ipapi.proxy))
        self._add_row(form, 'Hosting / Datacenter', fmt_bool(player.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)


def show_userip_detected_dialog(parent: QWidget | None, player: Player) -> None:
    """Open the UserIP Detected dialog for *player*."""
    dialog = UserIPDetectedDialog(parent, player)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
