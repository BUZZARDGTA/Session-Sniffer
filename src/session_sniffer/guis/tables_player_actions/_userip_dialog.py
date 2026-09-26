"""UserIPDetectedDialog and show_userip_detected_dialog helper."""

from typing import TYPE_CHECKING, override

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QFormLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import PLAYER_INFO_FORM_LABEL_STYLESHEET
from session_sniffer.guis.tables_player_actions._format import format_bool, format_text
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import ActiveDialogRegistry, format_player_display, set_dialog_window_flags
from session_sniffer.text_utils import pluralize

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QCloseEvent

    from session_sniffer.models.player import Player


class UserIPDetectedDialog(PlayerInfoDialogMixin):
    """A non-modal dialog showing UserIP detection data for a player, updating live as lookups resolve."""

    _REFRESH_INTERVAL_MS = 500

    def __init__(self, parent: QWidget | None, player: Player) -> None:
        """Snapshot player data at detection time, build the dialog UI, and start the refresh timer."""
        super().__init__(parent)
        set_dialog_window_flags(self, keep_on_top=True)
        self._player = player
        self._rows: list[tuple[QLabel, Callable[[], str]]] = []

        self.setWindowTitle(f'{TITLE} - UserIP Detected ({format_player_display(player.ip, player.usernames)})')
        self._apply_standard_dialog_size()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)
        self._header_label = self._add_header_label(outer_layout, f'UserIP Detected — {format_player_display(player.ip, player.usernames)}', '#c53030', '#dd6b20')

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_detection_group(scroll_layout, player)
        self._build_iplookup_group(scroll_layout, player)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

        self._timer = QTimer(self)
        self._timer.start(self._REFRESH_INTERVAL_MS)
        self._timer.timeout.connect(self._refresh)

        self._refresh()

    def _add_live_row(self, form: QFormLayout, label_text: str, provider: Callable[[], str]) -> None:
        """Append a label / copyable-value row to *form* and register it for refresh."""
        label_widget = QLabel(f'{label_text}:')
        label_widget.setStyleSheet(PLAYER_INFO_FORM_LABEL_STYLESHEET)
        value_widget = self._make_value_label(provider())
        form.addRow(label_widget, value_widget)
        self._rows.append((value_widget, provider))

    def _build_detection_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Detection Details' section to the scroll layout."""
        group, form = self._make_group('Detection Details', accent='#c53030')
        detection_time = player.userip_detection.time if player.userip_detection is not None else 'N/A'
        usernames = ', '.join(player.userip.usernames) if player.userip is not None and player.userip.usernames else 'N/A'
        if player.userip is not None:
            try:
                relative_db = str(player.userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))
            except ValueError:
                relative_db = str(player.userip.db_path)
        else:
            relative_db = 'N/A'
        detection_type = player.userip_detection.type if player.userip_detection is not None else 'N/A'
        self._add_row(form, 'Detection Time', detection_time)
        self._add_row(form, f'Username{pluralize(len(player.userip.usernames) if player.userip is not None else 0)}', usernames)
        self._add_row(form, 'IP Address', player.ip)
        self._add_live_row(form, 'Hostname', lambda: format_text(player.reverse_dns.hostname))
        self._add_live_row(form, 'Port(s)', lambda: ', '.join(map(str, reversed(player.ports.all))) if player.ports.all else 'N/A')
        self._add_live_row(form, 'Country Code', lambda: format_text(player.iplookup.geolite2.country_code))
        self._add_row(form, 'Detection Type', detection_type)
        self._add_row(form, 'Database', relative_db)
        parent_layout.addWidget(group)

    def _build_iplookup_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'IP Lookup' section to the scroll layout."""
        group, form = self._make_group('IP Lookup', accent='#38a169')
        self._add_live_row(form, 'Continent', lambda: format_text(player.iplookup.ipapi.continent))
        self._add_live_row(form, 'Country', lambda: format_text(player.iplookup.geolite2.country))
        self._add_live_row(form, 'Region', lambda: format_text(player.iplookup.ipapi.region))
        self._add_live_row(form, 'City', lambda: format_text(player.iplookup.geolite2.city))
        self._add_live_row(form, 'Organization', lambda: format_text(player.iplookup.ipapi.org))
        self._add_live_row(form, 'ISP', lambda: format_text(player.iplookup.ipapi.isp))
        self._add_live_row(form, 'GeoLite2 ASN / ISP', lambda: format_text(player.iplookup.geolite2.asn))
        self._add_live_row(form, 'AS Name', lambda: format_text(player.iplookup.ipapi.as_name))
        self._add_live_row(form, 'Mobile (cellular)', lambda: format_bool(player.iplookup.ipapi.mobile))
        self._add_live_row(form, 'Proxy / VPN / Tor', lambda: format_bool(player.iplookup.ipapi.proxy))
        self._add_live_row(form, 'Hosting / Datacenter', lambda: format_bool(player.iplookup.ipapi.hosting))
        parent_layout.addWidget(group)

    def _refresh(self) -> None:
        """Re-evaluate dynamic row providers, update the UI, and stop the timer once all lookups are complete."""
        display = format_player_display(self._player.ip, self._player.usernames)
        new_title = f'{TITLE} - UserIP Detected ({display})'
        if self.windowTitle() != new_title:
            self.setWindowTitle(new_title)
            self._header_label.setText(f'UserIP Detected — {display}')

        for value_widget, provider in self._rows:
            text = provider()
            if value_widget.text() != text:
                value_widget.setText(text)

        if self._player.reverse_dns.is_initialized and self._player.iplookup.geolite2.is_initialized and self._player.iplookup.ipapi.is_initialized:
            self._timer.stop()

    @override
    def reject(self) -> None:
        """Stop the refresh timer and reject the dialog."""
        self._timer.stop()
        super().reject()

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        """Stop the refresh timer when the dialog is closed."""
        self._timer.stop()
        super().closeEvent(event)


_active_dialogs: ActiveDialogRegistry[str, UserIPDetectedDialog] = ActiveDialogRegistry()


def show_userip_detected_dialog(parent: QWidget | None, player: Player) -> None:
    """Open or focus the UserIP Detected dialog for *player*."""
    _active_dialogs.show_or_focus(player.ip, lambda: UserIPDetectedDialog(parent, player))
