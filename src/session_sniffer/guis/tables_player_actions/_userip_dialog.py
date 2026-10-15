"""UserIPDetectedDialog and show_userip_detected_dialog helper."""

from typing import TYPE_CHECKING, override

from PySide6.QtWidgets import (
    QFormLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)
from shiboken6 import isValid

from session_sniffer.constants.local import USERIP_DATABASES_DIR_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.guis.stylesheets import PLAYER_INFO_FORM_LABEL_STYLESHEET
from session_sniffer.guis.tables_player_actions._format import format_bool, format_text
from session_sniffer.guis.tables_player_actions._player_info_dialog_mixin import PlayerInfoDialogMixin
from session_sniffer.guis.utils import ActiveDialogRegistry, format_player_display, set_dialog_window_flags
from session_sniffer.models.userip_settings_model import format_iso_timestamp_display
from session_sniffer.player.userip import UserIP, UserIPDatabases
from session_sniffer.text_utils import pluralize
from session_sniffer.utils import dedup_preserve_order

if TYPE_CHECKING:
    from collections.abc import Callable

    from PySide6.QtGui import QCloseEvent

    from session_sniffer.models.player import Player


class UserIPDetectedDialog(PlayerInfoDialogMixin):
    """A non-modal dialog showing UserIP detection data for a player, updating live as lookups resolve."""

    _REFRESH_INTERVAL_MS = 500

    def __init__(self, parent: QWidget | None, player: Player, userip: UserIP | None = None) -> None:
        """Snapshot player data at detection time, build the dialog UI, and start the refresh timer."""
        super().__init__(parent)
        set_dialog_window_flags(self, keep_on_top=True)
        self._player = player
        self._userip: UserIP | None = userip or player.userip
        if self._player.userip is None and self._userip is not None:
            self._player.userip = self._userip
        if self._userip is not None and self._userip.usernames:
            self._player.usernames = dedup_preserve_order(self._player.usernames, self._userip.usernames)
        self._rows: list[tuple[QLabel, Callable[[], str], QLabel, Callable[[], str] | None]] = []

        initial_usernames = self._get_usernames()
        display = format_player_display(player.ip, initial_usernames)
        self.setWindowTitle(f'{TITLE} - UserIP Detected ({display})')
        self._apply_standard_dialog_size()

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(10, 10, 10, 10)
        outer_layout.setSpacing(8)
        self._header_label = self._add_header_label(outer_layout, f'UserIP Detected — {display}', '#c53030', '#dd6b20')

        scroll_layout = self._init_scroll_area(outer_layout)

        self._build_detection_group(scroll_layout, player)
        self._build_iplookup_group(scroll_layout, player)
        scroll_layout.addStretch(1)

        self._add_close_button_box(outer_layout)

        self._timer = self._init_refresh_timer(self._REFRESH_INTERVAL_MS, self._refresh)

        self._refresh()

    def _get_userip(self) -> UserIP | None:
        if self._player.userip is not None:
            return self._player.userip
        if self._userip is not None:
            return self._userip
        resolved = UserIPDatabases.resolve_userip(self._player.ip)
        if resolved is not None:
            self._player.userip = resolved
            if resolved.usernames:
                self._player.usernames = dedup_preserve_order(self._player.usernames, resolved.usernames)
            return resolved
        return None

    def _get_usernames(self) -> list[str]:
        userip = self._get_userip()
        userip_names = userip.usernames if userip is not None else []
        if self._player.usernames and userip_names:
            return dedup_preserve_order(self._player.usernames, userip_names)
        if self._player.usernames:
            return self._player.usernames
        return list(userip_names)

    def _get_notes(self) -> list[str]:
        userip = self._get_userip()
        return list(userip.notes) if userip is not None and userip.notes else []

    def _get_sources(self) -> list[str]:
        userip = self._get_userip()
        return list(userip.sources) if userip is not None and userip.sources else []

    def _get_database_name(self) -> str:
        userip = self._get_userip()
        if userip is not None:
            try:
                return str(userip.db_path.relative_to(USERIP_DATABASES_DIR_PATH).with_suffix(''))
            except ValueError:
                return str(userip.db_path)
        return 'N/A'

    def _add_live_row(
        self,
        form: QFormLayout,
        label: str | Callable[[], str],
        provider: Callable[[], str],
    ) -> None:
        """Append a label / copyable-value row to *form* and register it for refresh."""
        if isinstance(label, str):
            initial_label = label
            label_provider = None
        else:
            initial_label = label()
            label_provider = label
        label_widget = QLabel(f'{initial_label}:')
        label_widget.setStyleSheet(PLAYER_INFO_FORM_LABEL_STYLESHEET)
        value_widget = self._make_value_label(provider())
        form.addRow(label_widget, value_widget)
        self._rows.append((value_widget, provider, label_widget, label_provider))

    def _build_detection_group(self, parent_layout: QVBoxLayout, player: Player) -> None:
        """Add the 'Detection Details' section to the scroll layout."""
        group, form = self._make_group('Detection Details', accent='#c53030')
        detection_type = player.userip_detection.type if player.userip_detection is not None else 'N/A'
        self._add_live_row(form, 'Detection Time', lambda: player.userip_detection.time if player.userip_detection is not None else 'N/A')
        self._add_live_row(
            form,
            lambda: f'Username{pluralize(len(self._get_usernames()))}',
            lambda: ', '.join(self._get_usernames()) or 'N/A',
        )
        self._add_row(form, 'IP Address', player.ip)
        self._add_live_row(form, 'Hostname', lambda: format_text(player.reverse_dns.hostname))
        self._add_live_row(form, lambda: f'Port{pluralize(len(player.ports.all))}', lambda: ', '.join(map(str, reversed(player.ports.all))) if player.ports.all else 'N/A')
        self._add_live_row(form, 'Country Code', lambda: format_text(player.iplookup.geolite2.country_code))
        self._add_live_row(form, 'Detection Type', lambda: player.userip_detection.type if player.userip_detection is not None else detection_type)
        self._add_live_row(form, 'Database', self._get_database_name)
        self._add_live_row(
            form,
            lambda: f'Note{pluralize(len(self._get_notes()))}',
            lambda: ', '.join(self._get_notes()) or 'N/A',
        )
        self._add_live_row(
            form,
            lambda: f'Source{pluralize(len(self._get_sources()))}',
            lambda: ', '.join(self._get_sources()) or 'N/A',
        )
        self._add_live_row(
            form,
            'Detections',
            lambda: str(userip.detections_count) if (userip := self._get_userip()) is not None else 'N/A',
        )
        self._add_live_row(
            form,
            'Added',
            lambda: (format_iso_timestamp_display(userip.added_at) or 'N/A') if (userip := self._get_userip()) is not None else 'N/A',
        )
        self._add_live_row(
            form,
            'Updated',
            lambda: (format_iso_timestamp_display(userip.updated_at) or 'N/A') if (userip := self._get_userip()) is not None else 'N/A',
        )
        self._add_live_row(
            form,
            'First Seen (DB)',
            lambda: (format_iso_timestamp_display(userip.first_seen_at) or 'N/A') if (userip := self._get_userip()) is not None else 'N/A',
        )
        self._add_live_row(
            form,
            'Last Seen (DB)',
            lambda: (format_iso_timestamp_display(userip.last_seen_at) or 'N/A') if (userip := self._get_userip()) is not None else 'N/A',
        )
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
        """Re-evaluate dynamic row providers and update the UI."""
        if not isValid(self):
            return
        usernames = self._get_usernames()
        display = format_player_display(self._player.ip, usernames)
        new_title = f'{TITLE} - UserIP Detected ({display})'
        if self.windowTitle() != new_title:
            self.setWindowTitle(new_title)
        new_header = f'UserIP Detected — {display}'
        if self._header_label.text() != new_header:
            self._header_label.setText(new_header)

        for value_widget, provider, label_widget, label_provider in self._rows:
            text = provider()
            if value_widget.text() != text:
                value_widget.setText(text)
            if label_provider is not None:
                new_label = f'{label_provider()}:'
                if label_widget.text() != new_label:
                    label_widget.setText(new_label)

    @override
    def done(self, r: int) -> None:
        """Stop the refresh timer and finalize the dialog."""
        self._timer.stop()
        super().done(r)

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


def show_userip_detected_dialog(parent: QWidget | None, player: Player, userip: UserIP | None = None) -> None:
    """Open or focus the UserIP Detected dialog for *player*."""
    if userip is not None and player.userip is None:
        player.userip = userip
    _active_dialogs.show_or_focus(player.ip, lambda: UserIPDetectedDialog(parent, player, userip))
