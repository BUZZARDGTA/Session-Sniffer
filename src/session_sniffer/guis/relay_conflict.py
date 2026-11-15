"""Dialogs for resolving incompatible GTA5 relay detection settings."""

from typing import Literal

from PySide6.QtWidgets import QMessageBox, QWidget

from session_sniffer.constants.local import DETECTIONS_JSON_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.i18n import tr
from session_sniffer.networking.third_party_servers import ThirdPartyServers
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.settings import Settings


def prompt_to_disable_gta5_relay_if_filtered(parent: QWidget | None, *, context: Literal['settings', 'startup']) -> None:
    """Ask to disable GTA5 relay detection when the Take-Two Interactive or Microsoft relay IPs are filtered."""
    blocked_relays = [name for name in ('TAKETWO_INTERACTIVE', 'MICROSOFT') if name in Settings.capture_block_third_party_servers]

    if not (Settings.is_gta5_feature_set() and blocked_relays and GUIDetectionSettings.gta5_relay_enabled):
        return

    blocked_names = [f"'{ThirdPartyServers[name].display_name}'" for name in blocked_relays]
    blocked_names_str = blocked_names[0] if len(blocked_names) == 1 else tr('{first} and {second}', first=blocked_names[0], second=blocked_names[1])

    if context == 'settings':
        detail = tr(
            'GTA5 relay detection is currently enabled, but the capture filter will now block the {blocked_names} IP ranges.',
            blocked_names=blocked_names_str,
        )
    else:
        detail = tr(
            'Conflicting settings detected:\n\nGTA5 relay detection is enabled, but the capture filter is blocking the {blocked_names} IP ranges.',
            blocked_names=blocked_names_str,
        )

    result = QMessageBox.question(
        parent,
        TITLE,
        tr(
            '{detail}\n\n'
            'Relay IPs will be dropped before the capture engine sees them, so relay detection '
            'will never trigger.\n\n'
            'Would you like to automatically disable GTA5 relay detection?',
            detail=detail,
        ),
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.Yes,
    )
    if result != QMessageBox.StandardButton.Yes:
        return

    GUIDetectionSettings.gta5_relay_enabled = False
    GUIDetectionSettings.export_to_file(DETECTIONS_JSON_PATH)
