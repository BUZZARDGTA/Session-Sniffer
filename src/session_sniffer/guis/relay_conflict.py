"""Dialogs for resolving incompatible GTA5 relay detection settings."""

from typing import Literal

from PyQt6.QtWidgets import QMessageBox, QWidget

from session_sniffer.constants.local import DETECTIONS_JSON_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.player.detections import GUIDetectionSettings
from session_sniffer.settings import Settings


def prompt_to_disable_gta5_relay_if_filtered(parent: QWidget | None, *, context: Literal['settings', 'startup']) -> bool:
    """Ask to disable GTA5 relay detection when the Take-Two Interactive relay IPs are filtered."""
    if not (
        Settings.is_gta5_preset()
        and 'TAKETWO_INTERACTIVE' in Settings.capture_block_third_party_servers
        and GUIDetectionSettings.gta5_relay_enabled
    ):
        return False

    if context == 'settings':
        detail = (
            'GTA5 relay detection is currently enabled, but the capture filter will now '
            "block the 'Take-Two Interactive Software, Inc.' IP ranges."
        )
    else:
        detail = (
            'Conflicting settings detected:\n\n'
            'GTA5 relay detection is enabled, but the capture filter is blocking '
            "the 'Take-Two Interactive Software, Inc.' IP ranges."
        )

    result = QMessageBox.question(
        parent,
        TITLE,
        f'\u26a0\ufe0f {detail}\n\n'
        'Relay IPs will be dropped before the capture engine sees them, so relay detection '
        'will never trigger.\n\n'
        'Would you like to automatically disable GTA5 relay detection?',
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.Yes,
    )
    if result != QMessageBox.StandardButton.Yes:
        return False

    GUIDetectionSettings.gta5_relay_enabled = False
    GUIDetectionSettings.export_to_file(DETECTIONS_JSON_PATH)
    return True
