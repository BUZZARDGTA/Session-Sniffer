"""Dialogs for resolving incompatible GTA5 relay protection settings."""

from typing import Literal

from PyQt6.QtWidgets import QMessageBox, QWidget

from session_sniffer.constants.local import PROTECTIONS_JSON_PATH
from session_sniffer.constants.standalone import TITLE
from session_sniffer.player.protections import GUIProtectionSettings
from session_sniffer.settings import Settings


def prompt_to_disable_gta5_relay_if_filtered(parent: QWidget | None, *, context: Literal['settings', 'startup']) -> bool:
    """Ask to disable GTA5 relay protection when the Take-Two relay IPs are filtered."""
    if not (
        Settings.capture_program_preset == 'GTA5'
        and 'GTAV_TAKETWO' in Settings.capture_block_third_party_servers
        and GUIProtectionSettings.gta5_relay_enabled
    ):
        return False

    if context == 'settings':
        detail = (
            'GTA5 relay protection is currently enabled, but the capture filter will now '
            "block the 'Take-Two (GTA V)' IP ranges."
        )
    else:
        detail = (
            'Conflicting settings detected:\n\n'
            'GTA5 relay protection is enabled, but the capture filter is blocking '
            "the 'Take-Two (GTA V)' IP ranges."
        )

    result = QMessageBox.question(
        parent,
        TITLE,
        f'\u26a0\ufe0f {detail}\n\n'
        'Relay IPs will be dropped before the capture engine sees them, so relay protection '
        'will never trigger.\n\n'
        'Would you like to automatically disable GTA5 relay protection?',
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.Yes,
    )
    if result != QMessageBox.StandardButton.Yes:
        return False

    GUIProtectionSettings.gta5_relay_enabled = False
    GUIProtectionSettings.export_to_file(PROTECTIONS_JSON_PATH)
    return True
