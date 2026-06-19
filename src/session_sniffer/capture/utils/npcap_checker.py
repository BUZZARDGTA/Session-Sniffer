"""Npcap Checker Module.

This module provides a utility function to check whether Npcap is installed on the system.
Npcap is required for network packet capturing in Windows environments.
"""

import subprocess
import sys
import webbrowser
from contextlib import suppress
from threading import Thread

from session_sniffer import msgbox
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import SC_EXE
from session_sniffer.error_messages import (
    format_npcap_installation_check_message,
    format_npcap_required_message,
    format_npcap_success_message,
)
from session_sniffer.text_utils import format_triple_quoted_text

NPCAP_SERVICE_QUERY_CMD = (SC_EXE, 'query', 'npcap')
NPCAP_DOWNLOAD_URL = 'https://npcap.com/#download'


def is_npcap_installed() -> bool:
    """Check if the Npcap driver is installed on the system."""
    with suppress(subprocess.CalledProcessError, subprocess.TimeoutExpired):
        subprocess.run(NPCAP_SERVICE_QUERY_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        return True
    return False


def open_npcap_download_page() -> None:
    """Open the official Npcap download page in the web browser."""
    webbrowser.open(NPCAP_DOWNLOAD_URL)


def ensure_npcap_installed() -> None:
    """Ensure that the Npcap driver is installed. If not, show instructions and wait for user to install manually."""
    if is_npcap_installed():
        return

    open_npcap_download_page()

    msgbox.show(
        title=TITLE,
        text=format_triple_quoted_text(format_npcap_required_message()),
        style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
    )

    while not is_npcap_installed():
        result = msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(format_npcap_installation_check_message()),
            style=msgbox.Style.MB_RETRYCANCEL | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND | msgbox.Style.MB_DEFBUTTON1,
        )

        if result == msgbox.ReturnValues.IDCANCEL:
            sys.exit(1)
        elif result == msgbox.ReturnValues.IDRETRY:
            continue

    # Success message in a separate thread so the app can continue running
    def show_success_message() -> None:
        msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text(format_npcap_success_message()),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
        )

    Thread(target=show_success_message, name='NpcapSuccessMessage', daemon=True).start()
