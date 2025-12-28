"""Npcap Checker Module.

This module provides a utility function to check whether Npcap is installed on the system.
Npcap is required for network packet capturing in Windows environments.
"""
import subprocess
import sys
import webbrowser
from contextlib import suppress
from threading import Thread

from modules import msgbox
from modules.constants.standalone import TITLE
from modules.constants.standard import SC_EXE
from modules.text_utils import format_triple_quoted_text

NPCAP_SERVICE_QUERY_CMD = (SC_EXE, 'query', 'npcap')
NPCAP_DOWNLOAD_URL = 'https://npcap.com/#download'


def is_npcap_installed() -> bool:
    """Check if the Npcap driver is installed on the system."""
    with suppress(subprocess.CalledProcessError):
        subprocess.run(NPCAP_SERVICE_QUERY_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    return False


def open_npcap_download_page() -> None:
    """Open the official Npcap download page in the web browser."""
    webbrowser.open(NPCAP_DOWNLOAD_URL)


def ensure_npcap_installed() -> None:
    """Ensure that the Npcap driver is installed. If not, show instructions and wait for user to install manually."""
    if is_npcap_installed():
        return

    # Open the official download page immediately
    open_npcap_download_page()

    # Show initial notification
    msgbox.show(
        title=TITLE,
        text=format_triple_quoted_text("""
            NPCAP REQUIRED:
                Npcap is required for network packet capturing.

            ACTION REQUIRED:
                1. Npcap download page opened in your browser
                2. Download and install Npcap from:
                    https://npcap.com/#download
                3. Follow the installation instructions on the website
                4. Click OK after installation is complete

            IMPORTANT:
                Waiting for installation to complete...
                Please do not close this dialog until Npcap is installed.
        """),
        style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
    )

    # Keep checking until Npcap is installed
    while not is_npcap_installed():
        result = msgbox.show(
            title=TITLE,
            text=format_triple_quoted_text("""
                NPCAP INSTALLATION CHECK:
                    Npcap is still not detected on your system.

                OPTIONS:
                    • Click "Retry" if you have completed the installation
                    • Click "Cancel" to exit the application
            """),
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
            text=format_triple_quoted_text("""
                SUCCESS:
                    Npcap has been successfully detected!

                The application will now continue normally.
            """),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
        )

    Thread(target=show_success_message, name='NpcapSuccessMessage', daemon=True).start()
