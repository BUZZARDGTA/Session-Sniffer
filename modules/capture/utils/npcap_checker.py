"""Npcap Checker Module.

This module provides a utility function to check whether Npcap is installed on the system.
Npcap is required for network packet capturing in Windows environments.
"""
import subprocess
import webbrowser
from contextlib import suppress

from modules.constants.standalone import TITLE
from modules.constants.standard import SC_EXE
from modules.msgbox import MsgBox
from modules.utils import format_triple_quoted_text

NPCAP_SERVICE_QUERY_CMD = (SC_EXE, "query", "npcap")
NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"


def is_npcap_installed():
    """Check if the Npcap driver is installed on the system."""
    with suppress(subprocess.CalledProcessError):
        subprocess.run(NPCAP_SERVICE_QUERY_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    return False


def open_npcap_download_page():
    """Open the official Npcap download page in the web browser."""
    webbrowser.open(NPCAP_DOWNLOAD_URL)


def ensure_npcap_installed():
    """Ensure that the Npcap driver is installed. If not, show instructions and wait for user to install manually."""
    if is_npcap_installed():
        return

    # Open the official download page immediately
    open_npcap_download_page()

    # Show initial notification
    MsgBox.show(
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
        style=MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONINFORMATION | MsgBox.Style.MB_SETFOREGROUND,
    )

    # Keep checking until Npcap is installed
    while not is_npcap_installed():
        result = MsgBox.show(
            title=TITLE,
            text=format_triple_quoted_text("""
                NPCAP INSTALLATION CHECK:
                    Npcap is still not detected on your system.

                OPTIONS:
                    • Click "Retry" if you have completed the installation
                    • Click "Cancel" to exit the application
            """),
            style=MsgBox.Style.MB_RETRYCANCEL | MsgBox.Style.MB_ICONWARNING | MsgBox.Style.MB_SETFOREGROUND | MsgBox.Style.MB_DEFBUTTON1,
        )

        if result == MsgBox.ReturnValues.IDCANCEL:
            import sys
            sys.exit(1)
        elif result == MsgBox.ReturnValues.IDRETRY:
            continue

    # Success message in a separate thread so the app can continue running
    from threading import Thread

    def show_success_message():
        MsgBox.show(
            title=TITLE,
            text=format_triple_quoted_text("""
                SUCCESS:
                    Npcap has been successfully detected!

                The application will now continue normally.
            """),
            style=MsgBox.Style.MB_OK | MsgBox.Style.MB_ICONINFORMATION | MsgBox.Style.MB_SETFOREGROUND,
        )

    Thread(target=show_success_message, name="NpcapSuccessMessage", daemon=True).start()
