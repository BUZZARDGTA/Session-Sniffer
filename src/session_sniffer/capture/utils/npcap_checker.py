"""Npcap Checker Module.

This module provides a utility function to check whether Npcap is installed on the system.
Npcap is required for network packet capturing in Windows environments.
"""

import os
import socket
import subprocess
import sys
import webbrowser
from threading import Thread

from session_sniffer import msgbox
from session_sniffer.capture.pcap import is_pcap_library_available
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import SC_EXE
from session_sniffer.error_messages import (
    format_npcap_installation_check_message,
    format_npcap_required_message,
    format_npcap_success_message,
)
from session_sniffer.logging_setup import get_logger
from session_sniffer.text_utils import format_triple_quoted_text

logger = get_logger(__name__)

NPCAP_SERVICE_QUERY_CMD = (SC_EXE, 'query', 'npcap')
NPCAP_DOWNLOAD_URL = 'https://npcap.com/#download'

LIBPCAP_REQUIRED_MESSAGE = (
    'Session Sniffer requires libpcap on Linux to capture packets.\n\n'
    'Please install it using your package manager, for example:\n'
    '  sudo apt install libpcap0.8\n\n'
    'After installing, click OK to proceed.'
)
LIBPCAP_INSTALLATION_CHECK_MESSAGE = (
    'libpcap was not detected.\n\n'
    'If you have already installed it, click Retry.\n'
    'Otherwise, click Cancel to exit.'
)


def is_libpcap_installed() -> bool:
    """Check if the libpcap shared library is installed on the system."""
    return is_pcap_library_available()


_AF_PACKET = getattr(socket, 'AF_PACKET', 17)


def can_capture_packets_on_linux() -> bool:
    """Check whether the current process has permission to open raw packet sockets on Linux."""
    if not is_libpcap_installed():
        return False
    try:
        raw_socket = socket.socket(_AF_PACKET, socket.SOCK_RAW)
        raw_socket.close()
    except (PermissionError, OSError) as e:
        logger.debug('Cannot capture packets on Linux: %s', e)
        return False
    return True


def get_linux_permissions_required_message() -> str:
    """Format the message explaining the required packet capture capabilities on Linux."""
    real_python_executable = os.path.realpath(sys.executable)
    return (
        'Session Sniffer requires root privileges or the CAP_NET_RAW capability to capture network traffic on Linux.\n\n'
        'To grant the required capability to Python without running as root, execute:\n'
        f'  sudo setcap cap_net_raw,cap_net_admin=eip {real_python_executable}\n\n'
        'Alternatively, run Session Sniffer with root privileges:\n'
        '  sudo -E env PATH=$PATH python3 -m session_sniffer\n\n'
        'After granting permissions, click OK to proceed.'
    )


def get_linux_permissions_check_message() -> str:
    """Format the retry message for packet capture capabilities on Linux."""
    real_python_executable = os.path.realpath(sys.executable)
    return (
        'Packet capture permissions were not granted.\n\n'
        f'Command: sudo setcap cap_net_raw,cap_net_admin=eip {real_python_executable}\n\n'
        'If you have granted permissions, click Retry.\n'
        'Otherwise, click Cancel to exit.'
    )


def ensure_libpcap_installed() -> None:
    """Ensure that libpcap is installed and capture permissions are granted on Linux."""
    if not is_libpcap_installed():
        msgbox.show(
            title=TITLE,
            text=LIBPCAP_REQUIRED_MESSAGE,
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
        )

        while not is_libpcap_installed():
            result = msgbox.show(
                title=TITLE,
                text=LIBPCAP_INSTALLATION_CHECK_MESSAGE,
                style=msgbox.Style.MB_RETRYCANCEL | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND | msgbox.Style.MB_DEFBUTTON1,
            )

            if result == msgbox.ReturnValues.IDCANCEL:
                sys.exit(1)
            elif result == msgbox.ReturnValues.IDRETRY:
                continue

    if not can_capture_packets_on_linux():
        msgbox.show(
            title=TITLE,
            text=get_linux_permissions_required_message(),
            style=msgbox.Style.MB_OK | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
        )

        while not can_capture_packets_on_linux():
            result = msgbox.show(
                title=TITLE,
                text=get_linux_permissions_check_message(),
                style=msgbox.Style.MB_RETRYCANCEL | msgbox.Style.MB_ICONWARNING | msgbox.Style.MB_SETFOREGROUND | msgbox.Style.MB_DEFBUTTON1,
            )

            if result == msgbox.ReturnValues.IDCANCEL:
                sys.exit(1)
            elif result == msgbox.ReturnValues.IDRETRY:
                continue


def is_npcap_installed() -> bool:
    """Check if the capture driver is installed and accessible on the system."""
    if sys.platform != 'win32':
        return can_capture_packets_on_linux()

    creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        subprocess.run(NPCAP_SERVICE_QUERY_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10, creationflags=creationflags)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.debug('Npcap service query failed: %s', e)
        return False

    return True


def open_npcap_download_page() -> None:
    """Open the official Npcap download page in the web browser."""
    webbrowser.open(NPCAP_DOWNLOAD_URL)


def ensure_npcap_installed() -> None:
    """Ensure that the capture driver is installed. If not, show instructions and wait for user to install manually."""
    if sys.platform != 'win32':
        ensure_libpcap_installed()
        return

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
