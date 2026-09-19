"""Npcap Checker Module.

This module provides a utility function to check whether Npcap is installed on the system.
Npcap is required for network packet capturing in Windows environments.
"""

import os
import socket
import subprocess
import sys
import webbrowser

from session_sniffer import msgbox
from session_sniffer.capture.pcap import is_pcap_library_available
from session_sniffer.constants.standalone import TITLE
from session_sniffer.constants.standard import SC_EXE
from session_sniffer.error_messages import format_npcap_required_message
from session_sniffer.logging_setup import get_logger
from session_sniffer.text_utils import format_triple_quoted_text

logger = get_logger(__name__)

NPCAP_SERVICE_QUERY_CMD = (SC_EXE, 'query', 'npcap')
NPCAP_DOWNLOAD_URL = 'https://npcap.com/#download'

LIBPCAP_REQUIRED_MESSAGE = (
    'Session Sniffer requires libpcap on Linux to capture packets.\n\n'
    'Please install it using your package manager, for example:\n'
    '  sudo apt install libpcap0.8\n\n'
    'Waiting for installation to complete... The application will resume automatically once libpcap is detected.'
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
        'Waiting for permissions to be granted... The application will resume automatically once permissions are detected.'
    )


def ensure_libpcap_installed() -> None:
    """Ensure that libpcap is installed and capture permissions are granted on Linux."""
    if not is_libpcap_installed() and not msgbox.show_until(
        title=TITLE,
        text=LIBPCAP_REQUIRED_MESSAGE,
        condition=is_libpcap_installed,
        style=msgbox.Style.MB_OKCANCEL | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
    ):
        sys.exit(1)

    if not can_capture_packets_on_linux() and not msgbox.show_until(
        title=TITLE,
        text=get_linux_permissions_required_message(),
        condition=can_capture_packets_on_linux,
        style=msgbox.Style.MB_OKCANCEL | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
    ):
        sys.exit(1)


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

    if not msgbox.show_until(
        title=TITLE,
        text=format_triple_quoted_text(format_npcap_required_message()),
        condition=is_npcap_installed,
        style=msgbox.Style.MB_OKCANCEL | msgbox.Style.MB_ICONINFORMATION | msgbox.Style.MB_SETFOREGROUND,
    ):
        sys.exit(1)
