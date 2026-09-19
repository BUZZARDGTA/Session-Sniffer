"""Npcap Checker Module.

This module provides a utility function to check whether Npcap is installed on the system.
Npcap is required for network packet capturing in Windows environments.
"""

import ctypes
import enum
import os
import socket
import subprocess
import sys
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path

if sys.platform == 'win32':
    import winreg
    from ctypes import wintypes
else:
    winreg = None  # type: ignore[assignment]  # pylint: disable=invalid-name
    wintypes = None  # type: ignore[assignment]  # pylint: disable=invalid-name

# pylint: disable=wrong-import-position
from session_sniffer.capture.pcap import is_pcap_library_available
from session_sniffer.capture.process import iter_running_processes
from session_sniffer.constants.standard import SC_EXE
from session_sniffer.error_messages import format_npcap_required_message
from session_sniffer.guis.dependency_prompt_dialog import show_dependency_prompt
from session_sniffer.logging_setup import get_logger

# pylint: enable=wrong-import-position

logger = get_logger(__name__)

NPCAP_SERVICE_QUERY_CMD = (SC_EXE, 'query', 'npcap')
NPCAP_DOWNLOAD_URL = 'https://npcap.com/#download'

LIBPCAP_REQUIRED_MESSAGE = (
    'Session Sniffer requires libpcap on Linux to capture packets.\n\n'
    'Please install it using your package manager, for example:\n'
    '  sudo apt install libpcap0.8'
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
        '  sudo -E env PATH=$PATH python3 -m session_sniffer'
    )


def ensure_libpcap_installed() -> None:
    """Ensure that libpcap is installed and capture permissions are granted on Linux."""
    if not is_libpcap_installed() and not show_dependency_prompt(
        title='libpcap Required',
        message=LIBPCAP_REQUIRED_MESSAGE,
        condition=is_libpcap_installed,
        status_callback=_get_libpcap_status,
    ):
        sys.exit(1)

    if not can_capture_packets_on_linux() and not show_dependency_prompt(
        title='Capture Permissions Required',
        message=get_linux_permissions_required_message(),
        condition=can_capture_packets_on_linux,
        status_callback=_get_linux_permissions_status,
    ):
        sys.exit(1)


def _is_npcap_setup_window_visible() -> bool:
    """Check if any visible window belongs to the Npcap setup wizard."""
    if sys.platform != 'win32' or wintypes is None:
        return False

    found = False
    window_enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def enum_windows_callback(hwnd: wintypes.HWND, _lparam: wintypes.LPARAM) -> bool:
        nonlocal found
        if not ctypes.windll.user32.IsWindowVisible(hwnd):
            return True
        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            title_buffer = ctypes.create_unicode_buffer(length + 1)
            ctypes.windll.user32.GetWindowTextW(hwnd, title_buffer, length + 1)
            title = title_buffer.value.lower()
            if 'npcap' in title and 'setup' in title:
                found = True
                return False
        return True

    ctypes.windll.user32.EnumWindows(window_enum_proc(enum_windows_callback), 0)
    return found


def _is_npcap_setup_in_progress() -> bool:
    """Check if an Npcap installer process or setup window is currently active."""
    if sys.platform != 'win32':
        return False

    if _is_npcap_setup_window_visible():
        return True

    for _pid, process_name in iter_running_processes():
        lowered_name = process_name.lower()
        if lowered_name.startswith('npcap') and lowered_name.endswith('.exe'):
            return True
        if lowered_name == 'npfinstall.exe':
            return True

    return False


def _is_npcap_registry_installed() -> bool:
    """Check if Npcap installation entry is recorded in the Windows registry."""
    if sys.platform != 'win32' or winreg is None:
        return False

    for subkey in (
        r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst',
    ):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ):
                return True
        except OSError:
            continue

    return False


def _is_npcap_files_present() -> bool:
    """Check if Npcap driver library files are present on the filesystem."""
    system_root = os.environ.get('WINDIR', 'C:\\Windows')
    wpcap_path = Path(system_root) / 'System32' / 'Npcap' / 'wpcap.dll'
    return wpcap_path.is_file()


def _is_npcap_files_or_registry_present() -> bool:
    """Check if Npcap binaries or registry entries are present on the system."""
    return _is_npcap_registry_installed() or _is_npcap_files_present()


SETUP_STEP_MIN_DURATION_SECONDS = 6.0
SERVICE_STEP_MIN_DURATION_SECONDS = 3.0


class _InstallStep(enum.IntEnum):
    """Chronological installation step identifiers."""

    LISTENING = 0
    SETUP_IN_PROGRESS = 1
    TESTING_REGISTRY = 2
    TESTING_SERVICE = 3
    WAITING_FOR_CLOSE = 4
    VERIFIED = 5


@dataclass
class _NpcapInstallTracker:
    """Track chronological Npcap installation step progression and query throttling."""

    step: _InstallStep = _InstallStep.LISTENING
    step_start_time: float = 0.0
    last_service_query_time: float = 0.0
    last_service_query_result: bool = False

    def reset(self) -> None:
        """Reset the installation tracker to initial state."""
        self.step = _InstallStep.LISTENING
        self.step_start_time = 0.0
        self.last_service_query_time = 0.0
        self.last_service_query_result = False


_tracker = _NpcapInstallTracker()


def _is_npcap_service_running(*, force: bool = False) -> bool:
    """Check if the npcap kernel driver service is currently active and running with throttling."""
    now = time.monotonic()
    if not force and (now - _tracker.last_service_query_time) < SERVICE_STEP_MIN_DURATION_SECONDS:
        return _tracker.last_service_query_result

    _tracker.last_service_query_time = now
    creationflags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        result = subprocess.run(
            NPCAP_SERVICE_QUERY_CMD,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
            creationflags=creationflags,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.debug('Npcap service query failed: %s', e)
        is_running = False
    else:
        is_running = 'RUNNING' in result.stdout or ' 4 ' in result.stdout

    _tracker.last_service_query_result = is_running
    return is_running


def _get_libpcap_status() -> tuple[str, str]:
    """Return dynamic status for libpcap installation on Linux."""
    if is_libpcap_installed():
        return 'libpcap detected!', 'Resuming Session Sniffer…'
    return 'Listening for installation…', 'Install libpcap via your package manager to continue.'


def _get_linux_permissions_status() -> tuple[str, str]:
    """Return dynamic status for Linux packet capture permissions."""
    if can_capture_packets_on_linux():
        return 'Capture permissions verified!', 'Resuming Session Sniffer…'
    return 'Listening for permissions…', 'Grant capture capabilities or run with elevated privileges.'


def get_npcap_status() -> tuple[str, str]:
    """Return the current dynamic installation status in chronological order with minimum step durations."""
    if sys.platform != 'win32':
        return _get_libpcap_status()

    now = time.monotonic()
    setup_active = _is_npcap_setup_in_progress()
    files_present = _is_npcap_files_present()
    registry_installed = _is_npcap_registry_installed()

    status: tuple[str, str]

    if _tracker.step == _InstallStep.LISTENING:
        if setup_active:
            _tracker.step = _InstallStep.SETUP_IN_PROGRESS
            _tracker.step_start_time = now
            status = ('Npcap setup in progress…', 'Waiting for installation to proceed in the setup wizard.')
        elif is_npcap_installed():
            status = ('Npcap driver verified!', 'Resuming Session Sniffer…')
        else:
            status = ('Listening for installation…', 'Download and run the Npcap installer from the official website.')

    else:
        elapsed = now - _tracker.step_start_time

        if _tracker.step == _InstallStep.SETUP_IN_PROGRESS:
            if not setup_active and not (files_present or registry_installed):
                _tracker.reset()
                status = ('Listening for installation…', 'Download and run the Npcap installer from the official website.')
            elif elapsed >= SETUP_STEP_MIN_DURATION_SECONDS and (files_present or registry_installed):
                _tracker.step = _InstallStep.TESTING_REGISTRY
                _tracker.step_start_time = now
                status = ('Testing registry path…', 'Driver files detected — waiting for registry configuration.')
            else:
                status = ('Npcap setup in progress…', 'Waiting for installation to proceed in the setup wizard.')

        elif _tracker.step == _InstallStep.TESTING_REGISTRY:
            if elapsed >= SETUP_STEP_MIN_DURATION_SECONDS and registry_installed:
                _tracker.step = _InstallStep.TESTING_SERVICE
                _tracker.step_start_time = now
                status = ('Testing driver service query…', 'Registry verified — waiting for the Npcap driver service to start.')
            else:
                status = ('Testing registry path…', 'Driver files detected — waiting for registry configuration.')

        elif _tracker.step == _InstallStep.TESTING_SERVICE:
            service_running = _is_npcap_service_running()
            if elapsed >= SERVICE_STEP_MIN_DURATION_SECONDS and service_running:
                if setup_active:
                    _tracker.step = _InstallStep.WAITING_FOR_CLOSE
                    _tracker.step_start_time = now
                    status = ('Installation detected — waiting for installer to close…', 'Click "Finish" to close the Npcap setup wizard and resume.')
                else:
                    _tracker.step = _InstallStep.VERIFIED
                    status = ('Npcap driver verified!', 'Resuming Session Sniffer…')
            else:
                status = ('Testing driver service query…', 'Registry verified — waiting for the Npcap driver service to start.')

        elif _tracker.step == _InstallStep.WAITING_FOR_CLOSE:
            if not setup_active:
                _tracker.step = _InstallStep.VERIFIED
                status = ('Npcap driver verified!', 'Resuming Session Sniffer…')
            else:
                status = ('Installation detected — waiting for installer to close…', 'Click "Finish" to close the Npcap setup wizard and resume.')

        else:
            status = ('Npcap driver verified!', 'Resuming Session Sniffer…')

    return status


def is_npcap_installed() -> bool:
    """Check if the capture driver is installed, running, and no setup wizard is in progress."""
    if sys.platform != 'win32':
        return can_capture_packets_on_linux()

    if _is_npcap_setup_in_progress():
        return False

    if not _is_npcap_files_or_registry_present():
        return False

    if not _is_npcap_service_running():
        return False

    return is_pcap_library_available()


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

    _tracker.reset()
    open_npcap_download_page()

    if not show_dependency_prompt(
        title='Npcap Driver Required',
        message=format_npcap_required_message(),
        condition=is_npcap_installed,
        status_callback=get_npcap_status,
        action=('Open Download Page', open_npcap_download_page),
    ):
        sys.exit(1)
