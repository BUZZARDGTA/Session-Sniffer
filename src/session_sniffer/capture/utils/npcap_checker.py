"""Npcap Checker Module.

This module provides a utility function to check whether Npcap is installed on the system.
Npcap is required for network packet capturing in Windows environments.
"""

import contextlib
import enum
import logging
import os
import shlex
import socket
import struct
import subprocess
import sys
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path

if sys.platform == 'win32':
    import winreg

with contextlib.suppress(ImportError):
    import posix

from session_sniffer.capture.pcap import can_open_pcap_device, is_pcap_library_available
from session_sniffer.capture.process import iter_running_processes
from session_sniffer.capture.utils.ctypes_win32 import is_npcap_setup_window_visible, is_service_running
from session_sniffer.error_messages import format_npcap_required_message
from session_sniffer.guis.dependency_prompt_dialog import show_dependency_prompt
from session_sniffer.utils import is_pyinstaller_compiled, run_elevated_powershell_command

logger = logging.getLogger(__name__)

NPCAP_DOWNLOAD_URL = 'https://npcap.com/#download'
_NPCAP_ADAPTERS_KEY = r'SYSTEM\CurrentControlSet\Services\npcap\Parameters\Adapters'
_NPCAP_NDIS_ADAPTERS_KEY = r'SYSTEM\CurrentControlSet\Services\npcap\Parameters\NdisAdapters'
_GUID_BODY_LENGTH = 36
_HEX_GUID_CHARS = frozenset('0123456789ABCDEF-')
_attempted_binding_guids: set[str] = set()

LIBPCAP_REQUIRED_MESSAGE = (
    'Session Sniffer requires libpcap on Linux to capture packets.\n\n'
    'Please install it using your package manager, for example:\n'
    '  sudo apt install libpcap0.8'
)


def is_libpcap_installed() -> bool:
    """Check if the libpcap shared library is installed on the system."""
    return is_pcap_library_available()


_AF_PACKET = getattr(socket, 'AF_PACKET', 17)
_LINUX_CAP_XATTR_NAME = 'security.capability'
_LINUX_VFS_CAP_FLAGS_EFFECTIVE = 0x000001
_LINUX_CAP_NET_ADMIN_BIT = 1 << 12
_LINUX_CAP_NET_RAW_BIT = 1 << 13
_LINUX_CAP_SYS_PTRACE_BIT = 1 << 19
_LINUX_VFS_CAP_MIN_HEADER_SIZE = 8


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


def _has_linux_executable_file_capabilities() -> bool:
    """Return whether the executable on disk has the required Linux file capabilities set."""
    if sys.platform == 'win32':
        return False
    real_executable = os.path.realpath(sys.executable)
    cap_bytes = b''
    try:
        cap_bytes = posix.getxattr(real_executable, _LINUX_CAP_XATTR_NAME)
    except (AttributeError, OSError):
        return False
    if len(cap_bytes) < _LINUX_VFS_CAP_MIN_HEADER_SIZE:
        return False
    magic_etc, permitted_low = struct.unpack_from('<II', cap_bytes)
    if not magic_etc & _LINUX_VFS_CAP_FLAGS_EFFECTIVE:
        return False
    required_mask = _LINUX_CAP_NET_RAW_BIT | _LINUX_CAP_NET_ADMIN_BIT
    if is_pyinstaller_compiled():
        required_mask |= _LINUX_CAP_SYS_PTRACE_BIT
    return bool((permitted_low & required_mask) == required_mask)


def _spawn_relaunch_process() -> subprocess.Popen[bytes]:
    """Spawn a detached process for relaunching with newly granted Linux file capabilities."""
    command = [sys.executable, *sys.argv[1:]] if is_pyinstaller_compiled() else (sys.orig_argv or [sys.executable, *sys.argv])
    return subprocess.Popen(
        command,
        cwd=str(Path(sys.executable).parent) if is_pyinstaller_compiled() else None,
        env={**os.environ, 'PYINSTALLER_RESET_ENVIRONMENT': '1'},
        close_fds=True,
    )


def _relaunch_with_linux_capabilities() -> None:
    """Relaunch the current process so newly granted Linux file capabilities take effect."""
    _spawn_relaunch_process()
    os._exit(0)


def get_linux_permissions_required_message() -> str:
    """Format the message explaining the required packet capture capabilities on Linux."""
    real_executable = shlex.quote(os.path.realpath(sys.executable))
    if is_pyinstaller_compiled():
        return (
            'Session Sniffer requires root privileges or packet capture capabilities to capture network traffic on Linux.\n\n'
            'To grant the required capabilities to the executable without running as root, execute:\n'
            f'  sudo setcap cap_net_raw,cap_net_admin,cap_sys_ptrace=eip {real_executable}\n\n'
            'Alternatively, run Session Sniffer with root privileges:\n'
            f'  sudo {real_executable}'
        )
    return (
        'Session Sniffer requires root privileges or the CAP_NET_RAW capability to capture network traffic on Linux.\n\n'
        'To grant the required capability to Python without running as root, execute:\n'
        f'  sudo setcap cap_net_raw,cap_net_admin=eip {real_executable}\n\n'
        'Alternatively, run Session Sniffer with root privileges:\n'
        '  sudo -E env PATH=$PATH python3 -m session_sniffer'
    )


def can_capture_packets_on_darwin() -> bool:
    """Check whether the current process has permission to open BPF capture devices on macOS."""
    if not is_libpcap_installed():
        return False
    for index in range(16):
        bpf_device = Path(f'/dev/bpf{index}')
        if bpf_device.exists() and os.access(bpf_device, os.R_OK | os.W_OK):
            return True
    return False


def get_darwin_permissions_required_message() -> str:
    """Format the message explaining the required BPF capture device permissions on macOS."""
    return (
        'Session Sniffer requires read and write permissions to BPF packet capture devices (/dev/bpf*) on macOS.\n\n'
        'To grant capture permissions to BPF devices, run the following in Terminal:\n'
        '  sudo chmod 666 /dev/bpf*\n\n'
        "Alternatively, install Wireshark's 'ChmodBPF' package to retain BPF permissions across reboots."
    )


def ensure_darwin_capture_ready() -> None:
    """Ensure that libpcap is available and BPF capture permissions are granted on macOS."""
    if not is_libpcap_installed() and not show_dependency_prompt(
        title='libpcap Required',
        message='Session Sniffer requires libpcap on macOS to capture packets.\n\nPlease verify that libpcap is present in /usr/lib.',
        condition=is_libpcap_installed,
        status_callback=_get_libpcap_status,
    ):
        sys.exit(1)

    if not can_capture_packets_on_darwin() and not show_dependency_prompt(
        title='Capture Permissions Required',
        message=get_darwin_permissions_required_message(),
        condition=can_capture_packets_on_darwin,
        status_callback=_get_darwin_permissions_status,
    ):
        sys.exit(1)


def ensure_libpcap_installed() -> None:
    """Ensure that libpcap is installed and capture permissions are granted on Linux."""
    if not is_libpcap_installed() and not show_dependency_prompt(
        title='libpcap Required',
        message=LIBPCAP_REQUIRED_MESSAGE,
        condition=is_libpcap_installed,
        status_callback=_get_libpcap_status,
    ):
        sys.exit(1)

    if can_capture_packets_on_linux():
        return

    had_file_caps_initially = _has_linux_executable_file_capabilities()

    def _is_linux_capture_ready() -> bool:
        return can_capture_packets_on_linux() or (not had_file_caps_initially and _has_linux_executable_file_capabilities())

    def _get_status() -> tuple[str, str]:
        if can_capture_packets_on_linux():
            return 'Capture permissions verified!', 'Resuming Session Sniffer…'
        if not had_file_caps_initially and _has_linux_executable_file_capabilities():
            return 'Capture permissions verified!', 'Restarting Session Sniffer…'
        return _get_linux_permissions_status()

    if not show_dependency_prompt(
        title='Capture Permissions Required',
        message=get_linux_permissions_required_message(),
        condition=_is_linux_capture_ready,
        status_callback=_get_status,
    ):
        sys.exit(1)

    if not can_capture_packets_on_linux():
        _relaunch_with_linux_capabilities()


def _is_npcap_setup_in_progress() -> bool:
    """Check if an Npcap installer process or setup window is currently active."""
    if sys.platform != 'win32':
        return False

    if is_npcap_setup_window_visible():
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
    if sys.platform == 'win32':
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


def _is_npcap_service_running() -> bool:
    """Check if the npcap kernel driver service is currently active and running with throttling."""
    if sys.platform != 'win32':
        return False

    now = time.monotonic()
    if (now - _tracker.last_service_query_time) < SERVICE_STEP_MIN_DURATION_SECONDS:
        return _tracker.last_service_query_result

    _tracker.last_service_query_time = now
    is_running = is_service_running('npcap')
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


def _get_darwin_permissions_status() -> tuple[str, str]:
    """Return dynamic status for macOS packet capture permissions."""
    if can_capture_packets_on_darwin():
        return ('Capture permissions verified!', 'Resuming Session Sniffer…')
    return ('Listening for BPF device permissions…', 'Run "sudo chmod 666 /dev/bpf*" in Terminal to grant permissions.')


def get_npcap_status() -> tuple[str, str]:
    """Return the current dynamic installation status in chronological order with minimum step durations."""
    if sys.platform == 'darwin':
        return _get_darwin_permissions_status()
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
    if sys.platform == 'darwin':
        return can_capture_packets_on_darwin()
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
    if sys.platform == 'darwin':
        ensure_darwin_capture_ready()
        return
    if sys.platform != 'win32':
        ensure_libpcap_installed()
        return

    if is_npcap_installed():
        return

    _tracker.reset()

    if not show_dependency_prompt(
        title='Npcap Driver Required',
        message=format_npcap_required_message(),
        condition=is_npcap_installed,
        status_callback=get_npcap_status,
        action=('Open Download Page', open_npcap_download_page),
    ):
        sys.exit(1)


def _normalize_adapter_guid(adapter_guid: str) -> str | None:
    """Validate and normalize an adapter GUID string to uppercase '{...}' format."""
    cleaned = adapter_guid.strip().strip('{}').upper()
    if len(cleaned) != _GUID_BODY_LENGTH or any(ch not in _HEX_GUID_CHARS for ch in cleaned):
        return None
    return f'{{{cleaned}}}'


def extract_npcap_device_guid(device_name: str) -> str | None:
    r"""Extract the normalized '{GUID}' from an Npcap device name such as '\Device\NPF_{...}'."""
    prefix = '\\Device\\NPF_'
    idx = device_name.find(prefix)
    if idx != -1:
        return _normalize_adapter_guid(device_name[idx + len(prefix) :])
    return _normalize_adapter_guid(device_name)


def _has_registry_subkey(parent_key_path: str, subkey_name: str) -> bool:
    r"""Return whether a subkey exists under HKLM\<parent_key_path>."""
    if sys.platform == 'win32':
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f'{parent_key_path}\\{subkey_name}'):
                return True
        except OSError:
            return False
    return False


def is_npcap_adapter_bound(adapter_guid: str) -> bool:
    """Return whether the Npcap NDIS filter driver is currently bound to the given adapter GUID."""
    if sys.platform != 'win32':
        return True
    normalized = _normalize_adapter_guid(adapter_guid)
    if normalized is None:
        return True
    return _has_registry_subkey(_NPCAP_ADAPTERS_KEY, normalized)


def is_ndis_adapter_registered(adapter_guid: str) -> bool:
    """Return whether the adapter GUID is registered in Npcap's known NDIS adapters list."""
    if sys.platform != 'win32':
        return False
    normalized = _normalize_adapter_guid(adapter_guid)
    if normalized is None:
        return False
    return _has_registry_subkey(_NPCAP_NDIS_ADAPTERS_KEY, normalized)


def reset_npcap_binding_repair_attempts() -> None:
    """Clear the set of adapter GUIDs for which automatic Npcap binding repair was already attempted."""
    _attempted_binding_guids.clear()


def try_enable_npcap_adapter_binding(adapter_guid: str, *, device_name: str | None = None) -> bool:
    """Attempt to enable the 'INSECURE_NPCAP' NDIS filter binding on the given adapter GUID.

    When the current process is already elevated, runs the PowerShell cmdlet directly.
    Otherwise, requests elevation via ShellExecuteExW ('runas') at most once per adapter GUID
    until reset_npcap_binding_repair_attempts() is called.
    """
    if sys.platform != 'win32':
        return False
    normalized = _normalize_adapter_guid(adapter_guid)
    if normalized is None or normalized in _attempted_binding_guids:
        return False

    _attempted_binding_guids.add(normalized)
    logger.info(
        'Npcap driver binding is disabled on adapter %s (%s) — attempting to enable INSECURE_NPCAP binding...',
        device_name or normalized,
        normalized,
    )
    ps_command = (
        f"Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -eq '{normalized}' }} "
        "| Enable-NetAdapterBinding -ComponentID 'INSECURE_NPCAP' -Confirm:$false -ErrorAction Stop"
    )
    if not run_elevated_powershell_command(ps_command):
        return False

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if is_npcap_adapter_bound(normalized) and (device_name is None or can_open_pcap_device(device_name)):
            logger.info('Successfully enabled Npcap driver binding on capture adapter %s.', device_name or normalized)
            return True
        time.sleep(0.1)
    return is_npcap_adapter_bound(normalized)


def ensure_npcap_adapter_bound(device_name: str) -> bool:
    """Ensure the Npcap NDIS filter driver is bound to the adapter for *device_name*, attempting repair if disabled."""
    if sys.platform != 'win32':
        return True
    adapter_guid = extract_npcap_device_guid(device_name)
    if adapter_guid is None or is_npcap_adapter_bound(adapter_guid) or not is_ndis_adapter_registered(adapter_guid):
        return True
    return try_enable_npcap_adapter_binding(adapter_guid, device_name=device_name)
