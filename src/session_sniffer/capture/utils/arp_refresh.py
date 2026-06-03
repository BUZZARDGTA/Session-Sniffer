"""Utilities to repopulate the Windows ARP cache via ICMP probes.

The Interface Selection dialog uses these helpers to give the user a "Refresh
ARP Table" action that wakes up devices on the local subnet(s) so that
recently plugged-in or idle devices show up as ARP neighbors.
"""

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from threading import Lock
from typing import TYPE_CHECKING

from session_sniffer.capture.utils.ctypes_win32 import get_system32_dir
from session_sniffer.logging_setup import get_logger
from session_sniffer.networking.utils import is_valid_private_ipv4

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from session_sniffer.networking.interface import Interface

    ProgressCallback = Callable[[int, int, str], None]

logger = get_logger(__name__)


_SYSTEM32_DIR = get_system32_dir()
_PING_PATH = str(_SYSTEM32_DIR / 'PING.EXE')

_PING_TIMEOUT_MS = 50
_PING_FANOUT_WORKERS = 64
_SUBPROCESS_TIMEOUT_S = 5.0


def _ping_host(ip_address: str) -> None:
    """Send a single ICMP echo request to *ip_address* (best-effort)."""
    try:
        IPv4Address(ip_address)
    except AddressValueError:
        return
    with suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            [_PING_PATH, '-n', '1', '-w', str(_PING_TIMEOUT_MS), ip_address],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_SUBPROCESS_TIMEOUT_S,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )


def _collect_target_ips(interfaces: Iterable[Interface]) -> list[str]:
    """Collect unique host IPs to probe based on each interface's private IPv4 addresses.

    Assumes a /24 subnet for each detected private IPv4 (covers virtually all
    home/SOHO networks). Skips the host's own IP, the network address and
    the broadcast address.
    """
    own_ips: set[str] = set()
    targets: set[str] = set()

    for interface in interfaces:
        for ip_address in interface.ip_addresses:
            if not is_valid_private_ipv4(ip_address):
                continue
            try:
                own = IPv4Address(ip_address)
            except AddressValueError:
                continue
            own_ips.add(str(own))
            network = IPv4Network(f'{ip_address}/24', strict=False)
            for host in network.hosts():
                targets.add(str(host))

    return sorted(targets - own_ips)


def wake_subnet_devices(
    interfaces: Iterable[Interface],
    progress_callback: ProgressCallback | None = None,
) -> None:
    """Send ICMP probes across the local subnet(s) of *interfaces* to repopulate ARP.

    If *progress_callback* is provided it is invoked from worker threads as
    `progress_callback(completed, total)` after each ping completes.
    """
    target_ips = _collect_target_ips(interfaces)
    total = len(target_ips)
    if not target_ips:
        logger.info('ARP refresh: no private IPv4 subnets to probe.')
        if progress_callback is not None:
            progress_callback(0, 0, '')
        return

    logger.debug('ARP refresh: pinging %d hosts to repopulate ARP cache.', total)
    completed = 0
    completed_lock = Lock()
    with ThreadPoolExecutor(max_workers=_PING_FANOUT_WORKERS, thread_name_prefix='ARPRefreshPing') as executor:
        future_to_ip = {executor.submit(_ping_host, ip): ip for ip in target_ips}
        for future in as_completed(future_to_ip):
            future.result()
            if progress_callback is None:
                continue
            ip = future_to_ip[future]
            with completed_lock:
                completed += 1
                current = completed
            progress_callback(current, total, ip)


def refresh_arp_table(
    interfaces: Iterable[Interface],
    progress_callback: ProgressCallback | None = None,
) -> None:
    """Probe local subnets to repopulate the ARP cache via ICMP.

    If *progress_callback* is provided it is invoked from worker threads with
    `(completed, total)` updates while pings run.
    """
    interfaces_list = list(interfaces)
    wake_subnet_devices(interfaces_list, progress_callback)
