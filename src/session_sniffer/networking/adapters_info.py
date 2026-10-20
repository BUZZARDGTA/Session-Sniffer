"""Cross-platform network adapter and IPv4 neighbor retrieval for Windows, Linux, and macOS."""

import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from session_sniffer.networking.adapter_types import (
    AdapterData,
    AdapterIdentity,
    AdapterStatus,
    AdapterTraffic,
)
from session_sniffer.networking.ctypes_adapters_info import (
    iter_win32_adapters_addresses,
    iter_win32_ip_net_table,
    query_darwin_ifaddrs,
    query_linux_ifaddrs,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

# OperStatus values
IF_OPER_STATUS_UP = 1
IF_OPER_STATUS_NOT_PRESENT = 6

# MediaConnectState values
MEDIA_CONNECT_STATE_CONNECTED = 1
MEDIA_CONNECT_STATE_DISCONNECTED = 2

# Windows Network Adapter State constant
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
NETWORK_ADAPTER_DISABLED = 3

_ARP_MIN_FIELD_COUNT = 6
_ROUTE_MIN_FIELD_COUNT = 3
_MAC_OCTETS_COUNT = 6
_MIN_NETSTAT_ROUTE_FIELDS = 4

_DARWIN_ARP_REGEX = re.compile(r'^\S+\s+\((?P<ip>[0-9.]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+)\s+on\s+(?P<interface>[a-zA-Z0-9]+)')
_DARWIN_ARP_EXECUTABLE = '/usr/sbin/arp'
_DARWIN_NETSTAT_EXECUTABLE = '/usr/sbin/netstat'


def _iterate_ipv4_neighbors_darwin() -> Iterator[tuple[int, str | None, str | None]]:
    """Yield IPv4 neighbor entries on macOS by querying the ARP table."""
    try:
        arp_executable = shutil.which('arp') or _DARWIN_ARP_EXECUTABLE
        process = subprocess.run(
            [arp_executable, '-an'],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return

    for line in process.stdout.splitlines():
        match = _DARWIN_ARP_REGEX.search(line.strip())
        if not match:
            continue
        ip_address = str(match.group('ip'))
        raw_mac = str(match.group('mac'))
        interface_name = str(match.group('interface'))

        mac_parts = raw_mac.split(':')
        if len(mac_parts) != _MAC_OCTETS_COUNT:
            continue
        try:
            mac_address = ':'.join(f'{int(part, 16):02X}' for part in mac_parts)
        except ValueError:
            continue

        try:
            interface_index = socket.if_nametoindex(interface_name)
        except OSError:
            interface_index = 0

        yield interface_index, ip_address, mac_address


def _iterate_ipv4_neighbors_linux() -> Iterator[tuple[int, str | None, str | None]]:
    try:
        with Path('/proc/net/arp').open(encoding='ascii') as arp_file:
            arp_lines = arp_file.readlines()
    except OSError:
        return

    for line in arp_lines[1:]:
        parts = line.split()
        if len(parts) >= _ARP_MIN_FIELD_COUNT:
            ip_address, _hw_type, flags, mac_address, _mask, device_name = parts[:6]
            if flags != '0x0' and mac_address != '00:00:00:00:00:00':
                try:
                    interface_index = socket.if_nametoindex(device_name)
                except OSError:
                    interface_index = 0
                yield interface_index, ip_address, mac_address.upper()


def iterate_ipv4_neighbors() -> Iterator[tuple[int, str | None, str | None]]:
    """Yield IPv4 neighbor entries (interface index, IPv4, link-layer MAC).

    Uses Windows IP Helper API `GetIpNetTable` on Windows, `/proc/net/arp` on Linux,
    or `arp -an` on macOS.
    """
    if sys.platform == 'darwin':
        yield from _iterate_ipv4_neighbors_darwin()
    elif sys.platform == 'win32':
        yield from iter_win32_ip_net_table()
    else:
        yield from _iterate_ipv4_neighbors_linux()


def _read_sys_file(path: Path) -> str:
    try:
        return path.read_text(encoding='ascii').strip()
    except OSError:
        return ''


def _read_sys_int(path: Path) -> int:
    try:
        return int(path.read_text(encoding='ascii').strip())
    except (OSError, ValueError):
        return 0


def _get_linux_adapters_info() -> Iterator[AdapterData]:
    """Retrieve network adapter information on Linux systems."""
    neighbors_by_interface_index: dict[int, list[tuple[str | None, str | None]]] = {}
    for interface_index, ip_address, mac_address in iterate_ipv4_neighbors():
        neighbors_by_interface_index.setdefault(interface_index, []).append((ip_address, mac_address))

    gateways_by_interface_name: dict[str, list[str]] = {}
    try:
        with Path('/proc/net/route').open(encoding='ascii') as route_file:
            for line in route_file.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) >= _ROUTE_MIN_FIELD_COUNT and fields[1] == '00000000':
                    gateway_hex = fields[2]
                    try:
                        gateway_integer = int(gateway_hex, 16)
                        if gateway_integer:
                            gateway_ip = socket.inet_ntoa(gateway_integer.to_bytes(4, 'little'))
                            gateways_by_interface_name.setdefault(fields[0], []).append(gateway_ip)
                    except (ValueError, OSError):
                        pass
    except OSError:
        pass

    ipv4_by_interface_name = query_linux_ifaddrs()

    try:
        interface_list = socket.if_nameindex()
    except OSError:
        return

    net_path = Path('/sys/class/net')
    for interface_index, interface_name in interface_list:
        interface_sys_dir = net_path / interface_name

        mac_text = _read_sys_file(interface_sys_dir / 'address')
        mac_address = mac_text.upper() if mac_text and mac_text != '00:00:00:00:00:00' else None

        operstate = _read_sys_file(interface_sys_dir / 'operstate').lower()
        is_up = operstate == 'up'

        packets_sent = _read_sys_int(interface_sys_dir / 'statistics' / 'tx_packets')
        packets_recv = _read_sys_int(interface_sys_dir / 'statistics' / 'rx_packets')
        link_speed_mbps = _read_sys_int(interface_sys_dir / 'speed')
        link_speed_bps = link_speed_mbps * 1_000_000 if link_speed_mbps > 0 else 0

        interface_ipv4_list = ipv4_by_interface_name.get(interface_name, [])
        interface_gateways = gateways_by_interface_name.get(interface_name, [])
        interface_neighbors = neighbors_by_interface_index.get(interface_index, [])

        yield AdapterData(
            identity=AdapterIdentity(
                interface_index=interface_index,
                friendly_name=interface_name,
                description=interface_name,
                mac_address=mac_address,
                adapter_guid=interface_name,
            ),
            status=AdapterStatus(
                operational_status=IF_OPER_STATUS_UP if is_up else IF_OPER_STATUS_NOT_PRESENT,
                ip_enabled=bool(interface_ipv4_list),
                media_connect_state=MEDIA_CONNECT_STATE_CONNECTED if is_up else MEDIA_CONNECT_STATE_DISCONNECTED,
            ),
            traffic=AdapterTraffic(
                packets_sent=packets_sent,
                packets_recv=packets_recv,
                transmit_link_speed=link_speed_bps,
                receive_link_speed=link_speed_bps,
            ),
            ipv4_addresses=interface_ipv4_list,
            gateway_addresses=interface_gateways,
            neighbors=interface_neighbors,
        )


def _get_darwin_gateways_by_interface() -> dict[str, list[str]]:
    """Retrieve default IPv4 gateways grouped by interface name on macOS."""
    gateways_by_interface_name: dict[str, list[str]] = {}
    try:
        netstat_executable = shutil.which('netstat') or _DARWIN_NETSTAT_EXECUTABLE
        process = subprocess.run(
            [netstat_executable, '-rn', '-f', 'inet'],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return gateways_by_interface_name

    for line in process.stdout.splitlines():
        fields = line.strip().split()
        if len(fields) >= _MIN_NETSTAT_ROUTE_FIELDS and fields[0] == 'default':
            gateway_ip = fields[1]
            interface_name = fields[3]
            try:
                socket.inet_aton(gateway_ip)
            except OSError:
                continue
            gateways_by_interface_name.setdefault(interface_name, []).append(gateway_ip)

    return gateways_by_interface_name


def _get_darwin_adapters_info() -> Iterator[AdapterData]:
    """Retrieve network adapter information on macOS systems."""
    neighbors_by_interface_index: dict[int, list[tuple[str | None, str | None]]] = {}
    for interface_index, ip_address, mac_address in _iterate_ipv4_neighbors_darwin():
        neighbors_by_interface_index.setdefault(interface_index, []).append((ip_address, mac_address))

    gateways_by_interface_name = _get_darwin_gateways_by_interface()
    (
        ipv4_by_interface_name,
        mac_by_interface_name,
        status_by_interface_name,
        traffic_by_interface_name,
    ) = query_darwin_ifaddrs()

    try:
        interface_list = socket.if_nameindex()
    except OSError:
        return

    for interface_index, interface_name in interface_list:
        mac_address = mac_by_interface_name.get(interface_name)
        is_up = status_by_interface_name.get(interface_name, False)
        packets_sent, packets_recv, link_speed_bps = traffic_by_interface_name.get(interface_name, (0, 0, 0))

        interface_ipv4_list = ipv4_by_interface_name.get(interface_name, [])
        interface_gateways = gateways_by_interface_name.get(interface_name, [])
        interface_neighbors = neighbors_by_interface_index.get(interface_index, [])

        yield AdapterData(
            identity=AdapterIdentity(
                interface_index=interface_index,
                friendly_name=interface_name,
                description=interface_name,
                mac_address=mac_address,
                adapter_guid=interface_name,
            ),
            status=AdapterStatus(
                operational_status=IF_OPER_STATUS_UP if is_up else IF_OPER_STATUS_NOT_PRESENT,
                ip_enabled=bool(interface_ipv4_list),
                media_connect_state=MEDIA_CONNECT_STATE_CONNECTED if is_up else MEDIA_CONNECT_STATE_DISCONNECTED,
            ),
            traffic=AdapterTraffic(
                packets_sent=packets_sent,
                packets_recv=packets_recv,
                transmit_link_speed=link_speed_bps,
                receive_link_speed=link_speed_bps,
            ),
            ipv4_addresses=interface_ipv4_list,
            gateway_addresses=interface_gateways,
            neighbors=interface_neighbors,
        )


def get_adapters_info() -> Iterator[AdapterData]:
    """Retrieve information for all network adapters across Windows, Linux, and macOS."""
    if sys.platform == 'darwin':
        yield from _get_darwin_adapters_info()
        return
    if sys.platform != 'win32':
        yield from _get_linux_adapters_info()
        return

    neighbors_by_if: dict[int, list[tuple[str | None, str | None]]] = {}
    for if_index, ip, mac in iterate_ipv4_neighbors():
        neighbors_by_if.setdefault(if_index, []).append((ip, mac))

    for raw_adapter in iter_win32_adapters_addresses():
        interface_index, friendly_name, description, mac_address, adapter_guid = raw_adapter[:5]
        operational_status, ip_enabled, media_connect_state = raw_adapter[5:8]
        packets_sent, packets_recv, transmit_link_speed, receive_link_speed = raw_adapter[8:12]
        ipv4_list, gateway_list = raw_adapter[12], raw_adapter[13]
        yield AdapterData(
            identity=AdapterIdentity(
                interface_index=interface_index,
                friendly_name=friendly_name,
                description=description,
                mac_address=mac_address,
                adapter_guid=adapter_guid,
            ),
            status=AdapterStatus(
                operational_status=operational_status,
                ip_enabled=ip_enabled,
                media_connect_state=media_connect_state,
            ),
            traffic=AdapterTraffic(
                packets_sent=packets_sent,
                packets_recv=packets_recv,
                transmit_link_speed=transmit_link_speed,
                receive_link_speed=receive_link_speed,
            ),
            ipv4_addresses=ipv4_list,
            gateway_addresses=gateway_list,
            neighbors=neighbors_by_if.get(interface_index, []),
        )
