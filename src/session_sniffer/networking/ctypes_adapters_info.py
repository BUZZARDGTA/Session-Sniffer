"""Network adapter information retrieval for Windows, Linux, and macOS."""

import ctypes
import re
import shutil
import socket
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING

from session_sniffer.networking.adapter_types import AdapterData, AdapterIdentity, AdapterStatus, AdapterTraffic, GetAdaptersAddressesError

if TYPE_CHECKING:
    from collections.abc import Iterator


# Constants
WORKING_BUFFER_SIZE = 15000
AF_INET = 2

GAA_FLAG_SKIP_ANYCAST = 0x0002  # Do not return IPv6 anycast addresses.
GAA_FLAG_SKIP_MULTICAST = 0x0004  # Do not return multicast addresses.
GAA_FLAG_SKIP_DNS_SERVER = 0x0008  # Do not return addresses of DNS servers.
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080  # Include gateway addresses in results.
IP_ADAPTER_IPV4_ENABLED = 0x0080  # IPv4 is enabled on this adapter
MAX_ADAPTER_ADDRESS_LENGTH = 8
ERROR_BUFFER_OVERFLOW = 111
ERROR_SUCCESS = 0
IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_DATA = 232

# OperStatus values (export only what's used externally)
IF_OPER_STATUS_UP = 1  # Interface is up and operational
IF_OPER_STATUS_NOT_PRESENT = 6  # Interface is not present

# MediaConnectState values
MEDIA_CONNECT_STATE_UNKNOWN = 0  # Unknown connection state
MEDIA_CONNECT_STATE_CONNECTED = 1  # Media is connected
MEDIA_CONNECT_STATE_DISCONNECTED = 2  # Media is disconnected

_ARP_MIN_FIELD_COUNT = 6
_ROUTE_MIN_FIELD_COUNT = 3
_MAC_OCTETS_COUNT = 6
_MIN_NETSTAT_ROUTE_FIELDS = 4

_DARWIN_ARP_REGEX = re.compile(r'^\S+\s+\((?P<ip>[0-9.]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+)\s+on\s+(?P<interface>[a-zA-Z0-9]+)')
_DARWIN_AF_LINK = 18
_DARWIN_AF_INET = 2
_DARWIN_ARP_EXECUTABLE = '/usr/sbin/arp'
_DARWIN_NETSTAT_EXECUTABLE = '/usr/sbin/netstat'
_IFF_UP = 0x1
_IFF_RUNNING = 0x40

# Windows Network Adapter State constant
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/hh968170(v=vs.85)
NETWORK_ADAPTER_DISABLED = 3


# Structures
class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    """ctypes definition for a Windows IP_ADAPTER_UNICAST_ADDRESS structure."""


class IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
    """ctypes definition for a Windows IP_ADAPTER_GATEWAY_ADDRESS_LH structure."""


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """ctypes definition for a Windows IP_ADAPTER_ADDRESSES structure."""


class _OPER_STATUS_FLAGS(ctypes.Structure):
    _fields_ = [
        ('HardwareInterface', ctypes.c_ubyte, 1),
        ('FilterInterface', ctypes.c_ubyte, 1),
        ('ConnectorPresent', ctypes.c_ubyte, 1),
        ('NotAuthenticated', ctypes.c_ubyte, 1),
        ('NotMediaConnected', ctypes.c_ubyte, 1),
        ('Paused', ctypes.c_ubyte, 1),
        ('LowPower', ctypes.c_ubyte, 1),
        ('EndPointInterface', ctypes.c_ubyte, 1),
    ]


class SOCKET_ADDRESS(ctypes.Structure):
    """ctypes definition for a Windows SOCKET_ADDRESS structure."""

    _fields_ = [
        ('lpSockaddr', ctypes.c_void_p),
        ('iSockaddrLength', ctypes.c_int),
    ]


LP_IP_ADAPTER_UNICAST_ADDRESS = ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)
LP_IP_ADAPTER_GATEWAY_ADDRESS = ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)
LP_IP_ADAPTER_ADDRESSES = ctypes.POINTER(IP_ADAPTER_ADDRESSES)


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ('Length', wintypes.ULONG),
    ('Flags', wintypes.DWORD),
    ('Next', LP_IP_ADAPTER_UNICAST_ADDRESS),
    ('Address', SOCKET_ADDRESS),
    # ... skipping the rest for brevity
]


IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
    ('Length', wintypes.ULONG),
    ('Reserved', wintypes.DWORD),
    ('Next', LP_IP_ADAPTER_GATEWAY_ADDRESS),
    ('Address', SOCKET_ADDRESS),
]


IP_ADAPTER_ADDRESSES._fields_ = [
    ('Length', wintypes.ULONG),
    ('IfIndex', wintypes.DWORD),
    ('Next', LP_IP_ADAPTER_ADDRESSES),
    ('AdapterName', ctypes.c_char_p),
    ('FirstUnicastAddress', LP_IP_ADAPTER_UNICAST_ADDRESS),
    ('FirstAnycastAddress', ctypes.c_void_p),
    ('FirstMulticastAddress', ctypes.c_void_p),
    ('FirstDnsServerAddress', ctypes.c_void_p),
    ('DnsSuffix', wintypes.LPWSTR),
    ('Description', wintypes.LPWSTR),
    ('FriendlyName', wintypes.LPWSTR),
    ('PhysicalAddress', ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
    ('PhysicalAddressLength', wintypes.DWORD),
    ('Flags', wintypes.DWORD),
    ('Mtu', wintypes.DWORD),
    ('IfType', wintypes.DWORD),
    ('OperStatus', wintypes.DWORD),
    ('Ipv6IfIndex', wintypes.DWORD),
    ('ZoneIndices', wintypes.ULONG * 16),
    ('FirstPrefix', ctypes.c_void_p),
    ('TransmitLinkSpeed', ctypes.c_uint64),
    ('ReceiveLinkSpeed', ctypes.c_uint64),
    ('FirstWinsServerAddress', ctypes.c_void_p),
    ('FirstGatewayAddress', LP_IP_ADAPTER_GATEWAY_ADDRESS),
    # ... skipping the rest for brevity
]


class MIB_IF_ROW2(ctypes.Structure):
    """ctypes definition for a Windows MIB_IF_ROW2 structure."""

    _fields_ = [
        ('InterfaceLuid', ctypes.c_uint64),
        ('InterfaceIndex', wintypes.DWORD),
        ('InterfaceGuid', ctypes.c_byte * 16),
        ('Alias', wintypes.WCHAR * (IF_MAX_STRING_SIZE + 1)),
        ('Description', wintypes.WCHAR * (IF_MAX_STRING_SIZE + 1)),
        ('PhysicalAddressLength', wintypes.ULONG),
        ('PhysicalAddress', ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ('PermanentPhysicalAddress', ctypes.c_ubyte * IF_MAX_PHYS_ADDRESS_LENGTH),
        ('Mtu', wintypes.ULONG),
        ('Type', wintypes.ULONG),
        ('TunnelType', wintypes.ULONG),
        ('MediaType', wintypes.ULONG),
        ('PhysicalMediumType', wintypes.ULONG),
        ('AccessType', wintypes.ULONG),
        ('DirectionType', wintypes.ULONG),
        ('InterfaceAndOperStatusFlags', _OPER_STATUS_FLAGS),
        ('OperStatus', wintypes.ULONG),
        ('AdminStatus', wintypes.ULONG),
        ('MediaConnectState', wintypes.ULONG),
        ('NetworkGuid', ctypes.c_byte * 16),
        ('ConnectionType', wintypes.ULONG),
        ('TransmitLinkSpeed', ctypes.c_uint64),
        ('ReceiveLinkSpeed', ctypes.c_uint64),
        ('InOctets', ctypes.c_uint64),
        ('InUcastPkts', ctypes.c_uint64),
        ('InNUcastPkts', ctypes.c_uint64),
        ('InDiscards', ctypes.c_uint64),
        ('InErrors', ctypes.c_uint64),
        ('InUnknownProtos', ctypes.c_uint64),
        ('InUcastOctets', ctypes.c_uint64),
        ('InMulticastOctets', ctypes.c_uint64),
        ('InBroadcastOctets', ctypes.c_uint64),
        ('OutOctets', ctypes.c_uint64),
        ('OutUcastPkts', ctypes.c_uint64),
        ('OutNUcastPkts', ctypes.c_uint64),
        ('OutDiscards', ctypes.c_uint64),
        ('OutErrors', ctypes.c_uint64),
        ('OutUcastOctets', ctypes.c_uint64),
        ('OutMulticastOctets', ctypes.c_uint64),
        ('OutBroadcastOctets', ctypes.c_uint64),
        ('OutQLen', ctypes.c_uint64),
    ]


class SOCKADDR_IN(ctypes.Structure):
    """ctypes definition for a Windows IPv4 sockaddr_in structure."""

    _fields_ = [
        ('sin_family', wintypes.USHORT),
        ('sin_port', wintypes.USHORT),
        ('sin_addr', ctypes.c_uint32),
        ('sin_zero', ctypes.c_char * 8),
    ]


if sys.platform == 'win32':
    # Windows API
    GetAdaptersAddresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
    GetAdaptersAddresses.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        LP_IP_ADAPTER_ADDRESSES,
        ctypes.POINTER(wintypes.ULONG),
    ]
    GetAdaptersAddresses.restype = wintypes.ULONG

    GetIfEntry2 = ctypes.windll.Iphlpapi.GetIfEntry2
    GetIfEntry2.argtypes = [ctypes.POINTER(MIB_IF_ROW2)]
    GetIfEntry2.restype = wintypes.ULONG


# =========================
# Neighbor / Neighborhood
# =========================


class MIB_IPNETROW(ctypes.Structure):
    """IPv4 neighbor table row (classic ARP style for IPv4)."""

    _fields_ = [
        ('dwIndex', wintypes.DWORD),
        ('dwPhysAddrLen', wintypes.DWORD),
        ('bPhysAddr', ctypes.c_ubyte * 8),
        ('dwAddr', wintypes.DWORD),
        ('dwType', wintypes.DWORD),
    ]


if sys.platform == 'win32':
    # GetIpNetTable returns a buffer with a DWORD count followed by an array of MIB_IPNETROW
    GetIpNetTable = ctypes.windll.iphlpapi.GetIpNetTable
    GetIpNetTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    GetIpNetTable.restype = wintypes.ULONG


def _get_ip_net_table(buf: object, size_ptr: object) -> int:
    """Call GetIpNetTable with required BOOL positional argument.

    Using a wrapper avoids false-positive lints about boolean positional args.
    """
    order_flag = wintypes.BOOL(0)
    return int(GetIpNetTable(buf, size_ptr, order_flag))


def _sockaddr_to_ipv4(sockaddr_ptr: int | None) -> str | None:
    """Converts a sockaddr pointer to an IPv4 address if applicable.

    Args:
        sockaddr_ptr: A pointer to a sockaddr_in structure.

    Returns:
        The IPv4 address as a string, or `None` if the sockaddr is not IPv4.
    """
    if sockaddr_ptr is None or not sockaddr_ptr:
        return None

    # Explicitly cast sockaddr_ptr to a ctypes pointer of SOCKADDR_IN
    sockaddr = ctypes.cast(sockaddr_ptr, ctypes.POINTER(SOCKADDR_IN)).contents

    if sockaddr.sin_family == socket.AF_INET:
        return socket.inet_ntoa(sockaddr.sin_addr.to_bytes(4, 'little'))
    return None


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


def _iterate_ipv4_neighbors_windows() -> Iterator[tuple[int, str | None, str | None]]:
    size = wintypes.ULONG(0)
    ret = _get_ip_net_table(None, ctypes.byref(size))
    if ret not in (ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS):
        return

    if not size.value:
        return

    buf = ctypes.create_string_buffer(size.value)
    ret = _get_ip_net_table(buf, ctypes.byref(size))
    if ret != ERROR_SUCCESS:
        return

    num_entries = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
    if not num_entries:
        return

    base = ctypes.addressof(buf)
    header_size = ctypes.sizeof(wintypes.DWORD)
    row_size = ctypes.sizeof(MIB_IPNETROW)
    max_entries = (size.value - header_size) // row_size
    valid_entries = min(num_entries, max_entries)

    for i in range(valid_entries):
        row_ptr = ctypes.cast(base + header_size + i * row_size, ctypes.POINTER(MIB_IPNETROW))
        row = row_ptr.contents
        ipv4 = socket.inet_ntoa(int(row.dwAddr).to_bytes(4, 'little'))
        mac_address = None if not row.dwPhysAddrLen else ':'.join(f'{byte:02X}' for byte in row.bPhysAddr[: row.dwPhysAddrLen])
        yield int(row.dwIndex), ipv4, mac_address


def iterate_ipv4_neighbors() -> Iterator[tuple[int, str | None, str | None]]:
    """Yield IPv4 neighbor entries (interface index, IPv4, link-layer MAC).

    This uses Windows IP Helper API `GetIpNetTable` on Windows, `/proc/net/arp` on Linux,
    or `arp -an` on macOS, and returns tuples of:
        - InterfaceIndex (int)
        - IPv4Address (str | None)
        - MacAddress (str | None)

    Returns an empty iterator if the table cannot be retrieved.
    """
    if sys.platform == 'darwin':
        yield from _iterate_ipv4_neighbors_darwin()
    elif sys.platform == 'win32':
        yield from _iterate_ipv4_neighbors_windows()
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


class _LinuxSockaddr(ctypes.Structure):
    _fields_ = [('sa_family', ctypes.c_ushort), ('sa_data', ctypes.c_char * 14)]


class _LinuxSockaddrIn(ctypes.Structure):
    _fields_ = [('sin_family', ctypes.c_ushort), ('sin_port', ctypes.c_ushort), ('sin_addr', ctypes.c_uint32)]


class _LinuxIfAddrs(ctypes.Structure):
    pass


_LinuxIfAddrs._fields_ = [
    ('ifa_next', ctypes.POINTER(_LinuxIfAddrs)),
    ('ifa_name', ctypes.c_char_p),
    ('ifa_flags', ctypes.c_uint),
    ('ifa_addr', ctypes.POINTER(_LinuxSockaddr)),
    ('ifa_netmask', ctypes.POINTER(_LinuxSockaddr)),
    ('ifa_ifu', ctypes.c_void_p),
    ('ifa_data', ctypes.c_void_p),
]


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

    ipv4_by_interface_name: dict[str, list[str]] = {}
    try:
        libc = ctypes.CDLL(None)
        libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_LinuxIfAddrs))]
        libc.getifaddrs.restype = ctypes.c_int
        libc.freeifaddrs.argtypes = [ctypes.POINTER(_LinuxIfAddrs)]
        libc.freeifaddrs.restype = None

        ifaddrs_pointer = ctypes.POINTER(_LinuxIfAddrs)()
        if not libc.getifaddrs(ctypes.byref(ifaddrs_pointer)):
            current_address = ifaddrs_pointer
            while current_address:
                address_entry = current_address.contents
                if address_entry.ifa_name:
                    interface_name_str = address_entry.ifa_name.decode('utf-8', errors='replace')
                    if address_entry.ifa_addr and address_entry.ifa_addr.contents.sa_family == socket.AF_INET:
                        sockaddr_in = ctypes.cast(address_entry.ifa_addr, ctypes.POINTER(_LinuxSockaddrIn)).contents
                        ip_string = socket.inet_ntoa(sockaddr_in.sin_addr.to_bytes(4, 'little'))
                        ipv4_by_interface_name.setdefault(interface_name_str, []).append(ip_string)
                current_address = address_entry.ifa_next
            libc.freeifaddrs(ifaddrs_pointer)
    except (OSError, AttributeError):
        pass

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


class _DarwinSockaddr(ctypes.Structure):
    _fields_ = [
        ('sa_len', ctypes.c_uint8),
        ('sa_family', ctypes.c_uint8),
        ('sa_data', ctypes.c_char * 14),
    ]


class _DarwinSockaddrIn(ctypes.Structure):
    _fields_ = [
        ('sin_len', ctypes.c_uint8),
        ('sin_family', ctypes.c_uint8),
        ('sin_port', ctypes.c_uint16),
        ('sin_addr', ctypes.c_uint32),
        ('sin_zero', ctypes.c_char * 8),
    ]


class _DarwinSockaddrDl(ctypes.Structure):
    _fields_ = [
        ('sdl_len', ctypes.c_uint8),
        ('sdl_family', ctypes.c_uint8),
        ('sdl_index', ctypes.c_uint16),
        ('sdl_type', ctypes.c_uint8),
        ('sdl_nlen', ctypes.c_uint8),
        ('sdl_alen', ctypes.c_uint8),
        ('sdl_slen', ctypes.c_uint8),
        ('sdl_data', ctypes.c_char * 24),
    ]


class _DarwinIfData64(ctypes.Structure):
    _fields_ = [
        ('ifi_type', ctypes.c_uint8),
        ('ifi_typelen', ctypes.c_uint8),
        ('ifi_physical', ctypes.c_uint8),
        ('ifi_addrlen', ctypes.c_uint8),
        ('ifi_hdrlen', ctypes.c_uint8),
        ('ifi_recvquota', ctypes.c_uint8),
        ('ifi_xmitquota', ctypes.c_uint8),
        ('ifi_unused1', ctypes.c_uint8),
        ('ifi_mtu', ctypes.c_uint32),
        ('ifi_metric', ctypes.c_uint32),
        ('ifi_baudrate', ctypes.c_uint64),
        ('ifi_ipackets', ctypes.c_uint64),
        ('ifi_ierrors', ctypes.c_uint64),
        ('ifi_opackets', ctypes.c_uint64),
        ('ifi_oerrors', ctypes.c_uint64),
        ('ifi_collisions', ctypes.c_uint64),
        ('ifi_ibytes', ctypes.c_uint64),
        ('ifi_obytes', ctypes.c_uint64),
    ]


class _DarwinIfAddrs(ctypes.Structure):
    pass


_DarwinIfAddrs._fields_ = [
    ('ifa_next', ctypes.POINTER(_DarwinIfAddrs)),
    ('ifa_name', ctypes.c_char_p),
    ('ifa_flags', ctypes.c_uint),
    ('ifa_addr', ctypes.POINTER(_DarwinSockaddr)),
    ('ifa_netmask', ctypes.POINTER(_DarwinSockaddr)),
    ('ifa_ifu', ctypes.c_void_p),
    ('ifa_data', ctypes.c_void_p),
]


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


def _populate_darwin_ifaddr(
    address_entry: _DarwinIfAddrs,
    ipv4_by_interface_name: dict[str, list[str]],
    mac_by_interface_name: dict[str, str | None],
    status_by_interface_name: dict[str, bool],
    traffic_by_interface_name: dict[str, tuple[int, int, int]],
) -> None:
    if not address_entry.ifa_name:
        return
    interface_name_string = address_entry.ifa_name.decode('utf-8', errors='replace')
    status_by_interface_name[interface_name_string] = bool(address_entry.ifa_flags & _IFF_UP)

    if address_entry.ifa_addr:
        sa_family = address_entry.ifa_addr.contents.sa_family
        if sa_family == _DARWIN_AF_INET:
            sockaddr_in = ctypes.cast(address_entry.ifa_addr, ctypes.POINTER(_DarwinSockaddrIn)).contents
            ip_string = socket.inet_ntoa(sockaddr_in.sin_addr.to_bytes(4, 'little'))
            ipv4_by_interface_name.setdefault(interface_name_string, []).append(ip_string)
        elif sa_family == _DARWIN_AF_LINK:
            sockaddr_dl = ctypes.cast(address_entry.ifa_addr, ctypes.POINTER(_DarwinSockaddrDl)).contents
            if sockaddr_dl.sdl_alen == _MAC_OCTETS_COUNT:
                raw_bytes = bytes(sockaddr_dl.sdl_data)[sockaddr_dl.sdl_nlen : sockaddr_dl.sdl_nlen + _MAC_OCTETS_COUNT]
                if any(raw_bytes):
                    mac_by_interface_name[interface_name_string] = ':'.join(f'{b:02X}' for b in raw_bytes)

    if address_entry.ifa_data:
        if_data = ctypes.cast(address_entry.ifa_data, ctypes.POINTER(_DarwinIfData64)).contents
        traffic_by_interface_name[interface_name_string] = (
            int(if_data.ifi_opackets),
            int(if_data.ifi_ipackets),
            int(if_data.ifi_baudrate),
        )


def _get_darwin_adapters_info() -> Iterator[AdapterData]:
    """Retrieve network adapter information on macOS systems."""
    neighbors_by_interface_index: dict[int, list[tuple[str | None, str | None]]] = {}
    for interface_index, ip_address, mac_address in _iterate_ipv4_neighbors_darwin():
        neighbors_by_interface_index.setdefault(interface_index, []).append((ip_address, mac_address))

    gateways_by_interface_name = _get_darwin_gateways_by_interface()

    ipv4_by_interface_name: dict[str, list[str]] = {}
    mac_by_interface_name: dict[str, str | None] = {}
    status_by_interface_name: dict[str, bool] = {}
    traffic_by_interface_name: dict[str, tuple[int, int, int]] = {}

    try:
        libc = ctypes.CDLL(None)
        libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(_DarwinIfAddrs))]
        libc.getifaddrs.restype = ctypes.c_int
        libc.freeifaddrs.argtypes = [ctypes.POINTER(_DarwinIfAddrs)]
        libc.freeifaddrs.restype = None

        ifaddrs_pointer = ctypes.POINTER(_DarwinIfAddrs)()
        if not libc.getifaddrs(ctypes.byref(ifaddrs_pointer)):
            current_address = ifaddrs_pointer
            while current_address:
                _populate_darwin_ifaddr(
                    current_address.contents,
                    ipv4_by_interface_name,
                    mac_by_interface_name,
                    status_by_interface_name,
                    traffic_by_interface_name,
                )
                current_address = current_address.contents.ifa_next
            libc.freeifaddrs(ifaddrs_pointer)
    except (OSError, AttributeError):
        pass

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
    """Retrieves information for all network adapters.

    Returns:
        An iterator of `AdapterData` objects containing network adapter information.
    """
    if sys.platform == 'darwin':
        yield from _get_darwin_adapters_info()
        return
    if sys.platform != 'win32':
        yield from _get_linux_adapters_info()
        return

    # Build neighbor map once to attach per adapter
    neighbors_by_if: dict[int, list[tuple[str | None, str | None]]] = {}

    for if_index, ip, mac in iterate_ipv4_neighbors():
        neighbors_by_if.setdefault(if_index, []).append((ip, mac))

    size = wintypes.ULONG(WORKING_BUFFER_SIZE)
    while True:
        buf = ctypes.create_string_buffer(size.value)
        ret = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS,
            None,
            ctypes.cast(buf, LP_IP_ADAPTER_ADDRESSES),
            ctypes.byref(size),
        )
        if ret == ERROR_BUFFER_OVERFLOW:
            continue
        if ret == ERROR_NO_DATA:
            return
        if ret != ERROR_SUCCESS:
            raise GetAdaptersAddressesError(ret)
        break

    adapter = ctypes.cast(buf, LP_IP_ADAPTER_ADDRESSES)
    while adapter:
        addr = adapter.contents

        # Handle multiple MAC addresses (if any)
        mac_address = None if not addr.PhysicalAddressLength else ':'.join(f'{byte:02X}' for byte in addr.PhysicalAddress[: addr.PhysicalAddressLength])
        ipv4_list: list[str] = []

        # Handle multiple IPv4 addresses
        uni = addr.FirstUnicastAddress
        while uni:
            ip = _sockaddr_to_ipv4(uni.contents.Address.lpSockaddr)
            if ip is not None and ip:
                ipv4_list.append(ip)
            uni = uni.contents.Next

        # Handle gateway addresses
        gateway_list: list[str] = []
        gw = addr.FirstGatewayAddress
        while gw:
            gw_ip = _sockaddr_to_ipv4(gw.contents.Address.lpSockaddr)
            if gw_ip is not None and gw_ip:
                gateway_list.append(gw_ip)
            gw = gw.contents.Next

        # Query MIB_IF_ROW2 by index
        row = MIB_IF_ROW2(InterfaceIndex=addr.IfIndex)
        if GetIfEntry2(ctypes.byref(row)) != ERROR_SUCCESS:
            packets_sent = packets_recv = 0
            media_connect_state = MEDIA_CONNECT_STATE_UNKNOWN
            transmit_link_speed = 0
            receive_link_speed = 0
        else:
            packets_sent = row.OutUcastPkts + row.OutNUcastPkts
            packets_recv = row.InUcastPkts + row.InNUcastPkts
            media_connect_state = row.MediaConnectState
            transmit_link_speed = row.TransmitLinkSpeed
            receive_link_speed = row.ReceiveLinkSpeed

        adapter_guid_raw = addr.AdapterName.decode('ascii', errors='ignore') if addr.AdapterName else None
        adapter_guid = adapter_guid_raw.upper() if adapter_guid_raw else None

        yield AdapterData(
            identity=AdapterIdentity(
                interface_index=addr.IfIndex,
                friendly_name=addr.FriendlyName,
                description=addr.Description,
                mac_address=mac_address,
                adapter_guid=adapter_guid,
            ),
            status=AdapterStatus(
                operational_status=addr.OperStatus,
                ip_enabled=bool(addr.Flags & IP_ADAPTER_IPV4_ENABLED),
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
            neighbors=neighbors_by_if.get(int(addr.IfIndex), []),
        )

        adapter = ctypes.cast(addr.Next, LP_IP_ADAPTER_ADDRESSES)
