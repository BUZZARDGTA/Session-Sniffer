"""This script retrieves network adapter information on Windows."""
import ctypes
import socket
from ctypes import wintypes
from dataclasses import field
from typing import TYPE_CHECKING, cast

from pydantic.dataclasses import dataclass

if TYPE_CHECKING:
    from collections.abc import Iterator


class GetAdaptersAddressesError(OSError):
    """Exception raised when GetAdaptersAddresses fails."""

    def __init__(self, error_code: int) -> None:
        """Initialize the exception with the error code."""
        super().__init__(f'GetAdaptersAddresses failed with error code: {error_code}')


@dataclass(frozen=True, kw_only=True, slots=True)
class AdapterData:  # pylint: disable=too-many-instance-attributes
    interface_index:    int
    friendly_name:      str
    description:        str
    mac_address:        str | None
    ipv4_addresses:     list[str]
    operational_status: int
    ip_enabled:         bool
    packets_sent:       int
    packets_recv:       int
    neighbors:          list[tuple[str | None, str | None]] = field(
        default_factory=lambda: cast('list[tuple[str | None, str | None]]', []),
    )


# Constants
WORKING_BUFFER_SIZE = 15000
AF_INET = 2

GAA_FLAG_SKIP_UNICAST = 0x0001  # Do not return unicast addresses.
GAA_FLAG_SKIP_ANYCAST = 0x0002  # Do not return IPv6 anycast addresses.
GAA_FLAG_SKIP_MULTICAST = 0x0004  # Do not return multicast addresses.
GAA_FLAG_SKIP_DNS_SERVER = 0x0008  # Do not return addresses of DNS servers.
GAA_FLAG_INCLUDE_PREFIX = 0x0010
IP_ADAPTER_FLAG_IPV4_ENABLED = 0x0080  # IPv4 is enabled on this adapter
MAX_ADAPTER_ADDRESS_LENGTH = 8
ERROR_BUFFER_OVERFLOW = 111
ERROR_SUCCESS = 0
IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32
ERROR_INSUFFICIENT_BUFFER = 122


# Structures
class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):  # noqa: N801  # pylint: disable=invalid-name,too-few-public-methods
    pass


class IP_ADAPTER_ADDRESSES(ctypes.Structure):  # noqa: N801  # pylint: disable=invalid-name,too-few-public-methods
    pass


class _OPER_STATUS_FLAGS(ctypes.Structure):  # noqa: N801  # pylint: disable=invalid-name,too-few-public-methods
    _fields_ = [  # noqa: RUF012
        ('HardwareInterface', ctypes.c_ubyte, 1),
        ('FilterInterface', ctypes.c_ubyte, 1),
        ('ConnectorPresent', ctypes.c_ubyte, 1),
        ('NotAuthenticated', ctypes.c_ubyte, 1),
        ('NotMediaConnected', ctypes.c_ubyte, 1),
        ('Paused', ctypes.c_ubyte, 1),
        ('LowPower', ctypes.c_ubyte, 1),
        ('EndPointInterface', ctypes.c_ubyte, 1),
    ]


class SOCKET_ADDRESS(ctypes.Structure):  # noqa: N801  # pylint: disable=invalid-name,too-few-public-methods
    _fields_ = [  # noqa: RUF012
        ('lpSockaddr', ctypes.c_void_p),
        ('iSockaddrLength', ctypes.c_int),
    ]


LP_IP_ADAPTER_UNICAST_ADDRESS = ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)
LP_IP_ADAPTER_ADDRESSES = ctypes.POINTER(IP_ADAPTER_ADDRESSES)


# pylint: disable=protected-access
IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ('Length', wintypes.ULONG),
    ('Flags', wintypes.DWORD),
    ('Next', LP_IP_ADAPTER_UNICAST_ADDRESS),
    ('Address', SOCKET_ADDRESS),
    # ... skipping the rest for brevity
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
    # ... skipping the rest for brevity
]
# pylint: enable=protected-access


class MIB_IF_ROW2(ctypes.Structure):  # noqa: N801  # pylint: disable=invalid-name,too-few-public-methods
    _fields_ = [  # noqa: RUF012
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


class SOCKADDR_IN(ctypes.Structure):  # noqa: N801  # pylint: disable=invalid-name,too-few-public-methods
    _fields_ = [  # noqa: RUF012
        ('sin_family', wintypes.USHORT),
        ('sin_port', wintypes.USHORT),
        ('sin_addr', ctypes.c_uint32),
        ('sin_zero', ctypes.c_char * 8),
    ]


# Windows API
GetAdaptersAddresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
GetAdaptersAddresses.argtypes = [
    wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p,
    LP_IP_ADAPTER_ADDRESSES, ctypes.POINTER(wintypes.ULONG),
]
GetAdaptersAddresses.restype = wintypes.ULONG

GetIfEntry2 = ctypes.windll.Iphlpapi.GetIfEntry2
GetIfEntry2.argtypes = [ctypes.POINTER(MIB_IF_ROW2)]
GetIfEntry2.restype = wintypes.ULONG


# =========================
# Neighbor ("Neighborhood")
# =========================

class MIB_IPNETROW(ctypes.Structure):  # noqa: N801  # pylint: disable=invalid-name,too-few-public-methods
    """IPv4 neighbor table row (classic ARP style for IPv4)."""

    _fields_ = [  # noqa: RUF012
        ('dwIndex', wintypes.DWORD),
        ('dwPhysAddrLen', wintypes.DWORD),
        ('bPhysAddr', ctypes.c_ubyte * 8),
        ('dwAddr', wintypes.DWORD),
        ('dwType', wintypes.DWORD),
    ]


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


def _sockaddr_to_ipv4(sockaddr_ptr: int) -> str | None:
    """Converts a sockaddr pointer to an IPv4 address if applicable.

    :param sockaddr_ptr: A pointer to a sockaddr_in structure.
    :return: IPv4 address as a string or None if not IPv4.
    """
    # Explicitly cast sockaddr_ptr to a ctypes pointer of SOCKADDR_IN
    sockaddr = ctypes.cast(sockaddr_ptr, ctypes.POINTER(SOCKADDR_IN)).contents

    if sockaddr.sin_family == socket.AF_INET:
        return socket.inet_ntoa(sockaddr.sin_addr.to_bytes(4, 'little'))
    return None


def iterate_ipv4_neighbors() -> Iterator[tuple[int, str | None, str | None]]:
    """Yield IPv4 neighbor entries (interface index, IPv4, link-layer MAC).

    This uses Windows IP Helper API `GetIpNetTable` and returns tuples of:
        - InterfaceIndex (int)
        - IPv4Address (str | None)
        - MacAddress (str | None)

    Returns an empty iterator if the table cannot be retrieved.
    """
    size = wintypes.ULONG(0)
    ret = _get_ip_net_table(None, ctypes.byref(size))
    if ret not in (ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS):
        return

    if size.value == 0:  # pylint: disable=compare-to-zero
        return

    buf = ctypes.create_string_buffer(size.value)
    ret = _get_ip_net_table(buf, ctypes.byref(size))
    if ret != ERROR_SUCCESS:
        return

    # First DWORD is number of entries
    num_entries = ctypes.cast(buf, ctypes.POINTER(wintypes.DWORD)).contents.value
    if num_entries == 0:  # pylint: disable=compare-to-zero
        return

    # Rows start right after the first DWORD
    base = ctypes.addressof(buf)
    header_size = ctypes.sizeof(wintypes.DWORD)
    row_size = ctypes.sizeof(MIB_IPNETROW)

    for i in range(num_entries):
        row_ptr = ctypes.cast(base + header_size + i * row_size, ctypes.POINTER(MIB_IPNETROW))
        row = row_ptr.contents

        # IPv4 address in little-endian DWORD
        ipv4 = socket.inet_ntoa(int(row.dwAddr).to_bytes(4, 'little'))

        # Format MAC if present
        mac_address = (
            None if row.dwPhysAddrLen == 0  # pylint: disable=use-implicit-booleaness-not-comparison-to-zero
            else ':'.join(f'{b:02X}' for b in row.bPhysAddr[: row.dwPhysAddrLen])
        )

        yield int(row.dwIndex), ipv4, mac_address


def get_adapters_info() -> Iterator[AdapterData]:
    """Retrieves information for all network adapters.

    :return: An iterator of `AdapterData` objects containing network adapter information.
    """
    # Build neighbor map once to attach per adapter
    neighbors_by_if: dict[int, list[tuple[str | None, str | None]]] = {}

    for if_index, ip, mac in iterate_ipv4_neighbors():
        neighbors_by_if.setdefault(int(if_index), []).append((ip, mac))

    size = wintypes.ULONG(WORKING_BUFFER_SIZE)
    while True:
        buf = ctypes.create_string_buffer(size.value)
        ret = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_PREFIX,
            None,
            ctypes.cast(buf, LP_IP_ADAPTER_ADDRESSES),
            ctypes.byref(size),
        )
        if ret == ERROR_BUFFER_OVERFLOW:
            continue
        if ret != ERROR_SUCCESS:
            raise GetAdaptersAddressesError(ret)
        break

    adapter = ctypes.cast(buf, LP_IP_ADAPTER_ADDRESSES)
    while adapter:
        addr = adapter.contents

        # Handle multiple MAC addresses (if any)
        mac_address = (
            None if addr.PhysicalAddressLength == 0  # pylint: disable=use-implicit-booleaness-not-comparison-to-zero
            else ':'.join(f'{b:02X}' for b in addr.PhysicalAddress[:addr.PhysicalAddressLength])
        )
        ipv4_list: list[str] = []

        # Handle multiple IPv4 addresses
        uni = addr.FirstUnicastAddress
        while uni:
            ip = _sockaddr_to_ipv4(uni.contents.Address.lpSockaddr)
            if ip:
                ipv4_list.append(ip)
            uni = uni.contents.Next

        # Query MIB_IF_ROW2 by index
        row = MIB_IF_ROW2()
        row.InterfaceIndex = addr.IfIndex  # pylint: disable=attribute-defined-outside-init,invalid-name
        if GetIfEntry2(ctypes.byref(row)) != ERROR_SUCCESS:
            packets_sent = packets_recv = 0
        else:
            packets_sent = row.OutUcastPkts + row.OutNUcastPkts
            packets_recv = row.InUcastPkts + row.InNUcastPkts

        yield AdapterData(
            interface_index=addr.IfIndex,
            friendly_name=addr.FriendlyName,
            description=addr.Description,
            mac_address=mac_address,
            ipv4_addresses=ipv4_list,
            operational_status=addr.OperStatus,
            ip_enabled=bool(addr.Flags & IP_ADAPTER_FLAG_IPV4_ENABLED),
            packets_sent=packets_sent,
            packets_recv=packets_recv,
            neighbors=neighbors_by_if.get(int(addr.IfIndex), []),
        )

        adapter = ctypes.cast(addr.Next, LP_IP_ADAPTER_ADDRESSES)
