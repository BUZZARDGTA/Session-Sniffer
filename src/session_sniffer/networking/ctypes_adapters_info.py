"""Low-level ctypes structures and bindings for network adapters, neighbors, WLAN, ICS COM, and ICMP."""

import ctypes
import functools
import logging
import socket
import sys
from ctypes import wintypes
from typing import TYPE_CHECKING, Final, cast

from session_sniffer.ctypes_windows import (
    WindowsGuid,
    clsid_from_progid,
    co_create_instance,
    co_initialize_ex,
    co_uninitialize,
    get_com_vtable_entry,
    query_com_interface,
    release_com_interface,
)
from session_sniffer.networking.adapter_types import GetAdaptersAddressesError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator

logger = logging.getLogger(__name__)

WORKING_BUFFER_SIZE = 15000
AF_INET = 2

GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
IP_ADAPTER_IPV4_ENABLED = 0x0080
MAX_ADAPTER_ADDRESS_LENGTH = 8
ERROR_BUFFER_OVERFLOW = 111
ERROR_SUCCESS = 0
IF_MAX_STRING_SIZE = 256
IF_MAX_PHYS_ADDRESS_LENGTH = 32
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_DATA = 232
MEDIA_CONNECT_STATE_UNKNOWN = 0

_MAC_OCTETS_COUNT = 6
_DARWIN_AF_LINK = 18
_DARWIN_AF_INET = 2
_IFF_UP = 0x1
_IP_REQ_TIMED_OUT = 11010

_IID_INET_SHARING_MANAGER = WindowsGuid(0xC08956B7, 0x1CD3, 0x11D1, (ctypes.c_ubyte * 8)(0xB1, 0xC5, 0x00, 0x80, 0x5F, 0xC1, 0x27, 0x0E))
_IID_IENUM_VARIANT = WindowsGuid(0x00020404, 0x0000, 0x0000, (ctypes.c_ubyte * 8)(0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46))
_INVALID_HANDLE_VALUE: Final[int] = cast('int', ctypes.c_void_p(-1).value)
_ACTIVE_MIB_CALLBACKS: dict[int, object] = {}


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
    ('PhysicalAddressLength', wintypes.ULONG),
    ('Flags', wintypes.ULONG),
    ('Mtu', wintypes.DWORD),
    ('IfType', wintypes.DWORD),
    ('OperStatus', wintypes.DWORD),
    ('Ipv6IfIndex', wintypes.DWORD),
    ('ZoneIndices', wintypes.DWORD * 16),
    ('FirstPrefix', ctypes.c_void_p),
    ('TransmitLinkSpeed', ctypes.c_uint64),
    ('ReceiveLinkSpeed', ctypes.c_uint64),
    ('FirstWinsServerAddress', ctypes.c_void_p),
    ('FirstGatewayAddress', LP_IP_ADAPTER_GATEWAY_ADDRESS),
]


class MIB_IF_ROW2(ctypes.Structure):
    """ctypes definition for a Windows MIB_IF_ROW2 structure."""

    _fields_ = [
        ('InterfaceLuid', ctypes.c_uint64),
        ('InterfaceIndex', wintypes.ULONG),
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
    """ctypes definition for an IPv4 socket address structure."""

    _fields_ = [
        ('sin_family', wintypes.USHORT),
        ('sin_port', wintypes.USHORT),
        ('sin_addr', ctypes.c_uint32),
        ('sin_zero', ctypes.c_char * 8),
    ]


class MIB_IPNETROW(ctypes.Structure):
    """IPv4 neighbor table row (classic ARP style for IPv4)."""

    _fields_ = [
        ('dwIndex', wintypes.DWORD),
        ('dwPhysAddrLen', wintypes.DWORD),
        ('bPhysAddr', ctypes.c_ubyte * 8),
        ('dwAddr', wintypes.DWORD),
        ('dwType', wintypes.DWORD),
    ]


class _IPOptionInformation(ctypes.Structure):
    """ctypes definition for IP_OPTION_INFORMATION structure."""

    _fields_ = [
        ('Ttl', ctypes.c_ubyte),
        ('Tos', ctypes.c_ubyte),
        ('Flags', ctypes.c_ubyte),
        ('OptionsSize', ctypes.c_ubyte),
        ('OptionsData', ctypes.c_void_p),
    ]


class _IcmpEchoReply(ctypes.Structure):
    """ctypes definition for ICMP_ECHO_REPLY structure."""

    _fields_ = [
        ('Address', ctypes.c_ulong),
        ('Status', ctypes.c_ulong),
        ('RoundTripTime', ctypes.c_ulong),
        ('DataSize', ctypes.c_ushort),
        ('Reserved', ctypes.c_ushort),
        ('Data', ctypes.c_void_p),
        ('Options', _IPOptionInformation),
    ]


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
        ('sdl_data', ctypes.c_ubyte * 24),
    ]


class _DarwinIfData(ctypes.Structure):
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
        ('ifi_baudrate', ctypes.c_uint32),
        ('ifi_ipackets', ctypes.c_uint32),
        ('ifi_ierrors', ctypes.c_uint32),
        ('ifi_opackets', ctypes.c_uint32),
        ('ifi_oerrors', ctypes.c_uint32),
        ('ifi_collisions', ctypes.c_uint32),
        ('ifi_ibytes', ctypes.c_uint32),
        ('ifi_obytes', ctypes.c_uint32),
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


if sys.platform == 'win32':
    _iphlpapi = ctypes.WinDLL('iphlpapi', use_last_error=True)

    GetAdaptersAddresses = _iphlpapi.GetAdaptersAddresses
    GetAdaptersAddresses.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        LP_IP_ADAPTER_ADDRESSES,
        ctypes.POINTER(wintypes.ULONG),
    ]
    GetAdaptersAddresses.restype = wintypes.ULONG

    GetIfEntry2 = _iphlpapi.GetIfEntry2
    GetIfEntry2.argtypes = [ctypes.POINTER(MIB_IF_ROW2)]
    GetIfEntry2.restype = wintypes.ULONG

    GetIpNetTable = _iphlpapi.GetIpNetTable
    GetIpNetTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
    GetIpNetTable.restype = wintypes.ULONG

    _IcmpCreateFile = _iphlpapi.IcmpCreateFile
    _IcmpCreateFile.argtypes = []
    _IcmpCreateFile.restype = ctypes.c_void_p

    _IcmpCloseHandle = _iphlpapi.IcmpCloseHandle
    _IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    _IcmpCloseHandle.restype = wintypes.BOOL

    _IcmpSendEcho = _iphlpapi.IcmpSendEcho
    _IcmpSendEcho.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.c_ushort,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _IcmpSendEcho.restype = wintypes.DWORD

    _MIB_CHANGE_CALLBACK_TYPE = ctypes.WINFUNCTYPE(
        None,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
    )

    _NotifyUnicastIpAddressChange = _iphlpapi.NotifyUnicastIpAddressChange
    _NotifyUnicastIpAddressChange.argtypes = [
        wintypes.USHORT,
        _MIB_CHANGE_CALLBACK_TYPE,
        ctypes.c_void_p,
        ctypes.c_ubyte,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _NotifyUnicastIpAddressChange.restype = wintypes.ULONG

    _NotifyIpInterfaceChange = _iphlpapi.NotifyIpInterfaceChange
    _NotifyIpInterfaceChange.argtypes = [
        wintypes.USHORT,
        _MIB_CHANGE_CALLBACK_TYPE,
        ctypes.c_void_p,
        ctypes.c_ubyte,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _NotifyIpInterfaceChange.restype = wintypes.ULONG

    _CancelMibChangeNotify2 = _iphlpapi.CancelMibChangeNotify2
    _CancelMibChangeNotify2.argtypes = [wintypes.HANDLE]
    _CancelMibChangeNotify2.restype = wintypes.ULONG

    _oleaut32 = ctypes.windll.oleaut32
    _oleaut32.SysFreeString.argtypes = [ctypes.c_wchar_p]
    _oleaut32.SysFreeString.restype = None
    _oleaut32.VariantClear.argtypes = [ctypes.c_void_p]
    _oleaut32.VariantClear.restype = wintypes.HRESULT


def _get_ip_net_table(buf: object, size_ptr: object) -> int:
    """Call GetIpNetTable with required BOOL positional argument."""
    order_flag = wintypes.BOOL(0)
    return int(GetIpNetTable(buf, size_ptr, order_flag))


def _ipv4_from_uint32_le(addr: int) -> str:
    """Convert a 32-bit IPv4 integer stored in network byte order within a little-endian integer to dotted quad."""
    return socket.inet_ntoa(addr.to_bytes(4, 'little'))


def _format_mac_octets(octets: Iterable[int]) -> str:
    """Format 6 raw MAC octets as uppercase colon-separated hex (`XX:XX:XX:XX:XX:XX`)."""
    return ':'.join(f'{byte:02X}' for byte in octets)


def _sockaddr_to_ipv4(sockaddr_ptr: int | None) -> str | None:
    """Convert a sockaddr pointer to an IPv4 address string if applicable."""
    if sockaddr_ptr is None or not sockaddr_ptr:
        return None
    sockaddr = ctypes.cast(sockaddr_ptr, ctypes.POINTER(SOCKADDR_IN)).contents
    if sockaddr.sin_family == socket.AF_INET:
        return _ipv4_from_uint32_le(sockaddr.sin_addr)
    return None


def iter_win32_ip_net_table() -> Iterator[tuple[int, str | None, str | None]]:
    """Yield (interface_index, ipv4_address, mac_address) from the Windows GetIpNetTable API."""
    if sys.platform != 'win32':
        return
    size = wintypes.ULONG(0)
    ret = _get_ip_net_table(None, ctypes.byref(size))
    if ret not in (ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS) or not size.value:
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
        ipv4 = _ipv4_from_uint32_le(row.dwAddr)
        mac_address = _format_mac_octets(row.bPhysAddr[:_MAC_OCTETS_COUNT]) if row.dwPhysAddrLen == _MAC_OCTETS_COUNT else None
        yield int(row.dwIndex), ipv4, mac_address


def query_linux_ifaddrs() -> dict[str, list[str]]:
    """Return a mapping of interface name -> IPv4 addresses on Linux via libc getifaddrs."""
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
                        ipv4_by_interface_name.setdefault(interface_name_str, []).append(_ipv4_from_uint32_le(sockaddr_in.sin_addr))
                current_address = address_entry.ifa_next
            libc.freeifaddrs(ifaddrs_pointer)
    except (OSError, AttributeError):
        pass
    return ipv4_by_interface_name


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
            ipv4_by_interface_name.setdefault(interface_name_string, []).append(_ipv4_from_uint32_le(sockaddr_in.sin_addr))
        elif sa_family == _DARWIN_AF_LINK:
            sockaddr_dl = ctypes.cast(address_entry.ifa_addr, ctypes.POINTER(_DarwinSockaddrDl)).contents
            name_length = int(sockaddr_dl.sdl_nlen)
            if sockaddr_dl.sdl_alen == _MAC_OCTETS_COUNT and name_length + _MAC_OCTETS_COUNT <= len(sockaddr_dl.sdl_data):
                raw_bytes = bytes(sockaddr_dl.sdl_data)[name_length : name_length + _MAC_OCTETS_COUNT]
                if any(raw_bytes):
                    mac_by_interface_name[interface_name_string] = _format_mac_octets(raw_bytes)

            if address_entry.ifa_data:
                if_data = ctypes.cast(address_entry.ifa_data, ctypes.POINTER(_DarwinIfData)).contents
                traffic_by_interface_name[interface_name_string] = (
                    int(if_data.ifi_opackets),
                    int(if_data.ifi_ipackets),
                    int(if_data.ifi_baudrate),
                )


def query_darwin_ifaddrs() -> tuple[
    dict[str, list[str]],
    dict[str, str | None],
    dict[str, bool],
    dict[str, tuple[int, int, int]],
]:
    """Query interface IPv4, MAC, up-status, and traffic counters on macOS via libc getifaddrs."""
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

    return (
        ipv4_by_interface_name,
        mac_by_interface_name,
        status_by_interface_name,
        traffic_by_interface_name,
    )


def iter_win32_adapters_addresses() -> Iterator[
    tuple[
        int,
        str,
        str,
        str | None,
        str | None,
        int,
        bool,
        int,
        int,
        int,
        int,
        int,
        list[str],
        list[str],
    ]
]:
    """Yield raw adapter tuples on Windows via GetAdaptersAddresses and GetIfEntry2."""
    if sys.platform != 'win32':
        return
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
        mac_address = (
            _format_mac_octets(addr.PhysicalAddress[:_MAC_OCTETS_COUNT])
            if addr.PhysicalAddressLength == _MAC_OCTETS_COUNT
            else None
        )
        ipv4_list: list[str] = []

        uni = addr.FirstUnicastAddress
        while uni:
            ip = _sockaddr_to_ipv4(uni.contents.Address.lpSockaddr)
            if ip is not None and ip:
                ipv4_list.append(ip)
            uni = uni.contents.Next

        gateway_list: list[str] = []
        gw = addr.FirstGatewayAddress
        while gw:
            gw_ip = _sockaddr_to_ipv4(gw.contents.Address.lpSockaddr)
            if gw_ip is not None and gw_ip:
                gateway_list.append(gw_ip)
            gw = gw.contents.Next

        row = MIB_IF_ROW2(InterfaceIndex=addr.IfIndex)
        if GetIfEntry2(ctypes.byref(row)) != ERROR_SUCCESS:
            packets_sent = packets_recv = 0
            media_connect_state = MEDIA_CONNECT_STATE_UNKNOWN
            transmit_link_speed = 0
            receive_link_speed = 0
        else:
            packets_sent = int(row.OutUcastPkts + row.OutNUcastPkts)
            packets_recv = int(row.InUcastPkts + row.InNUcastPkts)
            media_connect_state = int(row.MediaConnectState)
            transmit_link_speed = int(row.TransmitLinkSpeed)
            receive_link_speed = int(row.ReceiveLinkSpeed)

        adapter_guid_raw = addr.AdapterName.decode('ascii', errors='ignore') if addr.AdapterName else None
        adapter_guid: str | None = str(adapter_guid_raw).upper() if adapter_guid_raw else None

        yield (
            int(addr.IfIndex),
            str(addr.FriendlyName or ''),
            str(addr.Description or ''),
            mac_address,
            adapter_guid,
            int(addr.OperStatus),
            bool(addr.Flags & IP_ADAPTER_IPV4_ENABLED),
            media_connect_state,
            packets_sent,
            packets_recv,
            transmit_link_speed,
            receive_link_speed,
            ipv4_list,
            gateway_list,
        )

        adapter = ctypes.cast(addr.Next, LP_IP_ADAPTER_ADDRESSES)


@functools.cache
def _get_wlanapi() -> ctypes.WinDLL | None:
    """Load and prototype wlanapi.dll once, returning None if unavailable."""
    if sys.platform != 'win32':
        return None
    try:
        wlanapi = ctypes.WinDLL('wlanapi')
    except OSError:
        return None
    wlanapi.WlanOpenHandle.argtypes = [
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.HANDLE),
    ]
    wlanapi.WlanOpenHandle.restype = wintypes.DWORD
    wlanapi.WlanEnumInterfaces.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    wlanapi.WlanEnumInterfaces.restype = wintypes.DWORD
    wlanapi.WlanFreeMemory.argtypes = [ctypes.c_void_p]
    wlanapi.WlanFreeMemory.restype = None
    wlanapi.WlanCloseHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    wlanapi.WlanCloseHandle.restype = wintypes.DWORD
    return wlanapi


def has_wlan_interfaces() -> bool:
    """Return whether at least one wireless LAN interface is enumerated by Win32 wlanapi."""
    wlanapi = _get_wlanapi()
    if wlanapi is None:
        return False

    negotiated_version = wintypes.DWORD()
    client_handle = wintypes.HANDLE()
    open_result = wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated_version), ctypes.byref(client_handle))
    if open_result or not bool(client_handle.value):
        return False

    interface_list_ptr = ctypes.c_void_p()
    try:
        enum_result = wlanapi.WlanEnumInterfaces(client_handle, None, ctypes.byref(interface_list_ptr))
        if enum_result or not bool(interface_list_ptr.value):
            return False
        try:
            num_items = ctypes.cast(interface_list_ptr, ctypes.POINTER(wintypes.DWORD)).contents.value
            return num_items > 0
        finally:
            wlanapi.WlanFreeMemory(interface_list_ptr)
    finally:
        wlanapi.WlanCloseHandle(client_handle, None)


def _extract_bstr_guid(props_ptr: wintypes.LPVOID) -> str | None:
    get_guid = ctypes.WINFUNCTYPE(
        wintypes.HRESULT,
        wintypes.LPVOID,
        ctypes.POINTER(ctypes.c_wchar_p),
    )(get_com_vtable_entry(props_ptr, 7))
    bstr_guid = ctypes.c_wchar_p()
    if get_guid(props_ptr, ctypes.byref(bstr_guid)):
        return None
    try:
        return bstr_guid.value
    finally:
        if bstr_guid:
            _oleaut32.SysFreeString(bstr_guid)


def _query_connection_sharing_type(
    manager_ptr: wintypes.LPVOID,
    connection_ptr: wintypes.LPVOID,
) -> tuple[str, int] | None:
    """Extract (raw_guid, sharing_type) for a single COM connection if sharing is enabled."""
    get_configuration_for_connection = ctypes.WINFUNCTYPE(
        wintypes.HRESULT,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
    )(get_com_vtable_entry(manager_ptr, 10))
    get_connection_props = ctypes.WINFUNCTYPE(
        wintypes.HRESULT,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
    )(get_com_vtable_entry(manager_ptr, 12))

    config_ptr = wintypes.LPVOID()
    if get_configuration_for_connection(manager_ptr, connection_ptr, ctypes.byref(config_ptr)) or not config_ptr:
        return None

    try:
        get_sharing_enabled = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.SHORT),
        )(get_com_vtable_entry(config_ptr, 7))
        get_sharing_type = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            ctypes.POINTER(ctypes.c_int),
        )(get_com_vtable_entry(config_ptr, 8))

        sharing_enabled = wintypes.SHORT()
        if get_sharing_enabled(config_ptr, ctypes.byref(sharing_enabled)) or not sharing_enabled.value:
            return None

        sharing_type = ctypes.c_int()
        get_sharing_type(config_ptr, ctypes.byref(sharing_type))

        props_ptr = wintypes.LPVOID()
        if get_connection_props(manager_ptr, connection_ptr, ctypes.byref(props_ptr)) or not props_ptr:
            return None

        try:
            guid_value = _extract_bstr_guid(props_ptr)
            if guid_value is not None and guid_value:
                return (guid_value, sharing_type.value)
        finally:
            release_com_interface(props_ptr)
    finally:
        release_com_interface(config_ptr)

    return None


def _get_enum_variant(manager_ptr: wintypes.LPVOID) -> wintypes.LPVOID:
    """Obtain the IEnumVARIANT interface for all network connections."""
    get_enum_every_connection = ctypes.WINFUNCTYPE(
        wintypes.HRESULT,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
    )(get_com_vtable_entry(manager_ptr, 11))

    collection_ptr = wintypes.LPVOID()
    if get_enum_every_connection(manager_ptr, ctypes.byref(collection_ptr)) or not collection_ptr:
        return wintypes.LPVOID()

    try:
        get_new_enum = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.LPVOID),
        )(get_com_vtable_entry(collection_ptr, 7))

        unknown_enum_ptr = wintypes.LPVOID()
        if get_new_enum(collection_ptr, ctypes.byref(unknown_enum_ptr)) or not unknown_enum_ptr:
            return wintypes.LPVOID()

        try:
            return query_com_interface(unknown_enum_ptr, _IID_IENUM_VARIANT)
        finally:
            release_com_interface(unknown_enum_ptr)
    finally:
        release_com_interface(collection_ptr)


def _collect_ics_sharing_entries(manager_ptr: wintypes.LPVOID) -> list[tuple[str, int]]:
    """Query `manager_ptr` for ICS installation and collect `(guid, sharing_type)` pairs."""
    get_sharing_installed = ctypes.WINFUNCTYPE(
        wintypes.HRESULT,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.SHORT),
    )(get_com_vtable_entry(manager_ptr, 7))

    installed = wintypes.SHORT()
    if get_sharing_installed(manager_ptr, ctypes.byref(installed)) or not installed.value:
        return []

    enum_variant_ptr = _get_enum_variant(manager_ptr)
    if not enum_variant_ptr:
        return []

    entries: list[tuple[str, int]] = []

    try:
        next_enum = ctypes.WINFUNCTYPE(
            wintypes.HRESULT,
            wintypes.LPVOID,
            wintypes.ULONG,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.ULONG),
        )(get_com_vtable_entry(enum_variant_ptr, 3))

        variant_buffer = (ctypes.c_byte * 24)()
        fetched_count = wintypes.ULONG()
        while not next_enum(enum_variant_ptr, 1, ctypes.byref(variant_buffer), ctypes.byref(fetched_count)) and fetched_count.value == 1:
            try:
                connection_val = (ctypes.c_void_p.from_buffer(variant_buffer, 8)).value
                if not bool(connection_val):
                    continue
                connection_ptr = wintypes.LPVOID(connection_val)
                try:
                    entry = _query_connection_sharing_type(manager_ptr, connection_ptr)
                    if entry is not None:
                        entries.append(entry)
                except OSError as e:
                    logger.debug('Failed to classify ICS connection: %s', e)
            finally:
                _oleaut32.VariantClear(ctypes.byref(variant_buffer))
    finally:
        release_com_interface(enum_variant_ptr)
    return entries


def query_ics_sharing_types() -> list[tuple[str, int]]:
    """Return a list of (raw_guid, sharing_type) pairs from INetSharingManager COM interface."""
    if sys.platform != 'win32':
        return []
    entries: list[tuple[str, int]] = []
    need_uninit = co_initialize_ex(2)

    try:
        clsid = clsid_from_progid('HNetCfg.HNetShare')
        manager_ptr = co_create_instance(clsid, 5, _IID_INET_SHARING_MANAGER) if clsid is not None else wintypes.LPVOID()
        if manager_ptr:
            try:
                entries = _collect_ics_sharing_entries(manager_ptr)
            except OSError as e:
                logger.debug('ICS COM query encountered error: %s', e)
            finally:
                release_com_interface(manager_ptr)
    except OSError as e:
        logger.debug('Failed to initialize ICS COM interface: %s', e)
    finally:
        if need_uninit:
            co_uninitialize()

    return entries


def create_icmp_handle() -> int | None:
    """Create a Win32 ICMP handle via IcmpCreateFile, returning None on failure."""
    if sys.platform != 'win32':
        return None
    handle = _IcmpCreateFile()
    if not handle or handle == _INVALID_HANDLE_VALUE:
        return None
    return int(handle)


def close_icmp_handle(handle: int) -> None:
    """Close a Win32 ICMP handle created by create_icmp_handle()."""
    if sys.platform == 'win32' and handle != _INVALID_HANDLE_VALUE:
        _IcmpCloseHandle(handle)


def send_icmp_echo(
    handle: int,
    destination_address: int,
    payload_data: bytes,
    timeout_milliseconds: int,
) -> tuple[int, int, int, int]:
    """Send a Win32 ICMP echo request and return (reply_count, status_code, rtt_ms, ttl)."""
    reply_buffer_size = max(512, ctypes.sizeof(_IcmpEchoReply) + len(payload_data) + 64)
    reply_buffer = ctypes.create_string_buffer(reply_buffer_size)
    return_value = int(
        _IcmpSendEcho(
            handle,
            destination_address,
            payload_data,
            len(payload_data),
            None,
            reply_buffer,
            reply_buffer_size,
            timeout_milliseconds,
        ),
    )
    last_error = ctypes.get_last_error() if not return_value else 0
    reply = _IcmpEchoReply.from_buffer_copy(reply_buffer)
    status_code = int(reply.Status)
    if not return_value and not status_code:
        status_code = last_error or _IP_REQ_TIMED_OUT
    return (
        return_value,
        status_code,
        int(reply.RoundTripTime),
        int(reply.Options.Ttl),
    )


def register_win32_ip_change_notification(callback: Callable[[], None]) -> Callable[[], None]:
    """Subscribe to Windows kernel IPv4 address and interface change events, returning an unregister callable."""
    if sys.platform != 'win32':
        return lambda: None

    def _on_mib_change(_caller_context: int | None, _row_ptr: int | None, _notification_type: int) -> None:
        callback()

    c_callback = _MIB_CHANGE_CALLBACK_TYPE(_on_mib_change)
    handles: list[wintypes.HANDLE] = []

    unicast_handle = wintypes.HANDLE()
    if _NotifyUnicastIpAddressChange(AF_INET, c_callback, None, 0, ctypes.byref(unicast_handle)) == ERROR_SUCCESS and bool(unicast_handle.value):
        handles.append(unicast_handle)

    interface_handle = wintypes.HANDLE()
    if _NotifyIpInterfaceChange(AF_INET, c_callback, None, 0, ctypes.byref(interface_handle)) == ERROR_SUCCESS and bool(interface_handle.value):
        handles.append(interface_handle)

    callback_id = id(c_callback)
    if handles:
        _ACTIVE_MIB_CALLBACKS[callback_id] = c_callback

    closed = False

    def _unregister() -> None:
        nonlocal closed
        if closed:
            return
        closed = True
        for handle in handles:
            _CancelMibChangeNotify2(handle)
        handles.clear()
        _ACTIVE_MIB_CALLBACKS.pop(callback_id, None)

    return _unregister
