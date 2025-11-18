"""Test script for ctypes_adapters_info module.

This script tests the network adapter information retrieval using ctypes.
"""
import sys
from pathlib import Path

from modules.networking.ctypes_adapters_info import (  # pyright: ignore[reportMissingImports]
    GetAdaptersAddressesError,
    get_adapters_info,
)

# Add .venv/Scripts to path to import ctypes_adapters_info
sys.path.insert(0, str(Path(__file__).parent / '.venv' / 'Scripts'))


def format_bytes(mac: str | None) -> str:
    """Format MAC address for display."""
    return mac if mac else 'N/A'


def format_ipv4_list(ip_list: list[str]) -> str:
    """Format IPv4 address list for display."""
    return ', '.join(ip_list) if ip_list else 'None'


def get_oper_status_text(status: int) -> str:
    """Convert operational status code to readable text.

    Based on IF_OPER_STATUS enumeration:
    https://learn.microsoft.com/en-us/windows/win32/api/ifdef/ne-ifdef-if_oper_status
    """
    status_map = {
        1: 'Up',
        2: 'Down',
        3: 'Testing',
        4: 'Unknown',
        5: 'Dormant',
        6: 'NotPresent',
        7: 'LowerLayerDown',
    }
    return status_map.get(status, f'Unknown ({status})')


def main() -> None:
    """Main test function."""
    print('=' * 80)
    print('Network Adapter Information (using ctypes)')
    print('=' * 80)
    print()

    try:
        adapters = list(get_adapters_info())
    except GetAdaptersAddressesError as e:
        print(f'Error retrieving adapter information: {e}', file=sys.stderr)
        sys.exit(1)

    if not adapters:
        print('No network adapters found.')
        return

    print(f'Found {len(adapters)} network adapter(s):\n')

    for adapter in adapters:
        print('Adapter:')
        print(f'  Interface Index:    {adapter.interface_index}')
        print(f'  Friendly Name:      {adapter.friendly_name}')
        print(f'  Description:        {adapter.description}')
        print(f'  MAC Address:        {format_bytes(adapter.mac_address)}')
        print(f'  IPv4 Addresses:     {format_ipv4_list(adapter.ipv4_addresses)}')
        print(f'  Operational Status: {get_oper_status_text(adapter.operational_status)}')
        print(f'  Packets Sent:       {adapter.packets_sent:,}')
        print(f'  Packets Received:   {adapter.packets_recv:,}')

        # Per-adapter Neighborhood
        entries = adapter.neighbors
        print(f'  Neighbors:          {len(entries)}')
        for ip, mac in entries:
            print(f'    - IP: {ip or "N/A":15}  MAC: {format_bytes(mac)}')
        print()

    # No consolidated neighborhood section; neighbors are printed per adapter above

    # Summary statistics
    total_packets_sent = sum(a.packets_sent for a in adapters)
    total_packets_recv = sum(a.packets_recv for a in adapters)
    active_adapters = sum(1 for a in adapters if a.operational_status == 1)

    print('=' * 80)
    print('Summary:')
    print(f'  Total Adapters:         {len(adapters)}')
    print(f'  Active Adapters:        {active_adapters}')
    print(f'  Total Packets Sent:     {total_packets_sent:,}')
    print(f'  Total Packets Received: {total_packets_recv:,}')
    print('=' * 80)

    # No broad exception handling; let other errors surface during testing


if __name__ == '__main__':
    main()
