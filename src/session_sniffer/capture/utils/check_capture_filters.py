"""Module for checking BPF filter support on a network interface using scapy."""

from scapy.error import Scapy_Exception
from scapy.sendrecv import sniff


def _stop_immediately(_pkt: object) -> bool:
    """Stop Scapy sniffing as soon as the callback is evaluated."""
    return True


def check_broadcast_multicast_support(device_name: str) -> tuple[bool, bool]:
    r"""Check if the given network interface supports `broadcast` and `multicast` BPF filters.

    Opens a pcap handle on the interface and attempts to compile each filter.
    If the filter is invalid or unsupported the underlying pcap library raises an
    exception before any packets are read.

    Args:
        device_name: The pcap device name, e.g. `\Device\NPF_{GUID}`.

    Returns:
        A tuple where the first value indicates support for `broadcast` and the
        second indicates support for `multicast` BPF filters.
    """

    def _test_filter(filter_str: str) -> bool:
        try:
            sniff(
                iface=device_name,
                filter=filter_str,
                count=0,
                stop_filter=_stop_immediately,
                timeout=0.5,
                store=False,
            )
        except (Scapy_Exception, OSError):
            return False
        return True

    return (_test_filter('broadcast'), _test_filter('multicast'))
