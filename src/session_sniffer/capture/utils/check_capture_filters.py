"""Module for checking BPF filter support on a network interface using Npcap/WinPcap."""

from session_sniffer.capture.exceptions import PcapOpenError
from session_sniffer.capture.pcap import PcapHandle


def check_broadcast_multicast_support(device_name: str) -> tuple[bool, bool]:
    r"""Check if the given network interface supports `broadcast` and `multicast` BPF filters.

    Opens a pcap handle on the interface and attempts to compile each filter.
    If the filter is invalid or unsupported the underlying pcap library returns an error.

    Args:
        device_name: The pcap device name, e.g. `\Device\NPF_{GUID}`.

    Returns:
        A tuple where the first value indicates support for `broadcast` and the
        second indicates support for `multicast` BPF filters.
    """
    try:
        pcap_handle = PcapHandle.open_live(
            device_name,
            snaplen=64,
            promiscuous=False,
            timeout_milliseconds=50,
        )
    except (PcapOpenError, OSError):
        return (False, False)

    try:
        broadcast_supported = pcap_handle.test_filter_compilation('broadcast')
        multicast_supported = pcap_handle.test_filter_compilation('multicast')
        return (broadcast_supported, multicast_supported)
    finally:
        pcap_handle.close()
